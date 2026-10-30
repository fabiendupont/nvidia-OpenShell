// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy Information Point (PIP) supervisor (RFC 0019).
//!
//! Application-layer governance software running inside the sandbox exposes a
//! `PolicyInformationPoint` gRPC service on a Unix domain socket under
//! `/run/openshell/pip/<name>.sock`. The supervisor — never the sandbox —
//! initiates the connection, verifies the serving binary's identity via
//! `SO_PEERCRED` plus a TOFU SHA256 check, and streams the publisher's
//! security context into [`PipCache`]. The OPA engine merges the cached
//! properties into every network evaluation as `input.pip`.
//!
//! PIP context can only restrict network access (deny rules); it never
//! expands the baseline allowlist. A disconnected or absent PIP is equivalent
//! to no PIP: its cached context reverts to null.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use tokio::net::UnixStream;
use tonic::transport::Endpoint;
use tower::service_fn;

use crate::procfs;

/// Directory (relative to the sandbox root) where PIP publishers create
/// their sockets.
const PIP_DIR_RELATIVE: &str = "run/openshell/pip";

/// How often the watcher rescans the PIP socket directory.
const WATCH_INTERVAL: Duration = Duration::from_millis(1000);

/// Backoff before reconnecting a PIP stream after a disconnect.
const RECONNECT_BACKOFF: Duration = Duration::from_millis(1000);

/// Backoff before re-checking a PIP whose binary hash failed the TOFU check.
const TOFU_MISMATCH_BACKOFF: Duration = Duration::from_secs(5);

/// Cached security context published by in-sandbox PIP services.
///
/// The latest property map from each connected publisher is stored per PIP
/// name. [`PipCache::merged`] folds them into the single flat object injected
/// as `input.pip`; when no PIP is connected the merged value is `None` and
/// `input.pip` stays null, matching pre-PIP behavior.
///
/// Reads take one `RwLock::read()` on the OPA hot path; all I/O happens in
/// the watcher tasks.
#[derive(Debug, Default)]
pub struct PipCache {
    per_pip: std::sync::RwLock<BTreeMap<String, BTreeMap<String, String>>>,
}

impl PipCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the cached context of one publisher. Called with each streamed
    /// `SecurityContext` message; an empty property map is a valid state.
    pub(crate) fn update(&self, pip: &str, properties: BTreeMap<String, String>) {
        if let Ok(mut guard) = self.per_pip.write() {
            guard.insert(pip.to_string(), properties);
        }
    }

    /// Revert one publisher's context to null (fail-closed on disconnect).
    pub(crate) fn clear(&self, pip: &str) {
        if let Ok(mut guard) = self.per_pip.write() {
            guard.remove(pip);
        }
    }

    /// Merge every connected publisher's properties into one object.
    ///
    /// Returns `None` when no PIP is connected. Key collisions between
    /// publishers are resolved by lexicographic PIP name order; publishers
    /// should prefix their keys by convention to avoid this.
    pub fn merged(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        let guard = self.per_pip.read().ok()?;
        if guard.is_empty() {
            return None;
        }
        let mut merged = serde_json::Map::new();
        for properties in guard.values() {
            for (key, value) in properties {
                merged.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }
        if merged.is_empty() {
            // A connected PIP publishing an empty map is equivalent to no
            // properties; keep `input.pip` absent rather than `{}`.
            return None;
        }
        Some(merged)
    }

    /// Names of the publishers whose context is currently cached.
    pub fn connected_pips(&self) -> Vec<String> {
        self.per_pip
            .read()
            .map(|guard| guard.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Supervisor-side watcher for PIP sockets inside one sandbox.
///
/// Waits for the workload's mount namespace to become visible through
/// `/proc/<pid>/root/`, then polls `run/openshell/pip/` for `<name>.sock`
/// sockets and spawns one connection task per socket.
pub struct PipWatcher {
    cache: Arc<PipCache>,
    sandbox_id: String,
    /// Trust-on-first-use binary hashes, keyed by PIP name.
    tofu: Arc<Mutex<HashMap<String, String>>>,
}

/// Run the PIP watcher for one sandbox until the task is aborted.
///
/// Spawned by `run_networking` when process supervision is enabled. Never
/// fails the sandbox: every error path logs and retries or gives up on that
/// PIP only.
pub async fn run_pip_watcher(
    cache: Arc<PipCache>,
    entrypoint_pid: Arc<AtomicU32>,
    sandbox_id: String,
) {
    let watcher = PipWatcher {
        cache,
        sandbox_id,
        tofu: Arc::new(Mutex::new(HashMap::new())),
    };
    watcher.run(entrypoint_pid).await;
}

impl PipWatcher {
    async fn run(&self, entrypoint_pid: Arc<AtomicU32>) {
        // Phase 1: wait for the orchestrator to publish the entrypoint PID
        // (20 attempts * 250ms = 5s window, matching the symlink resolver).
        let mut pid = 0;
        for _ in 1..=20 {
            pid = entrypoint_pid.load(Ordering::Acquire);
            if pid != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if pid == 0 {
            tracing::debug!("PIP watcher: entrypoint PID never published, exiting");
            return;
        }

        // Phase 2: wait for /proc/<pid>/root/ to become traversable.
        let probe = format!("/proc/{pid}/root/");
        let mut root = None;
        for _ in 1..=10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if std::fs::metadata(&probe).is_ok() {
                root = Some(PathBuf::from(probe));
                break;
            }
        }
        let Some(root) = root else {
            tracing::debug!("PIP watcher: sandbox root never became visible, exiting");
            return;
        };

        let pip_dir = root.join(PIP_DIR_RELATIVE);
        Self::ensure_pip_dir(&pip_dir);
        tracing::info!(
            pip_dir = %pip_dir.display(),
            "PIP watcher: watching for Policy Information Point sockets"
        );

        // One spawned connection task per discovered socket name.
        let mut managed: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            for name in Self::discover_sockets(&pip_dir) {
                if let std::collections::hash_map::Entry::Vacant(slot) = managed.entry(name.clone())
                {
                    tracing::info!(pip = %name, "PIP watcher: connecting to policy information point");
                    let task = tokio::spawn(run_pip_connection(
                        Arc::clone(&self.cache),
                        Arc::clone(&self.tofu),
                        self.sandbox_id.clone(),
                        name.clone(),
                        pip_dir.join(format!("{name}.sock")),
                    ));
                    slot.insert(task);
                }
            }
            // Reap finished connection tasks (socket disappeared).
            managed.retain(|_, task| !task.is_finished());
            tokio::time::sleep(WATCH_INTERVAL).await;
        }
    }

    /// Best-effort creation of the PIP socket directory with mode 0750 so a
    /// governance framework can create its socket without preparing the
    /// directory itself. Failure is non-fatal: a publisher may create the
    /// directory with its own permissions.
    fn ensure_pip_dir(pip_dir: &Path) {
        if pip_dir.exists() {
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o750);
            if let Err(error) = builder.create(pip_dir) {
                tracing::debug!(
                    pip_dir = %pip_dir.display(),
                    %error,
                    "PIP watcher: could not create PIP socket directory"
                );
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pip_dir;
        }
    }

    /// Names (`<name>` from `<name>.sock`) of PIP sockets currently present.
    fn discover_sockets(pip_dir: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(pip_dir) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "sock") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
                && !stem.is_empty()
            {
                names.push(stem.to_string());
            }
        }
        names
    }
}

/// Maintain one supervisor-initiated PIP stream until the socket disappears.
///
/// On stream error or disconnect the publisher's cached context reverts to
/// null and the connection is retried with backoff while the socket exists.
#[allow(clippy::too_many_arguments)]
async fn run_pip_connection(
    cache: Arc<PipCache>,
    tofu: Arc<Mutex<HashMap<String, String>>>,
    sandbox_id: String,
    name: String,
    socket_path: PathBuf,
) {
    loop {
        if !socket_path.exists() {
            tracing::debug!(pip = %name, "PIP stream: socket gone, stopping");
            return;
        }

        match run_pip_stream_once(&cache, &tofu, &sandbox_id, &name, &socket_path).await {
            Ok(()) => {
                // Stream ended (publisher shutdown); retry after backoff.
                cache.clear(&name);
                tracing::info!(pip = %name, "PIP stream: disconnected, context reverted to null");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
            Err(PipStreamError::TofuMismatch) => {
                cache.clear(&name);
                tokio::time::sleep(TOFU_MISMATCH_BACKOFF).await;
            }
            Err(error) => {
                cache.clear(&name);
                tracing::warn!(pip = %name, %error, "PIP stream: error, context reverted to null");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        }
    }
}

/// Outcome of one connection attempt used for backoff selection.
enum PipStreamError {
    /// Binary hash mismatch: fail-closed, do not connect, warn.
    TofuMismatch,
    Other(String),
}

impl std::fmt::Display for PipStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TofuMismatch => write!(f, "publisher binary hash failed TOFU verification"),
            Self::Other(detail) => write!(f, "{detail}"),
        }
    }
}

async fn run_pip_stream_once(
    cache: &Arc<PipCache>,
    tofu: &Arc<Mutex<HashMap<String, String>>>,
    sandbox_id: &str,
    name: &str,
    socket_path: &Path,
) -> Result<(), PipStreamError> {
    // The connector hands the connected stream's peer PID back to us so
    // identity verification uses exactly the stream tonic owns.
    let peer_pid: Arc<Mutex<Option<i32>>> = Arc::new(Mutex::new(None));
    let connector_pid = Arc::clone(&peer_pid);
    let connector_path = socket_path.to_path_buf();

    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_timeout(Duration::from_secs(2))
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let path = connector_path.clone();
            let peer_pid = Arc::clone(&connector_pid);
            async move {
                let stream = UnixStream::connect(&path).await?;
                #[cfg(target_os = "linux")]
                if let Ok(cred) = stream.peer_cred()
                    && let Some(pid) = cred.pid()
                {
                    *peer_pid.lock().unwrap() = Some(pid);
                }
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| PipStreamError::Other(format!("connect failed: {e}")))?;

    verify_publisher_identity(tofu, name, &peer_pid)?;

    let mut client =
        openshell_core::proto::pip::v1::policy_information_point_client::PolicyInformationPointClient::new(
            channel,
        );
    let request = openshell_core::proto::pip::v1::StreamContextRequest {
        sandbox_id: sandbox_id.to_string(),
    };
    let stream = client
        .stream_context(request)
        .await
        .map_err(|e| PipStreamError::Other(format!("StreamContext RPC failed: {e}")))?;

    let mut stream = stream.into_inner();
    while let Some(message) = stream.next().await {
        let context = message
            .map_err(|e| PipStreamError::Other(format!("StreamContext stream failed: {e}")))?;
        cache.update(
            name,
            context.properties.into_iter().collect::<BTreeMap<_, _>>(),
        );
    }
    Ok(())
}

/// Verify the serving binary's identity: `SO_PEERCRED` supplies the PID, the
/// `/proc`-resolved executable is hashed, and the hash is checked against the
/// TOFU cache. First sight pins the hash; a later mismatch fails closed.
fn verify_publisher_identity(
    tofu: &Arc<Mutex<HashMap<String, String>>>,
    name: &str,
    peer_pid: &Arc<Mutex<Option<i32>>>,
) -> Result<(), PipStreamError> {
    #[cfg(target_os = "linux")]
    {
        let pid = peer_pid
            .lock()
            .unwrap()
            .ok_or_else(|| PipStreamError::Other("no peer credentials on PIP socket".into()))?;
        let exe = procfs::binary_path(pid)
            .map_err(|e| PipStreamError::Other(format!("resolve publisher exe: {e}")))?;
        let hash = procfs::file_sha256(&exe)
            .map_err(|e| PipStreamError::Other(format!("hash publisher exe: {e}")))?;

        let mut tofu = tofu.lock().unwrap();
        match tofu.get(name) {
            Some(pinned) if pinned != &hash => {
                drop(tofu);
                tracing::warn!(
                    pip = %name,
                    exe = %exe.display(),
                    "PIP publisher binary hash failed TOFU verification; not connecting"
                );
                openshell_ocsf::ocsf_emit!(
                    openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                        .severity(openshell_ocsf::SeverityId::High)
                        .finding_info(openshell_ocsf::FindingInfo::new(
                            "openshell.pip.tofu_mismatch",
                            "PIP publisher binary hash failed TOFU verification",
                        ))
                        .evidence_pairs(&[("pip", name), ("disposition", "not_connected"),])
                        .message("PIP publisher binary changed; supervisor refused to connect")
                        .build()
                );
                return Err(PipStreamError::TofuMismatch);
            }
            Some(_) => {}
            None => {
                tofu.insert(name.to_string(), hash);
                tracing::info!(pip = %name, exe = %exe.display(), "PIP publisher binary pinned (TOFU)");
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tofu, name, peer_pid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::atomic::AtomicU32;
    use std::task::{Context, Poll};

    use futures::Stream;
    use tokio::net::{UnixListener, UnixStream};

    use super::*;
    use openshell_core::proto::pip::v1::policy_information_point_server::{
        PolicyInformationPoint, PolicyInformationPointServer,
    };
    use openshell_core::proto::pip::v1::{SecurityContext, StreamContextRequest};

    #[test]
    fn merged_is_none_when_no_pip_connected() {
        let cache = PipCache::new();
        assert!(cache.merged().is_none());
    }

    #[test]
    fn update_replaces_and_clear_reverts_to_null() {
        let cache = PipCache::new();
        cache.update(
            "defenseclaw",
            BTreeMap::from([("trust_state".to_string(), "suspended".to_string())]),
        );
        let merged = cache.merged().unwrap();
        assert_eq!(merged["trust_state"], "suspended");

        cache.update("defenseclaw", BTreeMap::new());
        assert!(
            cache.merged().is_none(),
            "empty context is equivalent to null"
        );

        cache.update(
            "defenseclaw",
            BTreeMap::from([("trust_state".to_string(), "suspended".to_string())]),
        );
        cache.clear("defenseclaw");
        assert!(cache.merged().is_none(), "disconnect reverts to null");
        assert_eq!(cache.connected_pips(), Vec::<String>::new());
    }

    #[test]
    fn multiple_pips_merge_latest_writer_wins_per_key() {
        let cache = PipCache::new();
        cache.update(
            "alpha",
            BTreeMap::from([
                ("alpha.only".to_string(), "1".to_string()),
                ("shared".to_string(), "from-alpha".to_string()),
            ]),
        );
        cache.update(
            "beta",
            BTreeMap::from([
                ("beta.only".to_string(), "2".to_string()),
                ("shared".to_string(), "from-beta".to_string()),
            ]),
        );
        let merged = cache.merged().unwrap();
        assert_eq!(merged["alpha.only"], "1");
        assert_eq!(merged["beta.only"], "2");
        // Deterministic merge order: later PIP name wins on collision.
        assert_eq!(merged["shared"], "from-beta");
    }

    // ---- End-to-end tests against a mock in-sandbox publisher ----

    /// tonic `Incoming` stream adapter for a Unix domain socket listener,
    /// mirroring the in-process driver socket servers.
    struct UnixIncoming {
        listener: UnixListener,
    }

    impl Stream for UnixIncoming {
        type Item = std::io::Result<UnixStream>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.get_mut().listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
                Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    struct MockPip {
        expected_sandbox_id: String,
        seen_sandbox_id: Arc<Mutex<Option<String>>>,
        /// Signals the per-stream task to end the stream (publisher exit).
        shutdown: tokio::sync::watch::Receiver<bool>,
    }

    #[tonic::async_trait]
    impl PolicyInformationPoint for MockPip {
        type StreamContextStream =
            tokio_stream::wrappers::ReceiverStream<Result<SecurityContext, tonic::Status>>;

        async fn stream_context(
            &self,
            request: tonic::Request<StreamContextRequest>,
        ) -> Result<tonic::Response<Self::StreamContextStream>, tonic::Status> {
            let sandbox_id = request.into_inner().sandbox_id;
            if sandbox_id != self.expected_sandbox_id {
                return Err(tonic::Status::permission_denied("sandbox mismatch"));
            }
            *self.seen_sandbox_id.lock().unwrap() = Some(sandbox_id);
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            let initial = SecurityContext {
                properties: BTreeMap::from([
                    ("trust_state".to_string(), "suspended".to_string()),
                    ("data_classification".to_string(), "phi".to_string()),
                ])
                .into_iter()
                .collect(),
                trace_id: "trace-1".to_string(),
            };
            let mut shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                // Hold the stream open with the initial context until the
                // mock publisher exits.
                let _ = tx.send(Ok(initial)).await;
                let _ = shutdown.wait_for(|stop| *stop).await;
                // Dropping tx ends the supervisor's stream.
            });
            Ok(tonic::Response::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
        }
    }

    fn mock_pip_dir(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join(format!("{name}.sock"));
        (dir, socket)
    }

    #[allow(clippy::unused_async)] // keeps call sites uniform with async helpers
    async fn spawn_mock_pip(
        socket: &Path,
        sandbox_id: &str,
    ) -> (
        tokio::task::JoinHandle<()>,
        Arc<Mutex<Option<String>>>,
        tokio::sync::watch::Sender<bool>,
    ) {
        let listener = UnixListener::bind(socket).expect("bind mock PIP socket");
        let seen = Arc::new(Mutex::new(None));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let service = MockPip {
            expected_sandbox_id: sandbox_id.to_string(),
            seen_sandbox_id: Arc::clone(&seen),
            shutdown: shutdown_rx,
        };
        let serve = tonic::transport::Server::builder()
            .add_service(PolicyInformationPointServer::new(service))
            .serve_with_incoming(UnixIncoming { listener });
        let task = tokio::spawn(async move {
            let _ = serve.await;
        });
        (task, seen, shutdown_tx)
    }

    async fn wait_until<T>(mut probe: impl FnMut() -> Option<T>) -> T {
        for _ in 0..100 {
            if let Some(value) = probe() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("condition never became true within 5s");
    }

    #[tokio::test]
    async fn supervisor_receives_and_clears_pip_context() {
        let (_dir, socket) = mock_pip_dir("defenseclaw");
        let (server, seen, shutdown) = spawn_mock_pip(&socket, "sbx-42").await;

        let cache = Arc::new(PipCache::new());
        let tofu = Arc::new(Mutex::new(HashMap::new()));
        let connection = tokio::spawn(run_pip_connection(
            Arc::clone(&cache),
            Arc::clone(&tofu),
            "sbx-42".to_string(),
            "defenseclaw".to_string(),
            socket.clone(),
        ));

        // Initial streamed context lands in the cache.
        let merged = wait_until(|| cache.merged()).await;
        assert_eq!(merged["trust_state"], "suspended");
        assert_eq!(merged["data_classification"], "phi");
        // The publisher observed the sandbox id from the request.
        assert_eq!(*seen.lock().unwrap(), Some("sbx-42".to_string()));
        // The publisher binary was pinned trust-on-first-use.
        assert!(tofu.lock().unwrap().contains_key("defenseclaw"));

        // Publisher shutdown: stream ends and the cached context reverts to
        // null (fail-closed), even though the socket file still exists.
        shutdown.send(true).expect("signal publisher shutdown");
        server.abort();
        wait_until(|| cache.merged().is_none().then_some(())).await;

        connection.abort();
    }

    #[tokio::test]
    async fn tofu_hash_mismatch_refuses_connection() {
        let (_dir, socket) = mock_pip_dir("nemoclaw");
        let (server, seen, _shutdown) = spawn_mock_pip(&socket, "sbx-42").await;

        // Pin a bogus hash for this publisher before the first connection.
        let tofu = Arc::new(Mutex::new(HashMap::from([(
            "nemoclaw".to_string(),
            "deadbeef".to_string(),
        )])));
        let cache = Arc::new(PipCache::new());
        let result = run_pip_stream_once(&cache, &tofu, "sbx-42", "nemoclaw", &socket).await;

        assert!(matches!(result, Err(PipStreamError::TofuMismatch)));
        // No RPC reached the publisher and no context was cached.
        assert!(cache.merged().is_none());
        assert!(seen.lock().unwrap().is_none());

        server.abort();
    }

    #[tokio::test]
    async fn watcher_exits_when_pid_is_never_published() {
        // The watcher must not spin or panic when no entrypoint PID arrives;
        // it exits quietly after the polling window.
        let cache = Arc::new(PipCache::new());
        let pid = Arc::new(AtomicU32::new(0));
        // Short-circuit the 5s wait window by running to completion; the
        // watcher polls 20 times at 250ms.
        tokio::time::timeout(
            Duration::from_secs(10),
            run_pip_watcher(cache, pid, "sbx".into()),
        )
        .await
        .expect("watcher exits when PID is never published");
    }
}
