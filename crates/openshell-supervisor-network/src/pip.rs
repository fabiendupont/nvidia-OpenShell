// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy Information Point (PIP) supervisor (RFC 0019).
//!
//! Governance software publishes per-sandbox security context that network
//! policy acts on. The supervisor — never the sandbox — initiates every
//! connection and exposes the merged context to OPA as `input.pip`. Three
//! publisher classes are supported:
//!
//! - **In-sandbox publishers** serve `PolicyInformationPoint` on a Unix
//!   domain socket at `/run/openshell/pip/<name>.sock` inside the sandbox.
//!   The supervisor discovers the socket through `/proc/<pid>/root/`,
//!   verifies the serving binary's identity via `SO_PEERCRED` plus a TOFU
//!   SHA256 pin, and initiates the stream. Zero configuration.
//! - **Operator-side publishers** (same host) serve the identical contract
//!   on a socket under `/run/openshell-supervisor/pip/<sandbox-id>/`. The
//!   same peer-credential verification applies.
//! - **Remote publishers** (operator-configured gRPC endpoints, for
//!   deployments where the publisher runs on another node) are authorized at
//!   configuration time through the endpoint list; the supervisor connects
//!   and streams the same contract.
//!
//! PIP context can only restrict network access (deny rules); it never
//! expands the baseline allowlist. A disconnected or absent publisher is
//! equivalent to no publisher: its cached context reverts to null.

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

/// Directory (relative to the sandbox root) where in-sandbox PIP publishers
/// create their sockets.
const PIP_DIR_RELATIVE: &str = "run/openshell/pip";

/// Root of the supervisor-side directory tree for same-host operator
/// publishers. One subdirectory per sandbox id.
pub const HOST_PIP_ROOT: &str = "/run/openshell-supervisor/pip";

/// Overrides [`HOST_PIP_ROOT`] for supervisors that cannot write `/run`
/// directly, and for tests.
pub const HOST_PIP_DIR_ENV: &str = "OPENSHELL_PIP_HOST_DIR";

/// Comma-separated operator-configured remote publisher gRPC endpoints
/// (`http://host:port` or `https://host:port`). Setting the list is the
/// configuration-time authorization for those publishers.
pub const REMOTE_ENDPOINTS_ENV: &str = "OPENSHELL_PIP_REMOTE_ENDPOINTS";

/// PEM CA certificate file for remote publishers reached over `https://`.
pub const REMOTE_CA_CERT_ENV: &str = "OPENSHELL_PIP_REMOTE_CA_CERT";

/// How often a directory watcher rescans for PIP sockets.
const WATCH_INTERVAL: Duration = Duration::from_millis(1000);

/// Backoff before reconnecting a PIP stream after a disconnect.
const RECONNECT_BACKOFF: Duration = Duration::from_millis(1000);

/// Backoff before re-checking a PIP whose binary hash failed the TOFU check.
const TOFU_MISMATCH_BACKOFF: Duration = Duration::from_secs(5);

/// Where a published security context came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipOrigin {
    /// A governance application running inside the sandbox.
    Sandbox,
    /// Operator-deployed infrastructure on the supervisor host.
    OperatorHost,
    /// An operator-configured remote gRPC endpoint.
    Remote,
}

impl PipOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::OperatorHost => "operator_host",
            Self::Remote => "operator_remote",
        }
    }
}

/// One connected publisher's cached state.
#[derive(Clone, Debug)]
struct PipEntry {
    origin: PipOrigin,
    properties: BTreeMap<String, String>,
}

/// Cached security context published by PIP services for one sandbox.
///
/// The latest property map from each connected publisher is stored per
/// publisher name. [`PipCache::merged`] folds them into the single flat
/// object injected as `input.pip`; when no publisher is connected the merged
/// value is `None` and `input.pip` stays null, matching pre-PIP behavior.
///
/// Reads take one `RwLock::read()` on the OPA hot path; all I/O happens in
/// the watcher tasks.
#[derive(Debug, Default)]
pub struct PipCache {
    per_pip: std::sync::RwLock<BTreeMap<String, PipEntry>>,
}

/// An atomic view of the published context, for audit logging.
#[derive(Clone, Debug)]
pub struct PipSnapshot {
    /// Connected publisher names, for origin attribution in OCSF events.
    pub publishers: Vec<(String, PipOrigin)>,
    /// Merged properties (latest writer wins per key).
    pub properties: serde_json::Map<String, serde_json::Value>,
}

impl PipCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the cached context of one publisher. Called with each streamed
    /// `SecurityContext` message; an empty property map is a valid state.
    pub(crate) fn update(
        &self,
        pip: &str,
        origin: PipOrigin,
        properties: BTreeMap<String, String>,
    ) {
        if let Ok(mut guard) = self.per_pip.write() {
            guard.insert(pip.to_string(), PipEntry { origin, properties });
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
    /// Returns `None` when no publisher is connected. Key collisions between
    /// publishers are resolved by origin trust: in-sandbox values apply
    /// first, remote operator values next, and same-host operator values
    /// last, so the more trusted publisher wins. Publishers should still
    /// prefix their keys by convention to avoid collisions entirely.
    pub fn merged(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        self.snapshot().map(|snapshot| snapshot.properties)
    }

    /// Atomic snapshot of the merged properties and connected publishers.
    pub fn snapshot(&self) -> Option<PipSnapshot> {
        let guard = self.per_pip.read().ok()?;
        if guard.is_empty() {
            return None;
        }
        // Apply entries in ascending origin precedence so operator-published
        // values overwrite in-sandbox values on key collisions: the sandbox
        // is the untrusted party and must not be able to override operator
        // context (for example, replacing trust_state=suspended with
        // trusted). Within one origin, publisher names break ties
        // deterministically.
        let precedence = |origin: PipOrigin| match origin {
            PipOrigin::Sandbox => 0,
            PipOrigin::Remote => 1,
            PipOrigin::OperatorHost => 2,
        };
        let mut entries: Vec<(&String, &PipEntry)> = guard.iter().collect();
        entries.sort_by(|(left_name, left), (right_name, right)| {
            (precedence(left.origin), left_name).cmp(&(precedence(right.origin), right_name))
        });
        let mut merged = serde_json::Map::new();
        for (_, entry) in &entries {
            for (key, value) in &entry.properties {
                merged.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }
        if merged.is_empty() {
            // A connected publisher with an empty map is equivalent to no
            // properties; keep `input.pip` absent rather than `{}`.
            return None;
        }
        let publishers = guard
            .iter()
            .map(|(name, entry)| (name.clone(), entry.origin))
            .collect();
        Some(PipSnapshot {
            publishers,
            properties: merged,
        })
    }

    /// Names of the publishers whose context is currently cached.
    pub fn connected_pips(&self) -> Vec<String> {
        self.per_pip
            .read()
            .map(|guard| guard.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Operator-configured watcher inputs.
#[derive(Clone, Debug)]
pub struct PipWatcherConfig {
    /// Root of the supervisor-side directory tree for same-host operator
    /// publishers.
    pub host_dir_root: PathBuf,
    /// Operator-configured remote publisher gRPC endpoints (environment
    /// configuration for the standalone proxy role). Gateway-registered
    /// publishers arrive through the OPA engine instead.
    pub remote_endpoints: Vec<String>,
    /// Optional PEM CA certificate path for `https://` remote endpoints.
    pub remote_ca_cert: Option<PathBuf>,
}

/// One remote publisher endpoint with its optional PEM trust roots and
/// extension-credential bearer slot.
#[derive(Clone, Debug)]
pub struct RemotePipEndpoint {
    /// Registration name, when the endpoint came from a gateway
    /// registration; `None` for environment-configured endpoints.
    pub name: Option<String>,
    pub endpoint: String,
    pub ca_pem: Option<Vec<u8>>,
    /// Bearer slot for extension authentication. `None` connects without a
    /// credential (authentication disabled or opted out).
    pub bearer: Option<openshell_extension_core::BearerTokenSlot>,
}

impl Default for PipWatcherConfig {
    fn default() -> Self {
        Self {
            host_dir_root: PathBuf::from(HOST_PIP_ROOT),
            remote_endpoints: Vec::new(),
            remote_ca_cert: None,
        }
    }
}

impl PipWatcherConfig {
    /// Read operator configuration from the process environment.
    ///
    /// Process-level operator configuration, following the OTLP relay
    /// endpoint pattern. Sandbox-scoped state never comes from here.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(root) = std::env::var(HOST_PIP_DIR_ENV)
            && !root.is_empty()
        {
            config.host_dir_root = PathBuf::from(root);
        }
        if let Ok(endpoints) = std::env::var(REMOTE_ENDPOINTS_ENV) {
            config.remote_endpoints = endpoints
                .split(',')
                .map(str::trim)
                .filter(|endpoint| !endpoint.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Ok(ca) = std::env::var(REMOTE_CA_CERT_ENV)
            && !ca.is_empty()
        {
            config.remote_ca_cert = Some(PathBuf::from(ca));
        }
        config
    }
}

/// Run the PIP watcher for one sandbox until the tasks are aborted.
///
/// Spawns independent watcher tasks per publisher source; returns once the
/// tasks are launched. Never fails the sandbox: every error path logs and
/// retries or gives up on that publisher only.
pub async fn run_pip_watcher(
    cache: Arc<PipCache>,
    entrypoint_pid: Arc<AtomicU32>,
    sandbox_id: String,
) {
    run_pip_watcher_with_config(
        cache,
        entrypoint_pid,
        sandbox_id,
        PipWatcherConfig::from_env(),
    )
    .await;
}

/// [`run_pip_watcher`] with the OPA engine's gateway-registered remote
/// publishers merged into the environment-configured endpoint set.
///
/// Gateway registrations (`[[openshell.supervisor.pip]]` in `gateway.toml`,
/// delivered in the sandbox configuration snapshot) and environment
/// endpoints are unioned; the manager reconnects whenever the gateway
/// registration set changes.
pub async fn run_pip_watcher_with_engine(
    cache: Arc<PipCache>,
    entrypoint_pid: Arc<AtomicU32>,
    sandbox_id: String,
    engine: Arc<crate::opa::OpaEngine>,
) {
    let config = PipWatcherConfig::from_env();
    run_pip_watcher_with_config_and_engine(cache, entrypoint_pid, sandbox_id, config, Some(engine))
        .await;
}

/// [`run_pip_watcher`] with explicit operator configuration (tests, embedded
/// callers).
#[allow(clippy::unused_async)] // spawns detached tasks; kept async for a uniform spawn surface
pub async fn run_pip_watcher_with_config(
    cache: Arc<PipCache>,
    entrypoint_pid: Arc<AtomicU32>,
    sandbox_id: String,
    config: PipWatcherConfig,
) {
    run_pip_watcher_with_config_and_engine(cache, entrypoint_pid, sandbox_id, config, None).await;
}

#[allow(clippy::unused_async)] // spawns detached tasks; kept async for a uniform spawn surface
async fn run_pip_watcher_with_config_and_engine(
    cache: Arc<PipCache>,
    entrypoint_pid: Arc<AtomicU32>,
    sandbox_id: String,
    config: PipWatcherConfig,
    engine: Option<Arc<crate::opa::OpaEngine>>,
) {
    // In-sandbox publishers need the workload's mount namespace; wait for
    // the entrypoint PID in a child task so operator-side publishers start
    // immediately.
    let sandbox_cache = Arc::clone(&cache);
    let sandbox_id_for_sandbox = sandbox_id.clone();
    tokio::spawn(async move {
        if let Some(pip_dir) = resolve_sandbox_pip_dir(&entrypoint_pid).await {
            watch_pip_dir(
                sandbox_cache,
                sandbox_id_for_sandbox,
                PipOrigin::Sandbox,
                pip_dir,
            )
            .await;
        }
    });

    // Same-host operator publishers: one supervisor-side directory per
    // sandbox, created with mode 0750 so operator tooling can drop sockets
    // into it.
    if !sandbox_id.is_empty() {
        let host_dir = config.host_dir_root.join(&sandbox_id);
        if let Err(error) = create_pip_dir(&host_dir) {
            tracing::debug!(
                host_dir = %host_dir.display(),
                %error,
                "PIP watcher: could not create operator publisher directory"
            );
        } else {
            tracing::info!(
                host_dir = %host_dir.display(),
                "PIP watcher: watching for operator-side policy information point sockets"
            );
            tokio::spawn(watch_pip_dir(
                Arc::clone(&cache),
                sandbox_id.clone(),
                PipOrigin::OperatorHost,
                host_dir,
            ));
        }
    }

    // Remote operator publishers: authorized at configuration time (the
    // configured endpoint list) and, for gateway-registered publishers, at
    // gateway configuration time. Environment endpoints seed the set; the
    // engine watcher unions in gateway registrations and reconnects on
    // reconciliation changes.
    let manager = Arc::new(RemotePipManager::new(Arc::clone(&cache), sandbox_id));
    let env_ca_pem = config
        .remote_ca_cert
        .as_ref()
        .and_then(|path| std::fs::read(path).ok());
    let env_endpoints: Vec<RemotePipEndpoint> = config
        .remote_endpoints
        .iter()
        .map(|endpoint| RemotePipEndpoint {
            name: None,
            endpoint: endpoint.clone(),
            ca_pem: env_ca_pem.clone(),
            bearer: None,
        })
        .collect();
    if let Some(engine) = engine {
        let watcher_engine = engine;
        let watcher_manager = Arc::clone(&manager);
        tokio::spawn(async move {
            let mut generation = watcher_engine.subscribe_pip_services();
            loop {
                let authenticated = watcher_engine.pip_authenticated();
                let registered: Vec<RemotePipEndpoint> = watcher_engine
                    .pip_remote_services()
                    .into_iter()
                    .filter(|service| {
                        if authenticated
                            && !service.allow_insecure_transport
                            && watcher_engine.pip_credential(&service.name).is_none()
                        {
                            // Fail closed rather than silently downgrading to
                            // an unauthenticated call (mirrors middleware).
                            tracing::warn!(
                                pip = %service.name,
                                "PIP registration is missing its extension credential; not connecting"
                            );
                            false
                        } else {
                            true
                        }
                    })
                    .map(|service| RemotePipEndpoint {
                        bearer: authenticated
                            .then(|| watcher_engine.pip_credential(&service.name))
                            .flatten(),
                        name: Some(service.name),
                        endpoint: service.grpc_endpoint,
                        ca_pem: (!service.tls_ca_cert_pem.is_empty())
                            .then_some(service.tls_ca_cert_pem),
                    })
                    .collect();
                let mut merged = env_endpoints.clone();
                for endpoint in registered {
                    if let Some(existing) = merged
                        .iter_mut()
                        .find(|existing| existing.endpoint == endpoint.endpoint)
                    {
                        // A gateway registration supersedes an environment
                        // endpoint for the same address, including its
                        // credential.
                        *existing = endpoint;
                    } else {
                        merged.push(endpoint);
                    }
                }
                watcher_manager.set_endpoints(merged);
                if generation.changed().await.is_err() {
                    return;
                }
            }
        });
    } else {
        manager.set_endpoints(env_endpoints);
    }
}

/// Maintains one connection task per remote publisher endpoint.
struct RemotePipManager {
    cache: Arc<PipCache>,
    sandbox_id: String,
    tasks: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
}

impl RemotePipManager {
    fn new(cache: Arc<PipCache>, sandbox_id: String) -> Self {
        Self {
            cache,
            sandbox_id,
            tasks: Mutex::new(HashMap::new()),
        }
    }

    /// Replace the connected endpoint set. Unchanged endpoints keep their
    /// streams, removed endpoints are stopped, and new endpoints are
    /// spawned.
    fn set_endpoints(self: &Arc<Self>, endpoints: Vec<RemotePipEndpoint>) {
        let mut tasks = self.tasks.lock().unwrap();
        let live: std::collections::HashSet<String> =
            endpoints.iter().map(|e| e.endpoint.clone()).collect();
        let removed: Vec<String> = tasks
            .keys()
            .filter(|endpoint| !live.contains(*endpoint))
            .cloned()
            .collect();
        for endpoint in &removed {
            tracing::debug!(endpoint = %endpoint, "PIP remote stream: endpoint removed");
            // Aborting the task skips its own fail-closed clear, so revert
            // the deregistered publisher's context here.
            self.cache.clear(endpoint);
            if let Some(task) = tasks.remove(endpoint) {
                task.abort();
            }
        }
        for endpoint in endpoints {
            if let std::collections::hash_map::Entry::Vacant(slot) =
                tasks.entry(endpoint.endpoint.clone())
            {
                tracing::info!(
                    endpoint = %endpoint.endpoint,
                    "PIP watcher: connecting to remote policy information point"
                );
                let task = tokio::spawn(run_remote_pip_connection(
                    Arc::clone(&self.cache),
                    self.sandbox_id.clone(),
                    endpoint,
                ));
                slot.insert(task);
            }
        }
    }
}

/// Wait for the workload's PID and mount namespace, then return the in-sandbox
/// PIP socket directory. Returns `None` when the sandbox root never becomes
/// visible (no in-sandbox publishers possible).
async fn resolve_sandbox_pip_dir(entrypoint_pid: &Arc<AtomicU32>) -> Option<PathBuf> {
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
        tracing::debug!("PIP watcher: entrypoint PID never published; no in-sandbox publishers");
        return None;
    }

    // Phase 2: wait for /proc/<pid>/root/ to become traversable.
    let probe = format!("/proc/{pid}/root/");
    for _ in 1..=10 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if std::fs::metadata(&probe).is_ok() {
            let pip_dir = PathBuf::from(&probe).join(PIP_DIR_RELATIVE);
            if let Err(error) = create_pip_dir(&pip_dir) {
                tracing::debug!(
                    pip_dir = %pip_dir.display(),
                    %error,
                    "PIP watcher: could not create in-sandbox PIP socket directory"
                );
            }
            return Some(pip_dir);
        }
    }
    tracing::debug!("PIP watcher: sandbox root never became visible; no in-sandbox publishers");
    None
}

/// Best-effort creation of a PIP socket directory with mode 0750.
fn create_pip_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o750);
        builder.create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Watch one PIP socket directory and maintain a connection task per
/// discovered `<name>.sock`.
async fn watch_pip_dir(cache: Arc<PipCache>, sandbox_id: String, origin: PipOrigin, dir: PathBuf) {
    // TOFU binary hashes for this directory, keyed by publisher name. The
    // origin prefix keeps same-named sandbox and operator publishers from
    // sharing a pin.
    let tofu: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut managed: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        for name in discover_sockets(&dir) {
            let key = format!("{}/{name}", origin.as_str());
            if let std::collections::hash_map::Entry::Vacant(slot) = managed.entry(key.clone()) {
                tracing::info!(
                    pip = %name,
                    origin = origin.as_str(),
                    "PIP watcher: connecting to policy information point"
                );
                let task = tokio::spawn(run_pip_connection(
                    Arc::clone(&cache),
                    Arc::clone(&tofu),
                    sandbox_id.clone(),
                    key,
                    name.clone(),
                    origin,
                    dir.join(format!("{name}.sock")),
                ));
                slot.insert(task);
            }
        }
        // Reap finished connection tasks (socket disappeared).
        managed.retain(|_, task| !task.is_finished());
        tokio::time::sleep(WATCH_INTERVAL).await;
    }
}

/// Names (`<name>` from `<name>.sock`) of PIP sockets currently present.
fn discover_sockets(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
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

/// Maintain one supervisor-initiated PIP stream until the socket disappears.
///
/// On stream error or disconnect the publisher's cached context reverts to
/// null and the connection is retried with backoff while the socket exists.
async fn run_pip_connection(
    cache: Arc<PipCache>,
    tofu: Arc<Mutex<HashMap<String, String>>>,
    sandbox_id: String,
    cache_key: String,
    name: String,
    origin: PipOrigin,
    socket_path: PathBuf,
) {
    loop {
        if !socket_path.exists() {
            tracing::debug!(pip = %name, "PIP stream: socket gone, stopping");
            return;
        }

        match run_pip_stream_once(
            &cache,
            &tofu,
            &sandbox_id,
            &cache_key,
            &name,
            origin,
            &socket_path,
        )
        .await
        {
            Ok(()) => {
                // Stream ended (publisher shutdown); retry after backoff.
                cache.clear(&cache_key);
                tracing::info!(pip = %name, "PIP stream: disconnected, context reverted to null");
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
            Err(PipStreamError::TofuMismatch) => {
                cache.clear(&cache_key);
                tokio::time::sleep(TOFU_MISMATCH_BACKOFF).await;
            }
            Err(PipStreamError::UnsupportedPlatform(detail)) => {
                // Identity verification cannot run on this platform. Fail
                // closed and stop retrying: connecting without verification
                // would let any in-sandbox process publish policy context.
                cache.clear(&cache_key);
                tracing::warn!(pip = %name, detail = %detail, "PIP stream: identity verification unavailable, not connecting");
                return;
            }
            Err(error) => {
                cache.clear(&cache_key);
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
    /// Identity verification cannot run on this platform. Terminal: the
    /// connection task stops instead of retrying. Constructed only on
    /// non-Linux targets.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    UnsupportedPlatform(String),
    Other(String),
}

impl std::fmt::Display for PipStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TofuMismatch => write!(f, "publisher binary hash failed TOFU verification"),
            Self::UnsupportedPlatform(detail) | Self::Other(detail) => write!(f, "{detail}"),
        }
    }
}

async fn run_pip_stream_once(
    cache: &Arc<PipCache>,
    tofu: &Arc<Mutex<HashMap<String, String>>>,
    sandbox_id: &str,
    cache_key: &str,
    name: &str,
    origin: PipOrigin,
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

    verify_publisher_identity(tofu, cache_key, name, &peer_pid)?;

    stream_pip_context(cache, cache_key, origin, channel, sandbox_id).await
}

/// Maintain one remote publisher stream. The endpoint was authorized at
/// configuration time; transport security is TLS for `https://` endpoints.
async fn run_remote_pip_connection(
    cache: Arc<PipCache>,
    sandbox_id: String,
    remote: RemotePipEndpoint,
) {
    let endpoint = remote.endpoint.clone();
    loop {
        match run_remote_pip_stream_once(&cache, &sandbox_id, &remote).await {
            Ok(()) => {
                cache.clear(&endpoint);
                tracing::info!(
                    endpoint = %endpoint,
                    "PIP remote stream: disconnected, context reverted to null"
                );
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
            Err(error) => {
                cache.clear(&endpoint);
                tracing::warn!(
                    endpoint = %endpoint,
                    %error,
                    "PIP remote stream: error, context reverted to null"
                );
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        }
    }
}

async fn run_remote_pip_stream_once(
    cache: &Arc<PipCache>,
    sandbox_id: &str,
    remote: &RemotePipEndpoint,
) -> Result<(), PipStreamError> {
    let mut tonic_endpoint = Endpoint::from_shared(remote.endpoint.clone())
        .map_err(|e| PipStreamError::Other(format!("invalid endpoint: {e}")))?
        .connect_timeout(Duration::from_secs(5));
    if remote.endpoint.starts_with("https://") {
        let tls =
            remote
                .ca_pem
                .clone()
                .map_or_else(tonic::transport::ClientTlsConfig::new, |pem| {
                    tonic::transport::ClientTlsConfig::new()
                        .ca_certificate(tonic::transport::Certificate::from_pem(pem))
                });
        tonic_endpoint = tonic_endpoint
            .tls_config(tls)
            .map_err(|e| PipStreamError::Other(format!("TLS config: {e}")))?;
    }
    let channel = tonic_endpoint
        .connect()
        .await
        .map_err(|e| PipStreamError::Other(format!("connect failed: {e}")))?;
    // Extension authentication attaches the bearer on every call, reading the
    // current token from the shared slot so rotation needs no reconnect.
    let interceptor = remote.bearer.clone().map_or_else(
        openshell_extension_core::BearerTokenInterceptor::disabled,
        |slot| slot.interceptor(),
    );
    let channel = tonic::service::interceptor::InterceptedService::new(channel, interceptor);

    stream_pip_context(
        cache,
        &remote.endpoint,
        PipOrigin::Remote,
        channel,
        sandbox_id,
    )
    .await
}

/// Open `StreamContext` on a connected channel and fold messages into the
/// cache until the stream ends.
async fn stream_pip_context<C>(
    cache: &Arc<PipCache>,
    cache_key: &str,
    origin: PipOrigin,
    channel: C,
    sandbox_id: &str,
) -> Result<(), PipStreamError>
where
    C: tonic::client::GrpcService<tonic::body::Body> + Clone,
    C::Error: Into<tonic::codegen::StdError>,
    C::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <C::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
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
            cache_key,
            origin,
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
    cache_key: &str,
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
        // Hash the live executable through the /proc/<pid>/exe magic symlink,
        // not the resolved path: the path is inside the sandbox's mount
        // namespace, so opening it from the supervisor could miss the file or
        // hash an unrelated host file at the same location. Opening the
        // symlink reads the publisher's actual running binary (mirrors
        // `verify_or_cache_process_exe`).
        let live_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let hash = procfs::file_sha256(&live_exe)
            .map_err(|e| PipStreamError::Other(format!("hash publisher exe: {e}")))?;

        let mut tofu = tofu.lock().unwrap();
        match tofu.get(cache_key) {
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
                        .evidence_pairs(&[("pip", name), ("disposition", "not_connected")])
                        .message("PIP publisher binary changed; supervisor refused to connect")
                        .build()
                );
                return Err(PipStreamError::TofuMismatch);
            }
            Some(_) => {}
            None => {
                tofu.insert(cache_key.to_string(), hash);
                tracing::info!(pip = %name, exe = %exe.display(), "PIP publisher binary pinned (TOFU)");
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tofu, cache_key, name, peer_pid);
        Err(PipStreamError::UnsupportedPlatform(
            "publisher identity verification requires /proc (Linux)".into(),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(())
    }
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
            PipOrigin::Sandbox,
            BTreeMap::from([("trust_state".to_string(), "suspended".to_string())]),
        );
        let merged = cache.merged().unwrap();
        assert_eq!(merged["trust_state"], "suspended");

        cache.update("defenseclaw", PipOrigin::Sandbox, BTreeMap::new());
        assert!(
            cache.merged().is_none(),
            "empty context is equivalent to null"
        );

        cache.update(
            "defenseclaw",
            PipOrigin::Sandbox,
            BTreeMap::from([("trust_state".to_string(), "suspended".to_string())]),
        );
        cache.clear("defenseclaw");
        assert!(cache.merged().is_none(), "disconnect reverts to null");
        assert_eq!(cache.connected_pips(), Vec::<String>::new());
    }

    #[test]
    fn multiple_pips_merge_with_operator_precedence() {
        let cache = PipCache::new();
        cache.update(
            // Lexicographically last, but the least trusted origin.
            "zeta",
            PipOrigin::Sandbox,
            BTreeMap::from([
                ("zeta.only".to_string(), "1".to_string()),
                ("shared".to_string(), "from-sandbox".to_string()),
            ]),
        );
        cache.update(
            "beta",
            PipOrigin::OperatorHost,
            BTreeMap::from([
                ("beta.only".to_string(), "2".to_string()),
                ("shared".to_string(), "from-operator".to_string()),
            ]),
        );
        let merged = cache.merged().unwrap();
        assert_eq!(merged["zeta.only"], "1");
        assert_eq!(merged["beta.only"], "2");
        // Operator values win key collisions regardless of name order: the
        // in-sandbox publisher cannot override operator context.
        assert_eq!(merged["shared"], "from-operator");
        // Snapshots carry each publisher's origin for audit attribution.
        let snapshot = cache.snapshot().unwrap();
        assert_eq!(
            snapshot.publishers,
            vec![
                ("beta".to_string(), PipOrigin::OperatorHost),
                ("zeta".to_string(), PipOrigin::Sandbox),
            ]
        );
    }

    #[test]
    fn sandbox_publisher_cannot_override_remote_operator_context() {
        let cache = PipCache::new();
        cache.update(
            "navra",
            PipOrigin::Remote,
            BTreeMap::from([("trust_state".to_string(), "suspended".to_string())]),
        );
        cache.update(
            "attacker",
            PipOrigin::Sandbox,
            BTreeMap::from([("trust_state".to_string(), "trusted".to_string())]),
        );
        let merged = cache.merged().unwrap();
        assert_eq!(
            merged["trust_state"], "suspended",
            "an in-sandbox publisher must not mask an operator restriction"
        );
    }

    // ---- End-to-end tests against mock publishers ----

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
        /// Whether the publisher requires extension-authentication bearers.
        require_bearer: bool,
        /// Whether a valid bearer was observed on the accepted stream.
        seen_bearer: Arc<Mutex<bool>>,
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
            let bearer_ok = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Bearer "));
            if self.require_bearer && !bearer_ok {
                return Err(tonic::Status::unauthenticated("missing bearer"));
            }
            *self.seen_bearer.lock().unwrap() = bearer_ok;
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
            require_bearer: false,
            seen_bearer: Arc::new(Mutex::new(false)),
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
        for _ in 0..200 {
            if let Some(value) = probe() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("condition never became true within 10s");
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
            "sandbox/defenseclaw".to_string(),
            "defenseclaw".to_string(),
            PipOrigin::Sandbox,
            socket.clone(),
        ));

        // Initial streamed context lands in the cache.
        let merged = wait_until(|| cache.merged()).await;
        assert_eq!(merged["trust_state"], "suspended");
        assert_eq!(merged["data_classification"], "phi");
        // The publisher observed the sandbox id from the request.
        assert_eq!(*seen.lock().unwrap(), Some("sbx-42".to_string()));
        // The publisher binary was pinned trust-on-first-use.
        assert!(tofu.lock().unwrap().contains_key("sandbox/defenseclaw"));

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
            "sandbox/nemoclaw".to_string(),
            "deadbeef".to_string(),
        )])));
        let cache = Arc::new(PipCache::new());
        let result = run_pip_stream_once(
            &cache,
            &tofu,
            "sbx-42",
            "sandbox/nemoclaw",
            "nemoclaw",
            PipOrigin::Sandbox,
            &socket,
        )
        .await;

        assert!(matches!(result, Err(PipStreamError::TofuMismatch)));
        // No RPC reached the publisher and no context was cached.
        assert!(cache.merged().is_none());
        assert!(seen.lock().unwrap().is_none());

        server.abort();
    }

    #[tokio::test]
    async fn watcher_exits_when_pid_is_never_published() {
        // The watcher must not spin or panic when no entrypoint PID arrives;
        // the in-sandbox task exits quietly after the polling window.
        let cache = Arc::new(PipCache::new());
        let pid = Arc::new(AtomicU32::new(0));
        let config = PipWatcherConfig {
            host_dir_root: tempfile::tempdir().unwrap().keep(),
            remote_endpoints: Vec::new(),
            remote_ca_cert: None,
        };
        // Short-circuit the 5s wait window by running to completion; the
        // watcher polls 20 times at 250ms.
        tokio::time::timeout(
            Duration::from_secs(10),
            run_pip_watcher_with_config(cache, pid, "sbx".into(), config),
        )
        .await
        .expect("watcher exits when PID is never published");
    }

    #[tokio::test]
    async fn operator_side_host_publisher_streams_without_entrypoint() {
        // An operator-side publisher on the supervisor host is served from
        // <host_root>/<sandbox_id>/<name>.sock and needs no in-sandbox
        // process at all (entrypoint PID never published).
        let host_root = tempfile::tempdir().expect("host root");
        let sandbox_dir = host_root.path().join("sbx-77");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        let socket = sandbox_dir.join("navra.sock");
        let (server, seen, shutdown) = spawn_mock_pip(&socket, "sbx-77").await;

        let cache = Arc::new(PipCache::new());
        let pid = Arc::new(AtomicU32::new(0));
        let config = PipWatcherConfig {
            host_dir_root: host_root.path().to_path_buf(),
            remote_endpoints: Vec::new(),
            remote_ca_cert: None,
        };
        run_pip_watcher_with_config(Arc::clone(&cache), pid, "sbx-77".to_string(), config).await;

        let merged = wait_until(|| cache.merged()).await;
        assert_eq!(merged["trust_state"], "suspended");
        assert_eq!(*seen.lock().unwrap(), Some("sbx-77".to_string()));

        shutdown.send(true).expect("signal publisher shutdown");
        server.abort();
        wait_until(|| cache.merged().is_none().then_some(())).await;
    }

    #[tokio::test]
    async fn engine_registered_remote_publisher_streams_and_reconciles() {
        // Gateway-registered publishers arrive through the OPA engine
        // (`[[openshell.supervisor.pip]]` in gateway.toml → configuration
        // snapshot → replace_pip_services). Registering an endpoint connects
        // it; replacing the registration set disconnects the old endpoint.
        const POLICY_REGO: &str = include_str!("../data/sandbox-policy.rego");

        let seen = Arc::new(Mutex::new(None));
        let seen_bearer = Arc::new(Mutex::new(false));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let service = MockPip {
            expected_sandbox_id: "sbx-99".to_string(),
            seen_sandbox_id: Arc::clone(&seen),
            require_bearer: true,
            seen_bearer: Arc::clone(&seen_bearer),
            shutdown: shutdown_rx,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(PolicyInformationPointServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let engine = Arc::new(
            crate::opa::OpaEngine::from_strings(POLICY_REGO, "network_policies: {}\n")
                .expect("engine"),
        );
        let cache = Arc::new(PipCache::new());
        let pid = Arc::new(AtomicU32::new(0));
        run_pip_watcher_with_engine(
            Arc::clone(&cache),
            pid,
            "sbx-99".to_string(),
            Arc::clone(&engine),
        )
        .await;

        // No registrations yet: nothing connects.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(cache.merged().is_none());

        // An authenticated registration without its credential fails closed:
        // the watcher refuses to connect rather than downgrade to an
        // unauthenticated call.
        engine.replace_pip_services(
            vec![openshell_core::proto::SupervisorPipService {
                name: "navra".to_string(),
                grpc_endpoint: format!("http://{addr}"),
                tls_ca_cert_pem: Vec::new(),
                audience: String::new(),
                allow_insecure_transport: false,
            }],
            HashMap::new(),
            true,
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            cache.merged().is_none(),
            "missing credential must fail closed"
        );

        // With the credential installed, the stream connects and carries the
        // extension bearer on every call.
        let expires_at_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 3_600_000;
        let slot = openshell_extension_core::BearerTokenSlot::new("test-pip-token", expires_at_ms)
            .expect("bearer slot");
        engine.replace_pip_services(
            vec![openshell_core::proto::SupervisorPipService {
                name: "navra".to_string(),
                grpc_endpoint: format!("http://{addr}"),
                tls_ca_cert_pem: Vec::new(),
                audience: String::new(),
                allow_insecure_transport: false,
            }],
            HashMap::from([("navra".to_string(), slot)]),
            true,
        );
        let merged = wait_until(|| cache.merged()).await;
        assert_eq!(merged["trust_state"], "suspended");
        assert_eq!(*seen.lock().unwrap(), Some("sbx-99".to_string()));
        assert!(
            *seen_bearer.lock().unwrap(),
            "bearer must reach the publisher"
        );

        // Removing the registration stops the stream and reverts the cache.
        engine.replace_pip_services(Vec::new(), HashMap::new(), true);
        wait_until(|| cache.merged().is_none().then_some(())).await;

        shutdown_tx.send(true).expect("signal publisher shutdown");
        server.abort();
    }

    #[tokio::test]
    async fn remote_publisher_streams_over_configured_endpoint() {
        // A remote publisher is a plain TCP gRPC server authorized by
        // appearing in the configured endpoint list.
        let seen = Arc::new(Mutex::new(None));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let service = MockPip {
            expected_sandbox_id: "sbx-88".to_string(),
            seen_sandbox_id: Arc::clone(&seen),
            require_bearer: false,
            seen_bearer: Arc::new(Mutex::new(false)),
            shutdown: shutdown_rx,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(PolicyInformationPointServer::new(service))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let cache = Arc::new(PipCache::new());
        let pid = Arc::new(AtomicU32::new(0));
        let config = PipWatcherConfig {
            host_dir_root: tempfile::tempdir().unwrap().keep(),
            remote_endpoints: vec![format!("http://{addr}")],
            remote_ca_cert: None,
        };
        run_pip_watcher_with_config(Arc::clone(&cache), pid, "sbx-88".to_string(), config).await;

        let merged = wait_until(|| cache.merged()).await;
        assert_eq!(merged["trust_state"], "suspended");
        assert_eq!(*seen.lock().unwrap(), Some("sbx-88".to_string()));

        shutdown_tx.send(true).expect("signal publisher shutdown");
        server.abort();
        wait_until(|| cache.merged().is_none().then_some(())).await;
    }
}
