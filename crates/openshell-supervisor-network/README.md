# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Sandbox instance inputs

`run_networking` takes a `SandboxInstanceNetwork` with the sandbox identity,
the sandbox instance's `GatewayEndpoint`, the SPIFFE Workload API socket for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. Each instance owns its provider token cache and
HTTP client; a token acquired for one sandbox is never served to another.
Without a Workload API socket, token grants fail closed. A process hosting
several instances serves `/v1/denials` from a per-instance
`SandboxInstanceDenialLog` instead of the shared shorthand log files.

## Reserved destinations

`preauthorize_transparent_open` matches a staged TCP open against the reserved
OTLP relay address (`openshell_core::sandbox_env::OTLP_RELAY_ADDR`) before host
mapping, policy evaluation, and SSRF checks. The address is an unroutable
label, so the proxy never dials it. When `run_networking` receives a
`ReservedDestination`, the proxy hands the workload stream to its
`ReservedStreamHandler`; a handler that refuses, for example at its connection
cap, turns the open into a resource-exhausted denial. Without a handler, the
proxy denies the open at once. It logs the first attempt at warn and later ones
at debug, and emits no OCSF denial event: a standard OpenTelemetry SDK retries
for the life of the agent, and one event per retry would flood the OCSF log.
The supervisor installs its OTLP relay receiver as the handler while the agent
trace relay is active.

## Static credential placement

Substitution checks the declared request location before writing upstream.
Credentials without placement metadata default to the Authorization header. HTTP placement violations return a safe 403 response;
WebSocket violations close the connection with policy denial. Both paths emit a
domain event and a detection finding without credential values or placeholders.
Explicit body and WebSocket
rewrite flags authorize those locations for ordinary static credentials. SigV4
signing retains the endpoint-scoped resolver's existing trusted access.

## Policy Information Point (RFC 0019, prototype)

`pip.rs` implements the supervisor side of the Policy Information Point
interface: governance software publishes per-sandbox security context that
network policy acts on, merged into the OPA input document as `input.pip`.
The supervisor — never the sandbox or the publisher — initiates every
connection. Three publisher classes share one contract
(`openshell.pip.v1.PolicyInformationPoint`, `proto/pip.proto`):

- **In-sandbox publishers** serve on a Unix domain socket at
  `/run/openshell/pip/<name>.sock` inside the sandbox, discovered through
  `/proc/<pid>/root/`. Zero configuration.
- **Operator-side publishers (same host)** serve the identical contract under
  `/run/openshell-supervisor/pip/<sandbox-id>/` (override the root with
  `OPENSHELL_PIP_HOST_DIR`). The directory is created with mode 0750.
- **Remote publishers** are operator-configured gRPC endpoints. The gateway
  registration path is `[[openshell.supervisor.pip]]` in `gateway.toml`
  (name, grpc_endpoint, optional CA bundle), delivered in the sandbox
  configuration snapshot and reconciled by the policy poll loop through
  `OpaEngine::replace_pip_services`. For the standalone proxy role,
  `OPENSHELL_PIP_REMOTE_ENDPOINTS` (comma-separated) and
  `OPENSHELL_PIP_REMOTE_CA_CERT` configure the same class directly.
  Configuring either list is the configuration-time authorization for those
  publishers; the engine watcher unions both sources and reconnects on
  reconciliation changes, clearing the cached context of deregistered
  endpoints.

Unix-socket publishers (in-sandbox and same-host operator) are verified via
`SO_PEERCRED` plus a TOFU SHA256 pin of the `/proc`-resolved executable; a
mismatch refuses the connection and emits an OCSF detection finding. On
stream error or publisher shutdown the cached context reverts to null
(fail-closed); an absent or empty publisher is equivalent to no publisher,
so baseline policy applies unchanged.

The watcher tasks are spawned by `run_networking` whenever the OPA engine is
active. Every OPA query builds its input through
`OpaEngine::input_json_with_pip`, which merges the cached properties into
`input.pip` (null when no publisher is connected).

PIP denial is policy-authored and deny-only. A network policy declares
`pip_deny_rules` (`key`/`equals` pairs, schema in `openshell-policy-schema`,
proto `PipDenyRule` on `NetworkPolicyRule`); the baked policy
(`data/sandbox-policy.rego`) fires `pip_denies_network` when a rule on a
matching policy equals a published property, and `allow_network` /
`network_action` require `not pip_denies_network`. Published context can
never expand the allowlist. Because a custom Rego policy could map
`input.pip` to an allow decision, `OpaEngine::from_files`/`from_strings`
reject operator-supplied Rego that references `input.pip` (the baked policy
is exempt); authored `pip_deny_rules` is the supported surface.

Denial attribution: `EgressAuthorization` captures a `PipSnapshot`
(publishers with origins, merged properties) and a `pip_influenced` flag on
denials, and the denial OCSF events (transparent TCP, staged transparent,
CONNECT) tag `pip_influenced`/`pip_publishers`/`pip_origins`/`pip_context`
when the deny rule fired, so analysts can weight in-sandbox-sourced
evidence accordingly. Prototype follow-ups: per-request L7 evaluation
against `input.pip`, and authenticated transport (extension credentials)
for remote publishers, mirroring middleware extension authentication.
