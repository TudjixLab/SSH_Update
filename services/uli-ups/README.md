# SSH Update Agent 0.1.0 alpha

SSH Update Agent is a standalone Rust agent embedded in one Linux project. This alpha
provides a running daemon and tested deployment components. Automatic application
activation, rollback and agent self-update are not enabled.

> The Rust package, executable and systemd unit retain the historical internal name
> `uli-ups` for compatibility. The public product name is SSH Update.

Uli UpS is a standalone Rust agent embedded in one Linux project. This alpha
provides a running daemon and tested deployment components. Automatic application
activation, rollback and agent self-update are not enabled.

## Available

- Strict configuration, existing SQLite Store, exclusive daemon lease,0600 local
  Unix socket, bounded requests/events/errors, SIGINT/SIGTERM shutdown.
- Existing SEALED upload → signature verification → release/job registration →
  private immutable full source tree → PREPARED, activated=false.
- Durable execution-intent journal: immutable job/profile binding, generation CAS,
  fsync, atomic publication, conservative recovery classification.
- Rust build-worker: dedicated nonroot UID/GID, fixed root-owned Node/npm policy,
  pinned CWD, cgroup/capability/resource checks, approved environment, bounded
  output/deadlines/cancellation. Runs fixed npm ci and npm run build.
- WorkspacePool library: requires an SDK PreparedTree token, copies its signed
  inventory with SHA256 checks, uses private staging, preserves original sources,
  refuses overwrite, fences publication and selects a separate build workspace.
- Exact-unit systemd library with root-owned policy and runtime User verification.
- Loopback HTTP health library: no redirects, bounded response/deadline, expected
  status and optional exact release header. No public listener is opened.

BUILD_READY reports successful build only: activated=false, healthy=false.
Workspace export, systemd and HTTP libraries are not wired into an automatic
deployment controller or a new network protocol.

## Incomplete

- Durable registered-release lookup and retained-artifact/base recovery integration.
- Complete Store/journal/controller ordering, final build-output freeze, selection,
  process/socket identity proof, activation and automatic rollback after failures.
- Incremental staging through the agent, authenticated SSH/SFTP integration.
- Persistent storage/mount integration and project-specific migration policy.
- Actual Debian13 acceptance and physical power-loss tests.
- Signed agent self-update with independent recovery bootstrap.

StartDeploy, RequestRollback and ValidateRelease through local IPC fail closed.
Do not bypass those checks using direct SQL, alternate uploads or an unsigned package.

## Build

From repository root, on Linux with Rust1.100.0 and a C compiler:
~~~sh
cargo build -p uli-ups --release --locked
./target/release/uli-ups --version
~~~
The workspace crates and Cargo.lock are required. The agent is Linux-only.
Storage requires openat2, local filesystem permissions/locking/fsync and SQLite WAL
support. SQLite state must not be on a network filesystem.

## First launch without a .deb installer

Example stable location inside a project, outside replaceable release trees:
~~~text
/opt/site/UliUpS/
  bin/uli-ups
  agent.json
  state/
  sources/
~~~
The operator creates these directories and installs the unit manually.
Use a dedicated non-login agent account. Agent home/state/sources: agent-owned0700;
agent.json: agent-owned0600. Root-owned0755 executable recommended. Configured
ancestors must be root/agent-owned, without group/other write or symlinks.

Copy agent.example.json to agent.json, set the actual instance/app/profile/runtime/
health identifiers and project PUBLIC Ed25519 key. A private signing key must never
be stored on the agent. Placeholder values intentionally do not provide a usable
production configuration. Keep all real credentials/state out of Git.

Review uli-ups-site.service paths/users before installing it. Create state and
sources first. Do not put UliUpS below current or a replaceable application release.

As the agent account:
~~~sh
/opt/site/UliUpS/bin/uli-ups serve --config /opt/site/UliUpS/agent.json
~~~
From a second process of the SAME user:
~~~sh
printf '%s\n' '{"protocol_major":1,"request_id":"check-1","expected_instance_id":"site-production","command":{"type":"health"}}' | /opt/site/UliUpS/bin/uli-ups request --config /opt/site/UliUpS/agent.json
~~~

CLI:
~~~text
uli-ups serve --config ABS_PATH
uli-ups request --config ABS_PATH < request.json
uli-ups stage-upload --config ABS_PATH --upload-id EXISTING_SEALED_ID --request-id UNIQUE_ID
uli-ups build-worker --policy ROOT_OWNED_JSON
uli-ups --version
~~~
stage-upload prepares full packages only, stops at PREPARED and rejects agent
replacement. The existing upload mechanism must have created the SEALED upload.
No new remote receiver is implemented by that command.

Run build-worker only inside its reviewed systemd sandbox as the configured builder
account, never as root or in the immutable source pool. It rejects invalid contexts.

## Host templates

deployment/ contains root policy examples, a build-unit example, a future agent
drop-in and narrow polkit example. Review real accounts, paths, root-owned unit
files/drop-ins and existing authorization ordering before installation.
These examples are not an installer and do not enable the unfinished controller.

Use different UIDs for agent, builder and application. Never expose production
secrets or the private source/state directories to build scripts. The build unit
exposes only the immutable worker executable through a read-only bind mount.

The systemd start helper requires inactive/failed state and uses RestartUnit, which
can start a stopped static unit. The policy grants stop/restart only. verb=start
is deliberately denied because it also authorizes caller-defined transient units.
Manager acknowledgements are not application health or completed transitions.

References:
- https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
- https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html

## Local IPC

Input is the existing uliup-protocol Request, one bounded JSON line per connection.
Peer UID must match the agent. Hello/Capabilities use the shared Response shape;
other bodies are local controlv1, not an SSH protocol replacement.
Queries: AgentVersion, Health, InstanceInfo, GetJob, ListEvents, ListErrors.
Unfinished jobs are retained. Corrupt execution records fail closed.
An existing job is never marked healthy merely because the daemon restarted.

## Validation of this alpha

Observed on 2026-11-14 in Ubuntu WSL:
- Process/Store/signals/IPC, full signed staging, invalid signature, protected paths.
- Bounded history paging, source-anchor symlink rejection, durable intent recovery
  including a child-process SIGKILL fixture.
- Runtime export: signed inventory, changed source, symlink/cancellation/protected
  agent, no overwrite, source preservation and injected publication-fence failure.
- Bounded HTTP checks, final cancellation, child reaping and exact-unit identity.
- Real Node22.22.1/Next16.4.6/React19.3.1 build under UID65534, service and HTTP probe.
  A component harness exercised a broken subsequent build and restarted the previous
  working app. This is not an accepted Store-driven automatic rollback.
- Updated daemon under systemd as UID1000: start/restart/SIGKILL autorestart,
  SIGTERM stop and socket cleanup.
- Temporary nonroot delegation: allowed exact-unit stop/restart; other unit,
  properties, direct StartUnit and StartTransientUnit denied.
- Scoped service Clippy passed. Shared crates were not changed for server integration.

Standard reproducible source tests:
~~~sh
cargo test -p uli-ups --locked
cargo clippy -p uli-ups --all-targets --no-deps --locked -- -D warnings
~~~
The ignored journal child probe is invoked by its process-kill parent test.
Environment-specific acceptance harnesses and internal records are not part of
this source publication. Debian execution, complete deployment recovery and
production readiness remain unverified.
