# Host integration templates — not an installer

These files are examples, not enabled production configuration. No unit, rule,
account or directory from this folder has been installed on Site VM.

The working daemon still uses the separate `uli-ups-site.service` template.
The Next controller and automatic rollback remain disabled pending Qwen's durable
release/artifact/base Store API. Copying these examples does not enable deployment.

## Identities and directories

The JSON examples use illustrative identities: agent UID996, builder UID995,
application UID997, shared deployment GID986. Resolve real accounts on the host;
never create accounts using these numeric IDs without checking existing ownership.
Use a dedicated non-login builder without a user manager or production credentials.
Agent, builder and app must be distinct users. Runtime GID must be in the agent's
supplementary groups so its unprivileged export can set group ownership.

Private `/opt/site/UliUpS`, state and sources remain agent-owned0700.
Configuration remains agent-owned0600. Root-owned executable recommended.
Proposed runtime sibling `/opt/site/uliups-runtime`: agent-owned0750,
deployment GID; releases0750, staging0700, exported leaves2770/files0660.
The builder cannot rename the releases directory or modify the private source pool.
This new runtime sibling and host paths require integration approval before changing
the existing Site layout. No existing Site release directory is moved by this code.

The build unit bind-mounts only the immutable agent executable at worker-bin, so
builder access does not require opening the private UliUpS directory.
The root-owned /etc/uliups/site-build.json and Node/npm files must be readable by
the builder, with root-owned ancestors and no group/other write. Check the actual
Debian npm entry path; symlinked launchers are rejected by the worker.
Pre-create a regular root-owned0755 worker-bin placeholder at the bind target before validating/starting the unit. Outside the bind mount its empty content must not execute. Cache must be builder-owned0700. Do not bind production env/secrets into builds.

## Fixed unit and selection contract

The controller must prove the build unit is stopped and its cgroup empty BEFORE
export/selection changes. A single fixed build unit uses build-current. systemd
resolves WorkingDirectory and ReadWritePaths for that invocation; the worker
compares kernel CWD with the selected leaf and executes fixed Node/npm commands.
No package can supply shell fragments, unit names or build paths.

Build output is executable, untrusted code even when signed. The unit denies
capabilities, cgroup delegation and access to system/user manager buses, limits
memory/tasks/CPU and permits writes only in its selected leaf and private cache.
NoNewPrivileges is mandatory. The worker independently checks the effective UID,
capabilities, unified cgroup, resource limits and read-only root, then pins CWD.

BUILD_READY reports successful npm ci/build only: activated=false, healthy=false.
The future controller must check empty cgroup after exit, validate/export output,
reconcile its durable journal/Store, switch, start and verify the real service.
It must not trust a successful systemctl acknowledgement as a health check.

Root-owned control policies restrict operations to one exact app/build unit.
They grant NO privilege. A narrow polkit rule example now accompanies them: only stop/restart for fixed units. The Rust start gate uses RestartUnit after observing inactive/failed; verb=start is intentionally denied because it can authorize caller-defined transient units. No sudo or automatic privileged installation is included. Existing host policy ordering and root-owned unit files/drop-ins must be reviewed; no broader rule may pre-authorize this dedicated user.

## Site-specific acceptance still required

Keep existing media mounts and mount dependencies. A new release must fail closed
if NFS/bind mounts are unavailable. Keep databases, media, OAuth secrets, agent
state and recovery data outside replaced release trees. Do not execute database
migrations without the approved policy. No Site files or schema were edited here.

The health example assumes an endpoint with an exact release response header.
It is not evidence that Site already implements that endpoint. The Rust HTTP
module rejects non-loopback targets/redirects but does not prove TCP socket
ownership. The matching systemd invocation and listening-socket/cgroup proof
remain a controller acceptance gate.

## Checks performed

The Rust worker, root policy gates and real Next build/start/failure recovery have
run as isolated temporary systemd units in Ubuntu WSL. These deployment templates
themselves have NOT been installed or accepted on Debian13. systemd permissions,
media dependencies and the project's real service layout must be checked there.
Agent self-update/bootstrap and real power-loss recovery remain unimplemented.


Local WSL acceptance also covers the private executable bind and real nonroot polkit stop/restart; direct StartUnit/StartTransientUnit/other units/properties are denied. Temporary host rules/units were removed. This is not Debian or production acceptance.
