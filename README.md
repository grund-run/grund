# grund

grund takes an app from a bare machine to live for its users, on hardware
you own. This repository is grund itself: the server (dashboard, API and
background work), the orchestrator and the agent that runs on each machine.

grund.sh is live. This checkout's self-hosted instance runs the account,
machine, app deployment and own-machine storage paths described below.
Follow the deployment and data-backup instructions before depending on an
instance.

## Install the alpha CLI

Linux amd64 and arm64 downloads include the CLI, server and machine commands
in one static binary. **Alpha software: expect changes; back up data.**
Read the installer before running it:

```sh
curl -fsSLo install-grund.sh https://grund.sh/install
cat install-grund.sh
sh install-grund.sh
grund --version
grund login                           # hosted dashboard at https://app.grund.sh
```

It verifies SHA-256 before replacing `grund` in `~/.local/bin`, or
`/usr/local/bin` as root, without invoking sudo. Add the printed directory to
`PATH` if needed. `--bin-dir /absolute/path` chooses another directory;
`--version v0.0.0-alpha.3` pins a release. Without a version it resolves the
newest published release, including alpha prereleases. Download failures or
checksum mismatches leave the installed binary alone. Checksums rely on the
public registry's HTTPS; releases are not signed. macOS downloads are not
published yet.

For your own instance, `grund login https://grund.example.com` selects it.
An explicit address, `--instance` or `GRUND_INSTANCE` wins over the last
signed-in instance; only a fresh login falls back to the hosted dashboard.

## What is open, and what is paid

grund is open source. The self-hosted edition is free, and it is the real
product: deploying, releases, data, domains, and a whole team signing in
with passwords, with nothing held back to make the paid plans look better.
A few features on top are commercial. Their source is in `ee/`, where
it can be read. They are not in the public self-hosted build.

| | Where | License |
|---|---|---|
| Everything grund does, except the features below | everywhere but `ee/` | AGPL-3.0-only |
| The API contract, descriptors and clients | `proto/`, `crates/grund-descriptors`, `crates/grund-proto` | Apache-2.0 |
| Sign in with GitHub or Google (planned for the Homelab plan) | `ee/` | all rights reserved for now |
| Single sign-on with your own provider, audit log (planned for Business) | `ee/` | all rights reserved for now *(not built)* |

The hosted capacity provider and customer billing pages are supplied by
a separate private build. Neither is needed to self-host grund; this
checkout builds the public server, CLI and machine agent on their own.

Where things stand, plainly: nothing is for sale yet. The commercial
features in `ee/` are published so you can read them, but they are not
licensed for use and the public self-hosted build and image do not include
them. Commercial terms come when grund has a company to offer them; the
pricing on grund.sh is planned pricing. [LICENSE](LICENSE) says which
license covers what, and what the AGPL asks of you. Contributions are
welcome under Apache-2.0 with a sign-off ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Self-hosting

Managed installation is available from `v0.0.0-alpha.5`; CLI and managed
server updates are available from `v0.0.0-alpha.6`. The no-argument local
flow below is available from alpha.10: alphas .5 through .9 still require
a domain or an existing-instance setup code.

Installation requires Linux, root and systemd. On Debian or Ubuntu releases
whose own repositories provide Docker Compose v2, the installer announces and
installs missing Docker tools from those repositories. Otherwise, install
Docker Engine and Docker Compose v2 first. grund does not run a third-party
installation script.

**Fresh Debian 13:** use alpha.11 or newer for automatic Docker setup.
Alpha.10 omitted the separate client package; if keeping that release,
install `docker.io`, `docker-cli` and `docker-compose` first.

### Start without a domain

```sh
sudo "$(command -v grund)" install
```

On a terminal, leave the domain question empty to run locally. Scripts
use that same local default without prompting; `--yes` also suppresses
prompts and animated output. `--verbose` shows technical details, and
`NO_COLOR` disables colour.

grund listens only at `http://localhost:8080`. HTTP itself has no TLS:
use the printed SSH forwarding command from another computer, then open
the one owner setup link. Finishing owner setup connects this machine
automatically. No DNS name or separate machine setup code is needed.
The summary prints the next check, `grund doctor machine`.

To add HTTPS later, point a DNS name at this machine, make TCP 443
reachable, then run:

```sh
sudo "$(command -v grund)" install --domain grund.example.com
```

That upgrades the local server to TLS without replacing its data,
instance keys, enrolled-machine identity or server image. The existing
agent keeps its loopback connection. The name is the dashboard's address,
not an app's.

### Start with a domain, or join an existing instance

The explicit domain path, also supported by alphas .5 through .9, is:

```sh
sudo "$(command -v grund)" install --domain grund.example.com
sudo docker compose --project-directory /opt/grund exec grund /grund setup-link
# Open the link, create the owner, and get a setup code on Machines.
sudo "$(command -v grund)" install --domain grund.example.com --code CODE
grund login https://grund.example.com
```

`grund install --url https://grund.example.com --code CODE` installs only
the agent for an existing instance, not another server. `grund agent`
remains the foreground runner: it uses an existing registration, waits
for owner setup after a managed local install, or asks you to install or
join first on an unregistered machine.

Configuration is in `/opt/grund/.env`; the server image is pinned by its
verified release digest. The server and agent run under
`grund-server.service` and `grund-agent.service`. Reinstalling preserves
configuration, secrets, data and the server image; a different
`--version` is refused. The CLI and agent executables are separate, so
replacing the CLI does not change the next agent restart. `--no-vms`
skips Firecracker; arm64 supports container apps without it.
No app is deployed automatically. DNS, mail and scheduled backups are
not configured for you. Unmanaged configuration, changing an already-set
domain, and unsupported custom agent data-directory or `EnvironmentFile`
settings are refused instead of overwritten.

| Operation | Command |
|---|---|
| Inspect the managed services | `sudo systemctl status grund-server grund-agent` |
| Preview service removal | `sudo grund uninstall --dry-run --json` |
| Stop and remove managed services | `sudo grund uninstall --yes` |
| Preview an update to this CLI only | `grund update --channel alpha --dry-run` |
| Replace this CLI after checksum/version verification | `grund update --channel alpha --yes` |
| Preview a managed server update | `sudo "$(command -v grund)" update server --channel alpha --dry-run` |
| Back up, preflight, migrate and update the server | `sudo "$(command -v grund)" update server --channel alpha --yes` |

Uninstall retains `/opt/grund`, both server data volumes, machine identity
and workload disks. It does not revoke the retained machine automatically
or undo host networking. CLI/server updates do not replace agent executables;
other machines keep their installed build until explicitly reinstalled.

Updates preserve the installed release's channel by default. `stable`
excludes alphas; `alpha` includes final releases, ordered by numeric version.
`--version` selects an exact tag instead. Downgrades are refused.
Server updates require the canonical local database, named volumes and
managed key/password paths; only separate read-only TLS mounts are supported
as extra primary-service mounts. Unsupported topology is refused before downtime.
The updater stops writes and validates a root-only recovery set under
`/opt/grund/backups` before changing the image or running forward migrations.
It leaves a recovery journal after a cutover failure and never automatically
starts an older image against a migrated database. **Recovery replaces both
instance volumes and managed configuration together**; keep independent backups
and external TLS files. `grund update server --help` lists the supported scope.

To build from a checkout instead:

```bash
git clone https://git.kjuulh.io/grund/grund.git && cd grund
docker compose up -d --wait     # builds this checkout; then http://localhost:8080
GRUND_DOMAIN=grund.example.com docker compose up -d --wait     # or https, on 443
docker compose exec grund /grund setup-link                    # the owner's one-time link
```

That runs grund with PostgreSQL and NATS (wake-ups for background work).
The first account, the instance's owner, comes from `grund setup-link`: it
prints a link that works once, for an hour, and only while there is no
account, so the first sign-in needs no mail server and nobody else can
claim a fresh instance. Sign-up stays closed until then. Secrets are generated on first start into the
`grund-data` volume and kept. grund runs non-root in a read-only container,
and runs its migrations on every start. The first build takes a few
minutes. To run a published image instead, set `GRUND_IMAGE` and
`GRUND_PULL_POLICY=missing` in `.env`. Every setting is documented in
[.env.example](.env.example).

To add a machine, use "Add machine" on the Machines page. The command it
gives installs grund and its agent on a Linux machine (root, systemd,
amd64 or arm64) and connects it. This instance serves the installer and its
own binary at `/install`; the code's command selects that binary explicitly.
A machine on another host needs HTTPS, below.

Machines shows each machine's app and instance counts and reserved CPU, memory
and disk against its allocatable capacity. Open one of your own machines to see
its placed instances and volumes, linked to their apps, its software and last
contact. `grund machines list` and `grund machines get MACHINE` expose the same
data. The runtime reserves 256 MiB and 250m CPU before placing apps. Older raw
capacity reports are normalized by the server; updated agents report the net
capacity explicitly.

Virtual machines reserve their whole guest CPU and memory on the parent, plus
128 MiB for the VM monitor; apps inside a VM reserve capacity on the guest,
not a second time on the parent. App and VM allocation share the same capacity
check: creating a VM on a cordoned or full machine is refused. A requested VM
stop keeps its reservation until the machine reports a terminal state.
Reservations also include draining app instances; unsized volumes and existing
host directories are marked unbounded, not zero.

Apps require cgroup v2, including inside a VM: CPU limits throttle, and memory
limits can OOM-kill an app. An older own-machine guest without cgroup v2 reports
apps unavailable; it needs an explicit guest-image update, not a silent restart.

New agents also report whole-machine CPU, memory and data-filesystem usage
and uptime with their five-second heartbeat. These are measurements, separate
from reservations. Older agents show `Not reported`; samples older than
30 seconds show `stale`. There is no whole-machine usage history or network-traffic collection.
The detail page shows each app's disconnect policy: stateless instances become
eligible for replacement after its configured wait; apps with volumes stay
pinned. A replacement needs another eligible machine with capacity. A server
or database outage can restart the wait. Placement times do not imply readiness.

**App output and resource history.** New agents collect app stdout/stderr and
per-instance CPU and memory every ten seconds through their authenticated
connection. Data stays in this instance's database; no extra service is required.
Memory includes filesystem cache. Missing measurements are unknown, not zero.
Owners, admins and members can read their organisation's live apps.
In the dashboard, open an app's **Metrics** for hour/day/week charts against its
reservations, or **Logs** for search, instance/release/time filters and follow.

By default, each organisation retains up to 24 hours / 32 MiB of logs and seven
days / 24 MiB of measurements, whichever bound is reached first. Accounting charges
UTF-8 body bytes plus 384 bytes per log and 384 bytes per raw or rollup metric row.
Metrics keep ten-second detail for an hour, minute buckets through a day and
ten-minute buckets through a week, preserving weighted averages and maximum memory.
These are **not physical database-size limits**: replay receipts, MVCC, WAL,
replication and backup storage are additional. The settings and hard ceilings are in
[`grund serve --help`](#the-binary) and [.env.example](.env.example).

Collection is bounded and lossy, not an audit trail. Each machine buffers at most
16 MiB for offline delivery; pressure discards oldest batches. By default, batches
older than six hours are refused even if the spool has space. A machine disconnected
from its instance longer than that loses older buffered telemetry. Known delivery
gaps are labelled `not received (machine offline)`; unknown or evicted evidence is
not attributed to an outage. This does not mean the app stopped or emitted logs.
Rejected batches are counted in agent statistics. Lines are limited to 8 KiB and
marked when truncated. New or restarted containers have separate,
bounded capture; existing running containers keep combined output with periodic
truncation, not a strict size bound. Their next ordinary restart, deploy, image
update or rollback enables separate bounded capture; grund does not restart them
silently. Exact known app secret values are redacted before offline-delivery spooling
and sending. Local capture files remain raw, private machine data. Interleaved output,
especially legacy combined output, can retain secret fragments. Transformed secrets,
unknown credentials and personal data are not detected.

The log view keeps historical combined output labelled with its latest collected
time, not a universal capture cutover date. Owners and admins can choose
**Restart to enable**: the normal rolling path replaces one instance at a time,
waiting for health and drain before the next. A single-copy app warns about
possible interruption when a replacement cannot run alongside it. Stateful
workloads keep their machine and volume fencing.

**HTTPS.** With `GRUND_DOMAIN` set, grund terminates TLS itself on 443, with
no proxy in front. It orders the certificate by ACME from Let's Encrypt
(`GRUND_ACME_DIRECTORY` names another CA), proving the name with
TLS-ALPN-01 on 443 itself, so port 80 can stay closed. It keeps the
certificate in PostgreSQL, with the key sealed by the instance key, and
renews in the window the CA's renewal information (ARI) suggests. The
name's DNS must point at this machine, and 443 must be reachable from the
internet. If the CA is unreachable, grund keeps serving the certificate it
has and retries with backoff; `/health/ready` reports a `certificate` check
(minor) that turns degraded within 14 days of expiry. Your own certificate
works instead: set `GRUND_TLS_CERT_FILE` and `GRUND_TLS_KEY_FILE`
(re-read when they change). Plain http stays on 127.0.0.1:8080. Every
setting is in `grund serve --help` and [.env.example](.env.example).
grund's TLS, here, on its relays, between machines (iroh's QUIC) and in
its HTTPS and SMTP clients, offers TLS 1.3 and 1.2. Its key exchange
prefers the hybrid post-quantum X25519MLKEM768 and falls back to X25519,
with no C crypto library beyond ring (`crates/grund-crypto`).

**A relay on another host.** Machines behind different NATs need a relay
with a public address: `grund relay` on a host of its own, listed in the
instance's `GRUND_RELAYS`. Its certificate comes from the instance, which
orders it by ACME; the relay makes its key and answers TLS-ALPN-01 on its
own 443, and the key never leaves its host. Enroll it once:
`docker compose exec grund grund relays token relay.example.com` prints a
one-time token for that host, which the relay takes as
`GRUND_RELAY_ENROLLMENT_TOKEN` on its first start. From then on it signs
every call with a key of its own, kept in `GRUND_RELAY_DATA_DIR`.
`grund relays revoke relay.example.com` shuts it out. Every setting is in
`grund relay --help`.

An edge that loses its relay path waits until the relay answers again, then
closes its old endpoint before reconnecting with the same identity. It keeps
working direct machine streams open. Without a reachable relay or a direct
machine path, app traffic remains unavailable; a cached TLS certificate alone
does not mean the machine is reachable.

What compose deliberately does not do:

- **Scheduled backups.** No scheduled job protects the instance volumes.
  A managed server update takes a recovery set; checkout-managed deployments
  need their own backups. `docker compose down -v` deletes both volumes and
  every account with them. Back up both, and try a restore once.
- **Mail.** None is sent until `GRUND_SMTP_URL` is set: password reset
  and invitations wait in the outbox, and readiness says so. Set it and
  `GRUND_MAIL_FROM` for real users. To try grund without a mail server,
  `COMPOSE_PROFILES=mail` and `GRUND_SMTP_URL=smtp://mailpit:1025` add
  Mailpit, which catches every mail at http://localhost:8025 and delivers
  none.
- **Checkout updates.** Back up both instance volumes before `git pull` and
  `docker compose up -d`. These commands apply to checkouts, not to the
  installer-managed `/opt/grund` deployment.

### Machines following their instance

Machine build following is available from v0.0.0-alpha.8.
The feature-capable installer explicitly enables following and installs a
retained `grund-agent-updater.service`. Existing agents need one installer
rerun from a feature-capable instance; response fields alone cannot give a
legacy agent safe rollback.

This updater requires systemd. Hosted machines are updated by their hosting
provider, not by this updater; automatic hosted guest-image rollout is not
available yet.

Following replaces only `/usr/local/lib/grund/agent/grund`, not the CLI or
server. It targets the instance's exact public build, not the newest release.
The updater independently verifies artifacts from grund's fixed public registry;
checksums are not release signatures. An unpublished or unsupported build leaves
the current agent running. One machine is authorized at a time across the instance.
Health verification and durable finalize precede the next machine; verified
rollback pauses the rollout, and uncertain authorization retains its slot.

For unchanged app specs, restarting the agent preserves running apps. Missing
runtime observations are unknown, not proof that a process stopped. A running
container retains its last applied network identity while control-plane or
private-network configuration is unavailable; that temporary loss does not
recreate it.

Local root controls stop new authorization, not recovery of an existing attempt:

```sh
sudo /usr/local/lib/grund/agent/grund machine-follow status
sudo /usr/local/lib/grund/agent/grund machine-follow pause
sudo /usr/local/lib/grund/agent/grund machine-follow resume
```

An instance operator runs `/grund agent-updates status`,
`/grund agent-updates pause` or `/grund agent-updates resume` inside the configured
server container. Do not restore an older coordinator database while following
is enabled: pause first, then reconcile machine journals and provider grants
before resuming. Automatic following is not a cross-system recovery protocol.

## The binary

One binary, `grund`, with subcommands: `serve` (the control plane),
`migrate`, `init` (generate the instance's secrets), `setup-link` (the
owner's one-time link, run with `serve`'s settings), `doctor` and `probe`
(a health check for the scratch image), `join` and `agent` (a machine),
`relay(s)` and `edge(s)`. The same binary is the client for people, scripts
and coding agents: see "The CLI" below.

`grund doctor instance` (in compose: `docker compose exec grund /grund
doctor instance`) and `grund doctor machine` (on a machine, as root) check
without changing anything, one line per check (`ok`, `warn`, `fail` or
`skip`, its name, what was seen, and a `fix:` line), or one JSON document
with `--json`. The exit code is 1 when any check fails. `grund serve --help` lists every setting with
its environment variable.

grund sends no anonymous usage reports. App logs and resource measurements go
to the instance each machine joined. CLI and server updates are explicit; install/update
commands contact the public release registry. Following machines also contact
that registry when their instance offers a different public build.
With `GRUND_ACCOUNT_EVENT_URL` and `GRUND_ACCOUNT_EVENT_TOKEN`,
an instance queues one account event after the owner's email is confirmed and
POSTs it to the operator's configured endpoint. The event includes the account
ID, username, address, sign-in method and registration/verification times;
the endpoint chooses what to retain or notify. Without both settings, nothing
is queued or sent. See [.env.example](.env.example).

- `GET /health/live` answers `{"status":"ok"}` and checks nothing.
- `GET /health/ready` answers 200 or 503 from the last dependency checks,
  with the build `revision` and each check's state.
- Everything grund manages belongs to an organisation. A self-hosted
  instance has one (`GRUND_ORGANISATIONS=single`, the default): the first
  account, made with the setup link, owns it, and everyone after joins by
  invitation. A fresh `multi` instance also starts with a setup link: its
  first owner owns both `admin` and a personal organisation. Later sign-ups
  get their own organisations while open signup is enabled. Reserved names,
  including `admin` and `grund`, cannot be claimed by an ordinary
  organisation create or rename.
- Pages: `/signup`, `/signup/owner` (the setup link), `/verify`, `/login`, `/reset`, `/` (which opens your
  organisation), `/{org}`, `/{org}/members`, `/{org}/settings`,
  `/{org}/settings/tokens`, `/{org}/settings/registries`, `/orgs/new`,
  `/invite`, `/settings/sessions`, and `/style-guide`, which renders every
  component with example data.
- The API is ConnectRPC (`proto/`, generated at build time; Connect, gRPC and
  gRPC-Web on the same routes). `grund.account.v1.AccountService` has
  `GetViewer`, `ListSessions` and `RevokeSession`;
  `grund.organisation.v1.OrganisationService` lists, creates, renames and
  deletes organisations and manages their members and invitations, with the
  same rules as the pages. It takes the dashboard's session cookie, from this
  origin only, a `grund login` session (`Authorization: Bearer
  grund_cli_…`), or a personal access token (see "Deploy from CI" below).
  `grund.token.v1`, `grund.registry.v1` and `grund.login.v1` (the CLI's
  device login, approved on `/device`) are in `proto/` beside the rest.
- Organisations can be renamed (the old name redirects members and stays
  reserved) and deleted by their owners. A deletion is a mire saga: billing
  answers first, and while it cannot be reached grund keeps asking.
- Billing is an optional external service (`proto/grund/billing/v1`).
  Without `GRUND_BILLING_URL`, every organisation is free and nothing is
  sent. When configured, grund queues organisation creation, rename and
  deletion in the durable outbox, and consults billing before completing a
  deletion. An unavailable billing service delays deletion; it never
  grants deletion by default. Enabling billing on an existing instance
  queues its live organisations for registration at startup with stable
  event IDs. Customer checkout, payment portal, complimentary grants,
  machine usage and hourly metering are not part of the public build.
  `GRUND_BILLING_MODE` is `off` without that service and defaults to
  `sandbox` when it is configured; live mode requires `live` explicitly.
  Customer checkout in sandbox is disabled unless
  `GRUND_BILLING_SANDBOX_CHECKOUT=true` is set for testing. The production
  `app.grund.sh` origin refuses that sandbox test setting at startup.

```bash
curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
  http://localhost:8080/grund.account.v1.AccountService/GetViewer
# {"code":"unauthenticated","message":"sign in first"}
```

## The CLI

`grund` does everything the dashboard does, over the same API:

```bash
grund login grund.example.com          # approve in the browser; a session, revocable on Sessions
grund apps deploy -f grund.yaml --wait # every app the file declares; makes missing apps
grund apps status shop --json          # health, copies ready of wanted, the rollout
grund apps logs shop --follow --stream stderr
grund apps metrics shop --range hour
grund apps set shop image ghcr.io/acme/shop:2.1 --dry-run
grund apps set shop copies 3
grund apps rollback shop 4 --wait
grund machines add web-2               # prints the command to run on the new machine
grund domains add shop.example.net
grund domains check shop.example.net   # check setup and queue an eligible certificate retry
grund domains add example.com
grund domains verify example.com       # after adding the printed ownership TXT
grund domains app-domain example.com   # existing and future apps get <app>.example.com
grund domains subdomain shop storefront
grund tokens create --name ci --scope deploy --apps shop --json
```

Logs support literal `--search` and `--since` / `--until` collection times.
Both commands accept `--instance-id` and `--release` filters; global `--instance`
selects the server URL instead. `logs --follow --json` emits one response per
line and stops with Ctrl-C. `--help` lists the time formats and query limits.

On grund's hosted service, `grund machines offers` shows the available sizes
and your whole-VM allowance; `grund machines add NAME --hosted --size SIZE
--region REGION` saves a claim, including when capacity is waiting. Use
`grund machines remove NAME --yes` to request its safe return. These commands
use a public interface with a private provider implementation. A self-hosted
server without that service reports that hosted machines are only available
on grund's hosted service, rather than a raw RPC error. Ordinary `machines
add` still enrolls your own machine and never rents one.

- Nouns: `login`, `logout`, `whoami`, `orgs`, `apps`, `stacks`, `volumes`,
  `machines`, `domains`, `members`, `invitations`, `tokens`, `registries`.
- `--json` (or `-o json`, or `GRUND_OUTPUT=json`) on every command prints one
  JSON document: the protobuf JSON of the API's answer, or of a
  `grund.cli.v1` message (`proto/grund/cli/v1/cli.proto`). A failure prints
  `{"error": {"code", "message", "hint", "field", "reason"}}` on stderr and
  exits 1 failed, 2 usage or confirmation needed, 3 not signed in, 4
  permission denied, 5 not found, 6 conflict, 7 invalid, 8 unavailable, 9
  rollout failed.
- Nothing asks without a terminal: destructive commands need `--yes` then.
  Every command that changes the instance takes `--dry-run` except `domains
  verify` (ownership lookup) and `domains check` (an immediate setup check).
  `apps deploy --dry-run` resolves its image and checks the proposed change
  without writing it; `apps update --dry-run` only previews the cached selection.
  `apps deploy --dry-run` also previews a missing app without creating it
  and reports structured desired-versus-live changes and the observed
  `expectedVersion`; `apps deploy shop --expected-version N` refuses a
  stale single-app release. The API exposes the same through
  `AppService.PreviewDeploy`, `GetApp.version` and
  `DeployRequest.expected_version`.
- `--instance URL` and `--org SLUG` work before or after the noun; explicit
  values override `GRUND_INSTANCE` and `GRUND_ORG`. For CI use `GRUND_TOKEN`
  (a personal access token); otherwise `grund login` writes
  `~/.config/grund/credentials.yaml` (mode 0600; a file others can read is
  refused). Organisation fallback remains `grund orgs use`, then the token's
  organisation, then your only one.
- For agents: `grund describe --json` is the whole command tree with types,
  defaults, examples, output schemas and error codes, generated from the
  code; [schema/cli.json](schema/cli.json) is this commit's. `grund schema
  output <command>` gives one output's JSON Schema. `grund skill install`
  writes a SKILL.md for Claude Code (`grund skill print` for others), and
  `grund mcp` serves the commands as MCP tools over stdio (`claude mcp add
  grund -- grund mcp`).
- Versioned releases publish Linux amd64 and arm64 binaries with
  `SHA256SUMS`. An instance that serves its installer also exposes its own
  architecture's binary at `/install/grund-linux-<arch>`.

**App image updates are available from v0.0.0-alpha.7.** The dashboard shows
cached status; an app's Settings has explicit Check and Update actions.
The same operations are in the CLI:

```sh
grund apps updates shop --check
grund apps update shop --dry-run
grund apps update shop --wait
```

A check compares the app's tag with its running image and may show a labelled
template suggestion when the repository matches. It does not prove template
origin or a newer software version. Update makes a release of the selected
content without replacing your settings; it does not follow a tag that moves
after the check. Multiple choices require `--candidate` or `--digest`.
Stale checks and in-progress rollouts are refused. There are no scheduled checks
or automatic app updates. Back up app data first: image rollback is not data restore.

Domains and an app's Settings show one current status and only the DNS records
still needed, with copy buttons. **Details** holds the setup observations,
check and retry times, and failed-attempt count; it opens on failure. Move,
Unbind and Remove are in each domain's actions menu. `grund domains` shows the
same concise status; use `grund domains --details` for diagnostics.
Setup pages refresh while waiting and stop when HTTPS is working.
**Check now** queues a fresh check without bypassing a certificate authority's
retry deadline.

For organisation app addresses, verify a parent such as `example.com`, then
choose **Use for app addresses** in its actions menu on Domains. Point
`*.example.com` at the configured edge shown for an address still awaiting DNS.
Existing and future apps get `<app>.example.com`; an owner or admin can choose another single-label name
in app Settings or with `grund domains subdomain`. Collisions are refused,
and unbinding is an opt-out until explicitly restored. DNS control labels
are reserved; `api`, `www` and `admin` remain usable on your own parent.
Each assigned hostname uses its own HTTP-01 certificate. Wildcard DNS does
not require a wildcard certificate, DNS-01 or DNS-provider credentials.

## Deploy from CI

CI runs the CLI with a personal access token:

```bash
GRUND_INSTANCE=https://grund.example.com GRUND_TOKEN=$GRUND_TOKEN \
  grund apps deploy shop -f grund.yaml --note "$CI_COMMIT_SHA" --wait --json
```

1. Under Organisation, API tokens (or `grund tokens create`), make a token.
   It is shown once: keep it in your CI's secrets, here as `GRUND_TOKEN`. It
   starts with `grund_pat_` so secret scanners can find a leaked one. grund
   stores only its SHA-256.
2. Each build deploys the image it just pushed, from the repository's
   `grund.yaml` or from flags (`--image`, `--port`, `--env`).

A deploy token limited with `--apps shop` can exercise its deploy-scope
app operations only on that named app and read its bound domains. It cannot
bind or verify domains. CI or a release provider can pass
`DeployRequest.external_release` (forest organisation, destination,
project, intent UUID and artifact UUID) with an expected stream version:
the same key and request replay the original numbered release; a different
artifact/spec or forest owner is refused. Domain binding and a public
origin readiness check are separate from making a release.

The CLI is a client of the API; without it, `Deploy` takes the same:

```bash
curl --fail-with-body -sS https://grund.example.com/grund.app.v1.AppService/Deploy \
  -H "Authorization: Bearer $GRUND_TOKEN" -H 'Content-Type: application/json' \
  -d '{"organisation": "acme", "name": "shop", "note": "'"$CI_COMMIT_SHA"'",
       "spec": {"image": "ghcr.io/acme/shop:'"$CI_COMMIT_SHA"'",
                "ports": [{"name": "http", "port": 8080, "public": true}]}}'
```

Or send the repository's `grund.yaml` instead of a spec:

```bash
jq -n --rawfile file grund.yaml --arg note "$CI_COMMIT_SHA" \
  '{organisation: "acme", name: "shop", grundYaml: $file, note: $note}' |
curl --fail-with-body -sS https://grund.example.com/grund.app.v1.AppService/Deploy \
  -H "Authorization: Bearer $GRUND_TOKEN" -H 'Content-Type: application/json' -d @-
```

A `grund.yaml` declares one or more apps; a deploy takes the one it names:

```yaml
# yaml-language-server: $schema=https://grund.example.com/schema/grund.json
apps:
  shop:
    image: ghcr.io/acme/shop:2026-09-26.1
    copies: 2
    ports:
    - name: http
      port: 8080
      public: true
    env:
      DATABASE_URL: postgres://shop@db.grund.internal:5432/shop
    secrets:
      DATABASE_PASSWORD: db-password
    check:
      http: /healthz
```

Every instance serves the file's JSON Schema at `/schema/grund.json`
([schema/grund.json](schema/grund.json) in this repository). Editors that
read the first line's `$schema` (VS Code with the YAML extension, and other
editors using yaml-language-server) complete and check the file. In the
dashboard, an app's Settings has its newest release as this file, to copy,
download, or edit and apply. An unknown key is refused with its line,
column and path.

### Stacks

In the dashboard, open **Stacks → Create stack**. Paste a stack file or load
a basic, web + PostgreSQL + Redis, or app + Caddy example. **Preview** validates
the complete file and shows services, resources, storage and machine selection
without creating anything. Review it, then choose **Create stack**; **Edit file**
returns to the editor. Owners and admins create stacks. A name already used by
a stack is refused, not treated as an update.

The web/data example passes generated connection URLs as `DATABASE_URL` and
`REDIS_URL` to an nginx image service; replace that image with your application
to use them. Passwords are generated through the existing templates catalogue,
not embedded in the file. Enter custom secret values only after previewing;
refused forms never return those values. Use the stack's actions menu to edit,
restart, roll back, delete or restore it. Editing keeps the original name and
refuses a version changed since the editor was opened.

A stack owns several services on one existing capable machine or VM; it
creates neither a VM nor a shared localhost namespace. Private services remain
organisation-private, not isolated from other stacks. Agents must support stacks.
`placement.kind: hosted` is refused; stacks cannot request hosted machine rental.
Use top-level `stack` with `name` and `services` instead of `apps`: at most ten
services and 1 MiB of raw YAML per file. The same [file schema](schema/grund.json) describes both.
Services use app fields or a catalogue `template`. A whole env value such as
`${{ database.url }}`, with `depends_on: [database]`, delivers an encrypted
connection binding without copying credentials into the file.
Prefix a whole expression with an extra `$` (`$${{ database.url }}`) to deliver it literally.

```sh
grund stacks deploy -f grund.yaml --dry-run
grund stacks deploy -f grund.yaml --wait
grund stacks restart shop --wait
grund stacks logs shop --service web --follow
grund stacks metrics shop --service database --range hour
```

`--service web` updates only that service and refuses hidden sibling changes.
Removing a service also needs its explicit `--confirm-remove NAME`; omission
never purges data. Stack deletion drains and fences writers before the existing
[data-recovery window](#app-volumes-on-your-own-machines) begins. **A singleton
stateful restart briefly interrupts that service.** Rollback pins images and
secret versions, not database contents. Change backing apps through their stack;
`grund stacks --help` lists lifecycle commands and protected secret input.

Strict rolling services require positive `release.max_surge`; there is no stop-first fallback.
A failed first deployment retains its owned data without starting a deletion deadline.
Accepting Restore cancels child and volume deletion deadlines before waiting for capacity.
For explicit retries, reuse both `--idempotency-key` and the original `--expected-version`.


### Database templates

Deploy app → Template offers PostgreSQL and Redis when a connected machine
has working storage and enough resources. Each creates an app-owned data
volume and a generated password stored as an app secret. They run one copy;
their TCP readiness checks confirm a listening port, not database transactions.

| Template | Default hosted capacity | Data mount |
|---|---|---|
| PostgreSQL | 10 GiB | `/var/lib/postgresql/data` |
| Redis | 1 GiB | `/data` |

Own machines, including self-hosted instances, use local directories without
a capacity quota or automatic backup. Hosted templates request daily snapshots;
a request is not a verified recovery point. Hosted snapshots are crash-consistent
and same-site only, not protection against whole-site loss. Hosted capacity
is fixed; resizing is not supported. Redis syncs disk writes about once a second,
so abrupt power loss can lose recent writes.

On every start PostgreSQL restores its template host-auth rule and any missing
default configuration files. This does not repair database files or make a
snapshot database-consistent; test a restored copy before relying on it.

The app overview shows host, port, database/user and the environment variables
to set in another app. Secrets are separate per app. Owners and admins can
explicitly reveal and copy a grund-generated template password: each successful
reveal is audited without its value, limited to five per actor and organisation
per minute. User-entered values, including replacements, remain write-only.
Changing `POSTGRES_PASSWORD` does not rotate an existing database's password;
change the password inside PostgreSQL and update its consumers explicitly.
MinIO is unavailable because it no longer publishes public images.

### App volumes on your own machines

An app with a volume runs as one copy, pinned to the machine holding its
directory. A release stops that copy before starting the next; an offline
machine makes the app wait rather than writing somewhere else. Volumes are
available on your own machines. Declare named mounts in `grund.yaml`:

```yaml
apps:
  photos:
    image: example/photos:1
    volumes:
      data:
        path: /data
        backup: daily
      media:
        path: /var/media
        source: /srv/photos
```

With no `source`, the agent makes an app-owned directory in its data directory.
It survives releases and agent restarts. Deleting its volume or app stops use
immediately; the owner can restore the same identity and data before the
configured purge deadline (seven days by default; `GRUND_VOLUME_DELETE_WINDOW`
in hours). Deleted apps remain visible to owners on Apps. After the deadline,
grund requests physical erasure; an offline machine may not acknowledge it
until it reconnects. Use `grund apps list-restorable` and `grund apps restore
photos`, or `grund volumes restore-deleted photos data` for an individually
deleted volume. An existing `source` binds a customer-owned host directory,
only if the machine owner's local agent policy allows it. grund never erases
that host directory. Storage uses the host filesystem and its existing
permissions and encryption; there is no volume size quota. Keep independent
backups of the machine.

Creating another app with the same name during recovery is refused with
`name_reserved_for_restore`. The API, dashboard and CLI messages show the
recorded dates in UTC, for example `15 Oct 2026 19:04:03 UTC`. The API's
`ErrorReason.deleted_at` and `ErrorReason.purge_after` retain exact timestamps
as protobuf Timestamps (RFC 3339 in JSON). A live app
with that name still gives `name_taken`; another organisation can use the same
name.

An organisation owner or admin can end recovery early for a volume already
pending deletion, including one on a deleted app, with `grund volumes purge-now
photos data --reason 'owned synthetic app cleanup' --yes` (or ConnectRPC
`PurgeVolumeNow` with its current `expectedVersion`). This irreversible request
records the actor, reason and time and starts the same physical-erasure workflow
as deadline expiry. `deleting` is not proof the disk is gone: the volume leaves
the listing only after the machine or hosted storage backend confirms erasure.
Members cannot purge, and unrelated apps or organisations cannot select a
volume. The seven-day default remains unchanged for all other volumes.
Use `--dry-run` to preview the exact scoped purge request and audit reason
without erasing data or sending `PurgeVolumeNow`; omit it and confirm (or pass
`--yes`) only when the preview names the intended volume.

Every ancestor of an existing host directory must be root-owned and not
writable by non-root users; a user-writable home directory cannot be a source.
The source directory itself keeps its existing owner and permissions. This
prevents replacing its path after the agent checks it but before it is mounted.

`backup: daily` only requests backups; it does not protect data until an owner
configures an HTTPS S3-compatible destination and a verified recovery point
appears in Settings → Volumes. The agent encrypts backups with restic; the
destination credentials and repository password are sealed in grund, and the
repository password can be exported for independent recovery. Restore creates
a *new* managed volume on a chosen own machine, never overwriting the source.
Use `grund volumes list photos`, `grund volumes show photos data`,
`grund volumes backups photos data status`, `grund volumes backups photos data
points`, or `grund volumes restore --help`. On deletion grund retains its
backup credentials and point catalog until the purge deadline so a restored
app can resume backup; it removes them after purge, not the external S3 data.
Remove obsolete S3 data yourself. The backup does not include grund's own
PostgreSQL or data volumes (see Self-hosting).

### Hosted block volumes (operator-enabled build)

An instance with a hosted storage backend accepts a fixed block size in GiB
instead of an own-machine directory or host path:

```yaml
apps:
  photos:
    image: example/photos:1
    copies: 1
    volumes:
      data:
        path: /data
        size_gib: 200
        backup: daily
```

One app may use up to four hosted drives, all on one eligible machine; do not
mix block and own-machine mounts or combine `size_gib` with `source`. The
generic public server includes this file/API contract but **not** a hosted
storage backend: it rejects hosted creation rather than mounting an empty
directory. On an operator-enabled instance, signed mounts require a fresh,
exact host acknowledgement for that volume, machine lease and drive slot.
The app waits when the acknowledgement or checked ext4 device is missing.
Host-local bytes survive releases and a fenced lease-end detach, but moving
to a different physical host requires a paused data-volume migration or an
explicit restore into a new volume from a completed snapshot. Losing an
unbacked-up host loses its data; `backup: daily` is a request, not a
successful recovery point. Hosted provider snapshots do not use the
customer's own-machine S3 destination.

### Other app placement

For apps without volumes, copies spread over machines, one per machine first;
a copy on a machine that stays unreachable for 2 minutes (`reschedule_after`)
starts on another. On the Machines page, owners and admins label machines
(`zone=a`, `disk=ssd`) and take one out of service before maintenance: its
copies move, each started and ready elsewhere before it stops. An app's
`placement` picks machines by label and kind, and spreads over a label's
values before machines:

```yaml
    placement:
      labels: {disk: ssd}
      spread_by: zone
```

A copy on a machine that no longer matches moves the same way. One with
nowhere to go keeps running, and the app says what it waits for
("Waiting for a machine labelled disk=ssd.").

`Deploy` answers with the new release once its image is resolved to a
digest; the rollout then runs on its own. `GetApp` shows it
(`app.rollout.state` is `ROLLOUT_STATE_SUCCEEDED` or `ROLLOUT_STATE_FAILED`).
An error answers with a non-2xx status and a JSON body whose `code` says
why (`unauthenticated`, `not_found`, `invalid_argument`,
`failed_precondition`), so `--fail-with-body` fails the job.

What a token can do:
- It acts as the account that made it, in its own organisation only: any
  other organisation is `not_found`. It never does more than that account's
  role allows today, so a member's token can read apps but not deploy, and
  leaving the organisation leaves the token powerless.
- Its scope is chosen when it is made. `deploy` (the default) may call
  `CreateApp`, `GetApp`, `ListApps`, `Deploy`, `ListReleases`, `Rollback`,
  `Scale`, `ConfigureApp`, `SetSecret` and explicit app-image checks/updates.
  `full` may also change stacks, delete apps and manage machines, custom domains,
  members, invitations and registry logins. Stack changes need a full organisation
  token; otherwise the CLI says `stack changes need a full token`. Deploy tokens
  have read-only stack access. App-limited tokens can read a stack only when their
  allowlist covers its current and retained backing apps. A narrower stack-deploy
  grant is not available. Neither scope reaches the account, sessions, tokens, or
  creating, renaming and deleting organisations: those get `permission_denied`.
- It expires after 7, 30, 90 or 365 days, chosen when it is made. Owners and
  admins see and revoke every token of the organisation, members their own.
  A revoked or expired token is `unauthenticated` from the next call.
- An organisation holds at most 100 live tokens.

### Private images

Under Organisation, Registries, an owner or admin saves a login for a
registry host (`ghcr.io`, `registry.gitlab.com`, `docker.io` for Docker
Hub, `registry.example.com:5000`): a username and a password or, better, a
token that can only read packages. Then every image on that host is
resolved and pulled with it: grund uses it to turn the tag into a digest
when you deploy, and a machine is handed it, over its signed control link,
only to pull the image of one of your apps placed on it. The password is
stored sealed, is never shown again, and is never written into a release,
an event, a machine's desired state or a log. Saving a host again replaces
its login; removing it makes pulls from that host anonymous again. An
organisation holds logins for at most 20 hosts. Without a login, a private
image is refused when you deploy, with a message that names the host.

## Layout

```
crates/grund/          the binary; tests/accepttest/ (the contract over the wire)
crates/grund-server/   the control plane: config, services, pages, API, background work
crates/grund-server/templates/  compiled .html.sedge pages and components, and .txt.sedge mail
crates/grund-store/    PostgreSQL: migrations, event-sourced write paths, read models
crates/grund-domain/   aggregates, events and pure decisions; no I/O
crates/grund-config/   shared grund.yaml, YAML and validated values; no event store or server runtime
crates/grund-crypto/   shared TLS crypto provider and client config; no listeners or certificate generation
crates/grund-descriptors/  API descriptors and the shared proto file list (needs protoc)
crates/grund-proto/    typed messages and services generated from those descriptors
ee/grund-ee/           the commercial features, plugged in through one Extension seam (--features ee)
tools/comment-policy/  the CI check that Rust comments are docs on public items only
compose.yaml           the self-hosted instance
compose.dev.yaml       development and test infrastructure on fixed local ports
Dockerfile             builds the image from source (compose); Dockerfile.prebuilt packages CI's binary
check.sh               the static binary in a read-only scratch container, against the accepttests
```

The design documents, threat model and agent notes live in
[grund/grund-docs](https://git.kjuulh.io/grund/grund-docs) (private).

Pages and mail compile from typed Sedge templates at build time; page models and
form errors are Rust values. There is no runtime template loader. Changing a
template rebuilds `grund-server`.

Signed-in pages move between each other without a full reload: sedx (in the
sedge repository) fetches the next page and morphs it in, keeping the sidebar,
focus and typed input. Every page is still a complete page without JavaScript.

## Develop and verify

```bash
docker compose -f compose.dev.yaml up -d      # PostgreSQL, NATS, Mailpit on fixed local ports
cargo run -p grund -- serve --database-url postgres://grund:grund@127.0.0.1:55410/grund --dev-mode true

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -q -p comment-policy
cargo test --workspace --locked               # unit, store (real PostgreSQL) and accepttests
./check.sh                                    # plus the accepttests against the scratch image
```

The accepttests spawn the real binary against real PostgreSQL, NATS and
Mailpit. Point them at a running instance with `GRUND_ACCEPT_URL` (and
`GRUND_ACCEPT_MAILPIT_URL` for the flows that read mail).

## Releases

Tags on the `v0.0.0-alpha.N` line publish alpha prereleases. The tag workflow
waits for the normal CI gates, checks static amd64/arm64 binaries, runs the
arm64 commands under QEMU, and exercises the final amd64 binary against real
PostgreSQL and NATS before packaging those bytes into a multiarch image.
It publishes the immutable generic package at
`https://git.kjuulh.io/api/packages/grund/generic/grund/<tag>/`
(`grund-linux-amd64`, `grund-linux-arm64`, `SHA256SUMS`, `compose.yaml`,
`agent-install.sh`, the source `release.txt`, and `image-digest.txt`).
Existing package files and image tags have to match; a conflict never
overwrites a release. The public Gitea release is created last, and is what
the installer's release list resolves. There is no mutable `latest` package
or image.

`v0.0.0-alpha.1` and `v0.0.0-alpha.2` are unpublished tags. The first exposed
an annotated-tag identity mismatch; the second stopped at a missing Git
dependency in its clean runtime check. Neither published binaries or a
Gitea release. Release attribution peels annotated tags to the source
commit; `tools/test-release.py` covers it and refuses a different checkout.

Pushes to `main` still publish the commit-addressed amd64 image and machine
artifacts at `main-<commit>`. Neither a release tag nor this public
repository's CI deploys a hosted instance.
