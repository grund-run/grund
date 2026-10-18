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

Managed installation is implemented in this checkout; **alpha.4 and earlier
do not contain `grund install`**. Use a release that includes this command.
It requires Linux, root, systemd, Docker Engine and Docker Compose v2:

```sh
sudo grund install --domain grund.example.com
sudo docker compose --project-directory /opt/grund exec grund /grund setup-link
# Open the printed link, create the owner, and get a setup code on Machines.
sudo grund install --domain grund.example.com --code CODE
grund login https://grund.example.com
```

The name is the dashboard's address, not an app's; point it at this machine
and make TCP 443 reachable first. Configuration is in `/opt/grund/.env`;
the image is pinned by its verified release digest. The server runs under
`grund-server.service`; `grund-agent.service` is enabled but waits for
enrollment. The second pass connects it without changing its identity.
Reinstalling preserves configuration, secrets, data and the server image;
a different `--version` is refused. The CLI and agent executables are
separate, so replacing the CLI does not change the next agent restart.
`--no-vms` skips Firecracker; arm64 supports container apps without it.
No app is deployed. DNS, Docker installation, mail and scheduled backups
are not configured for you. Unmanaged configuration, another domain and
unsupported custom agent data-directory or `EnvironmentFile` settings are
refused instead of overwritten.

| Operation | Command |
|---|---|
| Inspect the managed services | `sudo systemctl status grund-server grund-agent` |
| Preview service removal | `sudo grund uninstall --dry-run --json` |
| Stop and remove managed services | `sudo grund uninstall --yes` |

Uninstall retains `/opt/grund`, both server data volumes, machine identity
and workload disks. It does not revoke the retained machine automatically
or undo host networking. A managed server update command is not included in
this release. Migrations remain forward-only; rollback needs a complete
backup, not an older image.

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
and disk against its capacity. Open one of your own machines to see its placed
instances and volumes, linked to their apps, its software and last contact.
`grund machines list` and `grund machines get MACHINE` expose the same data.
Reservations include draining instances and virtual machines; unsized volumes
and existing host directories are marked unbounded, not zero.

New agents also report whole-machine CPU, memory and data-filesystem usage
and uptime with their five-second heartbeat. These are measurements, separate
from reservations. Older agents show `Not reported`; samples older than
30 seconds show `stale`. There is no usage history or network-traffic collection.
The detail page shows each app's disconnect policy: stateless instances become
eligible for replacement after its configured wait; apps with volumes stay
pinned. A replacement needs another eligible machine with capacity. A server
or database outage can restart the wait. Placement times do not imply readiness.

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

- **Backups.** Nothing backs up the `grund-postgres` and `grund-data`
  volumes. `docker compose down -v` deletes them and every account with
  them. Back up both, and try a restore once.
- **Mail.** None is sent until `GRUND_SMTP_URL` is set: password reset
  and invitations wait in the outbox, and readiness says so. Set it and
  `GRUND_MAIL_FROM` for real users. To try grund without a mail server,
  `COMPOSE_PROFILES=mail` and `GRUND_SMTP_URL=smtp://mailpit:1025` add
  Mailpit, which catches every mail at http://localhost:8025 and delivers
  none.
- **Updates.** For a checkout, `git pull` and `docker compose up -d`.
  For an installer-managed instance, rerun the installer with the desired
  `--version` and the same `--domain`; this updates the local machine too.
  Migrations are forward-only: selecting an older binary is not a database
  rollback. Other machines keep their installed build until reinstalled.

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

grund contacts no service you have not configured: no telemetry, no update
check. With `GRUND_ACCOUNT_EVENT_URL` and `GRUND_ACCOUNT_EVENT_TOKEN`,
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

- Nouns: `login`, `logout`, `whoami`, `orgs`, `apps`, `volumes`,
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
  A release's dry run resolves its image and checks the proposed change
  without writing it.
  `apps deploy --dry-run` also previews a missing app without creating it
  and reports structured desired-versus-live changes and the observed
  `expectedVersion`; `apps deploy shop --expected-version N` refuses a
  stale single-app release. The API exposes the same through
  `AppService.PreviewDeploy`, `GetApp.version` and
  `DeployRequest.expected_version`.
- `GRUND_INSTANCE` and `GRUND_TOKEN` (a personal access token) for CI and
  agents; otherwise `grund login` writes `~/.config/grund/credentials.yaml`
  (mode 0600; a file others can read is refused). `--org`/`GRUND_ORG`, else
  `grund orgs use`, else the token's organisation, else your only one.
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

Domains and an app's Settings show the domain record, edge check, certificate
request, challenge result, issued certificate and observed HTTPS separately,
with check and retry times. `grund domains list` shows the same steps.
Owners and admins can add, verify, bind, move, unbind and check domains from
the app. Setup checks continue automatically; **Check now** queues a fresh
check without bypassing a certificate authority's retry deadline.

For organisation app addresses, verify a parent such as `example.com`, then
choose **Use for app addresses** on Domains. Point `*.example.com` at the
configured edge shown there. Existing and future apps get
`<app>.example.com`; an owner or admin can choose another single-label name
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
  `Scale`, `ConfigureApp` and `SetSecret`. `full` may also delete apps and
  manage machines, custom domains, members, invitations and registry
  logins. Neither reaches the account, sessions, tokens, or creating,
  renaming and deleting organisations: those get `permission_denied`.
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
