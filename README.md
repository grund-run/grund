# grund

grund takes an app from a bare machine to live for its users, on hardware
you own. This repository is grund itself: the server (the dashboard, the API
and the work behind them), and later the orchestrator and the agent that
runs on each machine.

**In development. Not yet available.** What exists today is the skeleton and
the first feature, accounts: sign up, confirm your email, sign in and out,
reset a forgotten password, and see and end your sessions. Each account
comes with its own organisation, which everything grund manages later will
belong to. Nothing here deploys an app yet.

## What is open, and what is paid

grund is open source. The self-hosted edition is free, and it is the real
product: deploying, releases, data, domains, and a whole team signing in
with passwords, with nothing held back to make the paid plans look better.
A few features on top are commercial. They are in `ee/`, where the source
can be read. They are not in any release yet.

| | Where | License |
|---|---|---|
| Everything grund does, except the features below | everywhere but `ee/` | AGPL-3.0-only |
| The API contract and clients | `proto/`, `crates/grund-proto` | Apache-2.0 |
| Sign in with GitHub or Google (planned for the Homelab plan) | `ee/` | all rights reserved for now |
| Single sign-on with your own provider, audit log (planned for Business) | `ee/` | all rights reserved for now *(not built)* |

Where things stand, plainly: nothing is for sale yet. The commercial
features are published so you can read them, but they are not licensed for
use and no official build or image contains them. Commercial terms come
when grund has a company to offer them, and the pricing on grund.sh is
planned pricing. [LICENSE](LICENSE) says which license covers what, and
what the AGPL asks of you. Contributions are welcome under Apache-2.0 with
a sign-off ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Self-hosting

```bash
git clone https://git.kjuulh.io/grund/grund.git && cd grund
docker compose up -d     # builds this checkout; then http://localhost:8080
```

That runs grund with PostgreSQL, NATS (wake-ups for background work) and
Mailpit, which catches every mail at http://localhost:8025 so sign-up works
without a mail server. Secrets are generated on first start into the
`grund-data` volume and kept. grund runs non-root in a read-only container,
and runs its migrations on every start. The first build takes a few
minutes. To run a published image instead, set `GRUND_IMAGE` and
`GRUND_PULL_POLICY=missing` in `.env`. Every setting is documented in
[.env.example](.env.example).

What compose deliberately does not do:

- **TLS.** grund serves plain http on 127.0.0.1:8080, and refuses a plain
  http `GRUND_PUBLIC_URL` anywhere but localhost. To serve other machines,
  put a TLS proxy (Caddy, Traefik, nginx) in front, set
  `GRUND_PUBLIC_URL=https://your.name` and `GRUND_TRUSTED_PROXY_HOPS=1`.
- **Backups.** Nothing backs up the `grund-postgres` and `grund-data`
  volumes. `docker compose down -v` deletes them and every account with
  them. Back up both, and try a restore once.
- **Real mail.** Mailpit delivers nothing. Set `GRUND_SMTP_URL` and
  `GRUND_MAIL_FROM` for real users.
- **Updates and more than one machine.** `git pull` and `docker compose up
  -d` update grund. Migrations are forward-only. One machine is one machine.

## The binary

One binary, `grund`, with subcommands: `serve` (the control plane),
`migrate`, `init` (generate the instance's secrets) and `probe` (a health
check for the scratch image). `grund serve --help` lists every setting with
its environment variable.

- `GET /health/live` answers `{"status":"ok"}` and checks nothing.
- `GET /health/ready` answers 200 or 503 from the last dependency checks,
  with the build `revision` and each check's state.
- Pages: `/signup`, `/verify`, `/login`, `/reset`, `/`, `/settings/sessions`,
  and `/style-guide`, which renders every component with example data.
- The API is ConnectRPC (`proto/`, generated at build time; Connect, gRPC and
  gRPC-Web on the same routes). `grund.account.v1.AccountService` has
  `GetViewer`, `ListSessions` and `RevokeSession`. Today it takes the
  dashboard's session cookie, from this origin only.

```bash
curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
  http://localhost:8080/grund.account.v1.AccountService/GetViewer
# {"code":"unauthenticated","message":"sign in first"}
```

## Layout

```
crates/grund/          the binary; tests/accepttest/ (the contract over the wire)
crates/grund-server/   the control plane: config, services, pages, API, background work
crates/grund-store/    PostgreSQL: migrations, event-sourced write paths, read models
crates/grund-domain/   aggregates, events and pure decisions; no I/O
crates/grund-proto/    the API contract, generated from proto/ (needs protoc)
ee/grund-ee/           the commercial features, plugged in through one Extension seam (--features ee)
tools/comment-policy/  the CI check that Rust comments are docs on public items only
compose.yaml           the self-hosted instance
compose.dev.yaml       development and test infrastructure on fixed local ports
Dockerfile             builds the image from source (compose); Dockerfile.prebuilt packages CI's binary
check.sh               the static binary in a read-only scratch container, against the accepttests
```

The design documents, threat model and agent notes live in
[grund/grund-docs](https://git.kjuulh.io/grund/grund-docs) (private).

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

Every push to `main` is tested, packaged into one image tagged
`main-<commit>` at `git.kjuulh.io/grund/grund`, and rolled to the dev
environment. There is no `latest` tag. Production is a deliberate promotion,
never CI.
