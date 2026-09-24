# grund

grund takes an app from a bare machine to live for its users, on hardware
you own. This repository is grund itself: the server (the dashboard, the API
and the work behind them), and later the orchestrator, the agent that runs on
each machine, and the dashboard's design.

**In development. Not yet available.** What exists today is the skeleton and
the first feature, accounts: sign up, confirm your email, sign in and out,
reset a forgotten password, and see and end your sessions. Each account
comes with its own organisation, which everything grund manages later will
belong to. Nothing here deploys an app yet.

License: to be decided. Until a license is chosen, no license is granted;
see [docs/design/licensing.md](docs/design/licensing.md) for the options.

## Run it

The whole instance on one machine:

```bash
docker compose up        # builds this checkout; http://localhost:8080
```

That starts grund with PostgreSQL, NATS and Mailpit (which catches mail
at http://localhost:8025). Secrets are generated on first start. What
compose gives you, what it does not (TLS, backups) and how to change it is
in [docs/self-hosting.md](docs/self-hosting.md). Every setting is in
[.env.example](.env.example).

For development:

```bash
docker compose -f compose.dev.yaml up -d      # PostgreSQL, NATS, Mailpit on fixed local ports
cargo run -p grund -- serve --database-url postgres://grund:grund@127.0.0.1:55410/grund --dev-mode true
cargo run -p grund -- serve --help            # every knob, with its env var
```

## The binary

One binary, `grund`, with subcommands:

| Command | What |
|---|---|
| `grund serve` | The control plane: pages, API, background work. Runs migrations on start |
| `grund migrate` | Apply database migrations and exit |
| `grund init` | Generate the instance secret key and database password, keeping existing ones |
| `grund probe` | Exit 0 when an instance's readiness answers 200 (the image has no shell) |

Endpoints every instance serves, unauthenticated:

- `GET /health/live`: `{"status":"ok"}`. Checks nothing, so no dependency
  outage restarts grund.
- `GET /health/ready`: 200 or 503 from the last dependency checks (nostatus,
  every `GRUND_HEALTH_INTERVAL`), with the build `revision`, version,
  uptime and each check's name, severity and state (`postgres` critical,
  `nats` major, `mail` minor). Never error text.

Pages (server-rendered; the design is [docs/design/auth.md](docs/design/auth.md),
the look is [docs/design/style-guide.md](docs/design/style-guide.md)):

| Page | What |
|---|---|
| `/signup`, `/signup/sent` | Create an account (username, email, password) and its organisation |
| `/verify?token=` | Confirm the email address (the link in the mail) |
| `/login`, `POST /logout` | Sign in by username or email; sign out |
| `/reset`, `/reset/sent`, `/reset/confirm?token=` | Mail a reset link; choose a new password, which signs out every device |
| `/` | The signed-in overview (a placeholder until apps exist) |
| `/settings/sessions` | Every device signed in, with sign-out for each or all others |
| `/style-guide`, `/licenses` | Every component with example data; the fonts' licenses |

## Layout

```
crates/grund/          the binary: subcommands, tracing; tests/accepttest/ (the contract over the wire)
crates/grund-server/   the control plane: config, State and services, pages, API, notmad components
crates/grund-store/    PostgreSQL: migrations, event-sourced write paths, read models, plain tables
crates/grund-domain/   aggregates, events and pure decisions; no I/O, no clock
tools/comment-policy/  the CI check that Rust comments are docs on public items only
compose.yaml           the self-hosted instance (grund, PostgreSQL, NATS, Mailpit)
compose.dev.yaml       development and test infrastructure on fixed local ports
Dockerfile             builds the image from source (compose)
Dockerfile.prebuilt    packages CI's tested binary (CI)
check.sh               the static binary in a read-only scratch container, against the accepttests
docs/                  self-hosting, design documents
```

### Why this layout

The choice was one binary with subcommands versus a binary per role, and
how finely to split crates. grund is **one binary** because a self-hoster
installs one thing and CI signs and ships one artifact. The agent that runs
on each machine becomes `grund agent`, as k3s does it.

The crates are split along the lines that will carry weight when the
orchestrator and agent arrive, and no finer:

- **`grund-domain` is its own crate** because the orchestrator and the agent
  will share its types (an app, a release, a machine) and must not link a web
  server or a database driver to get them. It has no I/O, so its tests are
  pure.
- **`grund-store` is its own crate** because SQL is the part most worth
  testing against a real database in isolation, and because a second
  process (a migration job, an audit binary) needs it without the HTTP
  stack.
- **The API contract** gets its own crate, `grund-proto`, when the first
  ConnectRPC service lands, so the future CLI and agent generate clients
  without pulling in the server. *(Not built yet.)*
- **Pages, API and services stay modules of `grund-server`**, not crates.
  They share one `State` and reach each other through extension traits
  (`state.accounts()`). Splitting them now would push `State` into yet another
  crate and put every service behind a generic, to protect a boundary nothing
  crosses yet. When a second consumer appears (the orchestrator calling the
  same services), that module moves out whole.

## Verify

```bash
docker compose -f compose.dev.yaml up -d
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -q -p comment-policy       # Rust comments are docs on public items, nothing else
cargo test --workspace --locked      # unit, store (real PostgreSQL) and accepttests against spawned binaries
./check.sh                           # the above, plus the accepttests against the scratch image
```

The accepttests (`crates/grund/tests/accepttest/`) spawn the real binary
against real PostgreSQL, NATS and Mailpit. Point them at any running
instance instead:

```bash
GRUND_ACCEPT_URL=http://127.0.0.1:8080 GRUND_ACCEPT_MAILPIT_URL=http://127.0.0.1:8025 \
  cargo test -p grund --test tests
```

## Releases

Every push to `main` is tested, packaged into one image tagged
`main-<commit>` at `git.kjuulh.io/grund/grund`, and rolled to the dev
environment. There is no `latest` tag. Production is a deliberate promotion
through forest, never CI.
