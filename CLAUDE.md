# CLAUDE.md: grund/grund

Operational notes for agents. What grund is and how to run it is in
README.md; what compose promises is in docs/self-hosting.md; designs are in
docs/design/.

## This repository is public

`grund/grund` is public on git.kjuulh.io and push-mirrored hourly to
github.com/grund-run/grund. Everything in it is public from the first push:

- no secrets, tokens or real keys. Test keys are generated inside tests at
  run time, never committed;
- no internal IPs, cluster internals or gateway details. Those live in the
  private repos (`grund/terraform`, `kjuulh/clank-homelab`) or forest config;
- the licensing is decided (Kasper, 2026-09-24; LICENSE and
  docs/design/licensing.md): AGPL-3.0-only for the core, Apache-2.0 for
  `proto/` and `crates/grund-proto`, the grund Commercial License for
  `ee/`. New code goes on the right side of that line. A commercial feature
  lives in `ee/` and plugs in through `Extension`. Moving code out of `ee/`
  publishes it under the AGPL for good, and moving code into `ee/` takes a
  feature away from the open edition. Ask Kasper before moving code either
  way.

## House rules

The grund engineering skills (`/grund:principles` and the rest) are the
rules. Where this repository deviates, the commit body says why.

## Comments

In Rust, **the only comments are doc comments on public items** (Kasper,
2026-09-24). No `//` or `/* */` anywhere, and no `///`/`//!` on private
items, tests included. `tools/comment-policy` enforces it in CI and in
`cargo test`; `cargo run -q -p comment-policy` lists what it refuses. Say
the why in a name, in the public item's docs, in a commit body or in
`docs/`. This overrides the skills' "comments explain why" for this
repository. Config files (YAML, CUE, SQL, Dockerfiles, shell) keep their
comments: the rule is about Rust.

## Layout

- `crates/grund` is the binary and the accepttests. Keep `main.rs` thin: it
  parses the CLI and calls into `grund-server`.
- `crates/grund-server/src/lib.rs` wires `serve`: config, tracing, pool,
  migrations, NATS, State, then notmad components **in drain order** (HTTP
  first, outbox last). Add a component in the right place, not at the end.
- `ee/grund-ee` holds the commercial features (social sign-in today). It
  plugs into the core only through `grund_server::extension::Extension`,
  and every feature asks `Entitlements` before acting. Core code never
  imports from `ee/`. Official builds (the default features) are the core
  alone; `--features ee` adds `ee/`, and CI builds and tests it that way so
  it does not rot. `ee/LICENSE` is an interim all-rights-reserved notice
  until grund has a company; the full commercial license waits for that
  (docs/design/licensing.md).
- `crates/grund-domain` has no I/O. If a change needs a clock or a query
  there, it belongs in a service.
- `crates/grund-store/migrations/` is forward-only. Never edit an applied
  migration; the checksum breaks every running instance on restart.

## Verify

```bash
docker compose -f compose.dev.yaml up -d
cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings \
  && cargo test --workspace --locked
./check.sh    # needs docker; builds in rust:1.98-alpine exactly as CI does
```

- Behaviour over the wire goes in `crates/grund/tests/accepttest/` as a
  given/when/then flow (the forest-server and grund/website shape). Add a
  step to `fixtures/{given,when,then}.rs` when a flow needs one. Do not add
  shell assertion scripts.
- Why the accepttests use a raw HTTP/1.1 client (`fixtures/client.rs`):
  general clients normalise paths and hide what a response carried, and
  these tests assert the bytes on the wire (the grund/website harness).
- Each spawned instance gets its own database (`grund_accept_<random>`),
  created from `GRUND_ACCEPT_DATABASE_URL` and dropped when its test ends,
  because instances drain the outbox: sharing one database lets a finished
  test's server take another test's mail with it. Account names are random
  too, so a run needs no cleanup (skills D-22).
- The store's `#[sqlx::test]`s need `DATABASE_URL`; `.cargo/config.toml`
  points it at compose.dev.yaml's PostgreSQL unless the environment sets one.
- Mail in tests is read back from Mailpit's API (`fixtures/mail.rs`). When a
  flow sends a second link (sign-in resends verification), wait for it and
  follow the newest: the older link is already invalid.
- `compose.dev.yaml` keeps PostgreSQL on tmpfs: `docker compose -f
  compose.dev.yaml down` wipes it.
- The revision in `/health/ready` comes from `CI_COMMIT_SHA` (or
  `GRUND_REVISION`) at build time. Local builds say `unknown`.

## Deploy

- Push to main. `ci.yaml` gates, `images.yaml` builds the static binary, runs
  the accepttests against that exact file and publishes
  `git.kjuulh.io/grund/grund:main-<sha>`, and `rollout.yaml` stages a forest
  release (project `kjuulh/grund`). The project's dev trigger rolls it to dev.
- **Never promote to prod from here** (`forest release release/approve`
  against prod). That is Kasper's call.
- `rollout.yaml` is generated. After changing the `woodpecker-forest` block in
  `forest.cue`, run `forest run install` and commit what it writes.
- The forest instance is forest.kjuulh.io; the CLI talks to
  `https://api.forest.kjuulh.io`. Pass `--context kjuulh-prod` on every
  command: the default context on this machine is another instance.
- `forest validate` reports "Validated 0 component(s)". To check the config
  against kubernetes-app's `#Spec`, unify `config` with each env's `config`
  and `cue vet -c` it against the component's `forest.component.cue`.
- Prove what is deployed from the live origin:
  `curl -s https://dev.app.grund.sh/health/ready` must report the commit as
  `revision`, sampled a few times (replicas can disagree mid-rollout).

## Live

- **dev**: namespace `dev` on clank-dev, host `dev.app.grund.sh`, with its
  PostgreSQL as CNPG cluster `grund-db` (backups on). Verified 2026-09-24:
  `/health/ready` through `kubectl -n dev port-forward deploy/grund`
  reported revision 202bd223b726 on three samples, image
  `git.kjuulh.io/grund/grund:main-202bd223b726…`. The public name does not
  resolve until the DNS and gateway commits in grund/terraform and
  kjuulh/clank-homelab are applied. Dev runs with GRUND_DEV_MODE (a
  throwaway key) and no SMTP until the `grund-secrets` Secret exists
  (forest.cue).
- **prod**: not deployed. Promotion is Kasper's.
- **compose**: verified 2026-09-24 from a clean clone of 202bd22 (no cached
  image, no volumes). `docker compose up -d --wait` brought every service
  healthy in 2 min 18 s, with a warm cargo cache on this machine. Sign-up,
  the mailed link through Mailpit, verification, sign-in, the dashboard and
  GetViewer all worked over HTTP. The published image ran the same way,
  with GRUND_IMAGE and GRUND_PULL_POLICY=missing, reporting its revision.

## Gotchas

- `compose.yaml` builds `grund:local` from source unless `GRUND_IMAGE` is set.
  The first build takes a few minutes.
- On this development machine another project's Mailpit holds port 8025; use
  `GRUND_MAILPIT_PORT=58025 docker compose up` here.
- `check.sh` builds as root inside the container and chowns `target/musl`
  back. If you interrupt it, `target/musl` may be left owned by root.
