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
- no license. The choice is Kasper's (docs/design/licensing.md). Do not add a
  LICENSE file, name a license in docs, or set `license` in Cargo.toml.

## House rules

The grund engineering skills (`/grund:principles` and the rest) are the
rules. Where this repository deviates, the commit body says why.

## Layout

- `crates/grund` is the binary and the accepttests. Keep `main.rs` thin: it
  parses the CLI and calls into `grund-server`.
- `crates/grund-server/src/lib.rs` wires `serve`: config, tracing, pool,
  migrations, NATS, State, then notmad components **in drain order** (HTTP
  first, outbox last). Add a component in the right place, not at the end.
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
- Tests use random account names and never clean up, so the dev database
  can be shared by every run (skills D-22).
- `compose.dev.yaml` keeps PostgreSQL on tmpfs: `docker compose -f
  compose.dev.yaml down` wipes it.
- The revision in `/health/ready` comes from `CI_COMMIT_SHA` (or
  `GRUND_REVISION`) at build time. Local builds say `unknown`.

## Gotchas

- `compose.yaml` builds `grund:local` from source unless `GRUND_IMAGE` is set.
  The first build takes a few minutes.
- On this development machine another project's Mailpit holds port 8025; use
  `GRUND_MAILPIT_PORT=58025 docker compose up` here.
- `check.sh` builds as root inside the container and chowns `target/musl`
  back. If you interrupt it, `target/musl` may be left owned by root.
