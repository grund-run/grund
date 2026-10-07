---
name: grund
description: Deploy and operate apps on a grund instance with the grund CLI instead of the dashboard - deploy from grund.yaml or an image, read status as JSON, change one setting (image, env, ports, copies, placement), roll back, delete; add machines, custom domains, members, tokens and registry logins. Use when the user mentions grund, grund.yaml, a grund instance or grund.sh, or asks to deploy, scale, roll back or inspect an app there.
---

# grund CLI

`grund` drives a grund instance over the same API the dashboard uses. Every
command takes `--json` and prints one JSON document on stdout; a failure
prints `{"error": {"code", "message", "hint", "field", "reason"}}` on
stderr and exits with the code's status. Always pass `--json` and read
fields, not text.

## Before anything

1. `grund whoami --json`. Exit 3 (`not_signed_in`/`unauthenticated`): ask
   the user to run `grund login <instance>` in their terminal (it opens the
   browser), or to set `GRUND_INSTANCE` and `GRUND_TOKEN`. Never ask for a
   token in chat and never put one on a command line.
2. Exit 2 with `organisation_required`: pass `--org <slug>` (the error lists
   them), or `grund orgs use <slug>` once.

## Deploy

```sh
grund apps deploy -f grund.yaml --dry-run --json    # checks the file, resolves the image, shows changes
grund apps deploy -f grund.yaml --wait --json       # every app in the file; makes missing apps
grund apps deploy web --image nginx:1.27 --port http=80 --public http --wait --json
```

`--wait` returns when the rollout is live (exit 0) or failed (exit 9,
`rollout_failed`; the release rolled back on its own unless auto-rollback
is off). The file's schema: `grund schema grund.yaml`.

## Read state

- `grund apps status APP --json`: `health` is one of `no_release`,
  `rolling_out`, `live`, `degraded`, `failed`, `halted`; `copiesReady` of
  `copiesWanted`; `waiting[]` says why a copy has no machine.
- `grund apps get APP --json`: every copy, its machine and what it reports.
- `grund apps history APP --json`: releases, newest first, with outcome.

## Change one thing

Each makes a new release from the newest one, as the dashboard's Settings
does (copies, placement and auto-rollback are settings, no release):

```sh
grund apps set web image ghcr.io/acme/web:2.1 --wait --json
grund apps set web env LOG_LEVEL=debug --unset OLD --json
printf %s "$VALUE" | grund apps secrets set web db-url --json
grund apps set web secret-env DATABASE_URL=db-url --json
grund apps set web copies 3 --json
grund apps set web placement --label zone=eu --spread-by zone --json
```

Add `--dry-run` to any of them first to see `changes[]` (JSON pointers,
before and after) without changing anything.

## Undo and remove

- `grund apps history web --json`, then `grund apps rollback web <n> --wait --json`.
- Destructive commands (`apps delete`, `machines remove`, `domains remove`,
  `members remove`, `tokens revoke`, …) need `--yes` without a terminal.
  Confirm with the user first; prefer `--dry-run` to show what happens.

## Machines, domains, people

- `grund machines add NAME --json`: `installCommand` is what the user runs
  as root on the new machine. `grund machines out-of-service NAME` before
  `grund machines remove NAME --yes`.
- `grund domains add shop.example.com --json` gives the TXT record; after
  the user makes it and a CNAME to the app's address, `grund domains verify`
  then `grund domains bind shop.example.com web`.
- `grund members invite ana@example.com --role admin`.

## Tokens for CI and other agents

`grund tokens create --name ci --scope deploy --json` prints `secret`
once; give it to CI as `GRUND_TOKEN`. Scope `deploy` creates, deploys and
changes apps; `full` does everything its maker's role allows in the
organisation (delete apps, machines, domains, members) but never tokens or
the account. Making tokens needs `grund login`, not a token.

## When something fails

Act on `error.code`: `not_found` (check the name with a list command),
`conflict` (`reason` says which: `name_taken`, `app_limit`, `halted`, …),
`invalid` (`field` names the flag or grund.yaml path), `permission_denied`
(the role, or a deploy token on something else), `unavailable` (retry
later). `grund describe --json` has every command, argument, output schema
and error code; `grund schema output <command>` one output's schema.
