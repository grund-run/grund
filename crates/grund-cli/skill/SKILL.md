---
name: grund
description: Deploy and operate apps on a grund instance with the grund CLI instead of the dashboard - deploy from grund.yaml or an image, read status, logs and measured CPU/memory as JSON, change one setting (image, env, ports, copies, placement), roll back, delete; add machines, custom domains, members, tokens and registry logins. Use when the user mentions grund, grund.yaml, a grund instance or grund.sh, or asks to deploy, scale, roll back or inspect an app there.
---

# grund CLI

`grund` drives a grund instance over the same API the dashboard uses. Every
command takes `--json` and prints one JSON document on stdout, except
`app logs --follow`, which emits one response per line until interrupted.
A failure prints `{"error": {"code", "message", "hint", "field", "reason"}}`
on stderr and exits with the code's status. Always pass `--json` and read
fields, not text.

## Before anything

1. `grund auth status --json`. Exit 3 (`not_signed_in`/`unauthenticated`): ask
   the user to run `grund auth login <instance>` in their terminal (it opens the
   browser), or to set `GRUND_INSTANCE` and `GRUND_TOKEN`. Never ask for a
   token in chat and never put one on a command line.
2. Exit 2 with `organisation_required`: pass `--org <slug>` (the error lists
   them), or `grund org use <slug>` once.
3. Several instances or organisations: `grund context list --json` shows the
   user's contexts; pass `--context <name>` per command rather than switching
   theirs with `grund context use`.

## Deploy

```sh
grund app deploy -f grund.yaml --dry-run --json    # checks the file, resolves the image, shows changes
grund app deploy -f grund.yaml --wait --json       # every app in the file; makes missing apps
grund app deploy web --image nginx:1.27 --port http=80 --public http --wait --json
```

`--wait` returns when the rollout is live (exit 0) or failed (exit 9,
`rollout_failed`; the release rolled back on its own unless auto-rollback
is off). The file's schema: `grund schema grund.yaml`.

## Read state

- `grund app status APP --json`: `health` is one of `no_release`,
  `rolling_out`, `live`, `degraded`, `failed`, `halted`; `copiesReady` of
  `copiesWanted`; `waiting[]` says why a copy has no machine.
- `grund app show APP --json`: every copy, its machine and what it reports.
- `grund app history APP --json`: releases, newest first, with outcome.

## Logs and measurements

```sh
grund app logs web --since 1h --limit 200 --json
grund app logs web --follow --stream stderr --json
grund app metrics web --range day --json
```

Logs are ordered by when received, not by their observed timestamps, so a
late upload can have an older observed time. Observed times are collection
times, not application emission times. Filter with `--instance-id ID`,
`--release N`, `--since TIME`, `--until TIME`, `--search TEXT` (literal,
case-insensitive, at most 200 bytes), and `--stream stdout|stderr|combined`.
`combined` is older output without separate streams. Times are RFC3339 or
durations ago, such as `30s`, `15m`, `1h30m`, `1d` or `1w`.
`--instance URL` still chooses the server; it is not an app instance filter.

One read returns at most `--limit` records (default 200, maximum 1000),
oldest received first. `--follow` drains every retained matching page before
waiting for more; its limit is per page, not a total. Ctrl-C stops it.
JSON follow emits one `ListAppLogsResponse` per line; YAML follow emits
separate documents. The MCP tool reads one bounded page, without follow.
Check `truncated` and `droppedRecords`: the latter counts this app's
retained-history evictions, not collection or delivery losses. A zero
count does not promise complete output. App output may contain sensitive
data; do not paste it into chat without reviewing it.

Metrics accept `--range hour|day|week` (default hour), `--instance-id ID`
and `--release N`. `points` contain measured averages, maximum memory,
sample counts and CPU/memory reservations. CPU is millicores (1000 = one
vCPU); memory is bytes from `memory.current`, including cache, not process
RSS. Missing values and absent buckets are unknown, never zero; do not
interpolate gaps. Responses include their time buckets and retention bounds.

## Change one thing

Each makes a new release from the newest one, as the dashboard's Settings
does (copies, placement and auto-rollback are settings, no release):

```sh
grund app set web image ghcr.io/acme/web:2.1 --wait --json
grund app set web env LOG_LEVEL=debug --unset OLD --json
printf %s "$VALUE" | grund app secret set web db-url --json
grund app set web secret-env DATABASE_URL=db-url --json
grund app set web copies 3 --json
grund app set web placement --label zone=eu --spread-by zone --json
```

Add `--dry-run` to any of them first to see `changes[]` (JSON pointers,
before and after) without changing anything.

## Undo and remove

- `grund app history web --json`, then `grund app rollback web <n> --wait --json`.
- Destructive commands (`app delete`, `machine remove`, `domain remove`,
  `member remove`, `auth token revoke`, …) need `--yes` without a terminal.
  Confirm with the user first; prefer `--dry-run` to show what happens.

## Machines, domains, people

- `grund machine add NAME --json`: `installCommand` is what the user runs
  as root on the new machine. `grund machine drain NAME` before
  `grund machine remove NAME --yes`.
- `grund domain add shop.example.com --json` gives the TXT record; after
  the user makes it and a CNAME to the app's address, `grund domain verify`
  then `grund domain bind shop.example.com web`.
- `grund member invite ana@example.com --role admin`.

## Tokens for CI and other agents

`grund auth token create --name ci --scope deploy --apps web --json` prints
`secret` once; give it to CI as `GRUND_TOKEN`. `--apps` accepts up to 64
distinct app names (repeat the flag or comma-separate names), restricting
the token to those apps in its own organisation. It can get/list only their
apps and bound domains, deploy and change those apps, but not write domains
or use VolumeService. Leaving out `--apps` preserves organisation-wide
deploy access for existing workflows. `full` does everything its maker's
role allows in the organisation (delete apps, machines, domains, members)
but never tokens or the account; it cannot be combined with `--apps`.
Making tokens needs `grund auth login`, not a token.

## When something fails

Act on `error.code`: `not_found` (check the name with a list command),
`conflict` (`reason` says which: `name_taken`, `app_limit`, `halted`, …),
`invalid` (`field` names the flag or grund.yaml path), `permission_denied`
(the role, or a deploy token on something else), `unavailable` (retry
later). `grund describe --json` has every command, argument, output schema
and error code; `grund schema output <command>` one output's schema.
