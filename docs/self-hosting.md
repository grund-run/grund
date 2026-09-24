# Self-hosting grund with compose

Status: grund is in development. This describes what `compose.yaml` does
today, and says plainly what it does not do.

## Start

```bash
git clone https://git.kjuulh.io/grund/grund.git && cd grund
docker compose up -d
```

Open http://localhost:8080. The first start builds the image from the
checkout, which takes a few minutes. Later starts rebuild only what changed.
To run a published build instead, set
`GRUND_IMAGE=git.kjuulh.io/grund/grund:main-<commit>` and
`GRUND_PULL_POLICY=missing` in `.env`.

## What you get

| Service | What it does | Reachable at |
|---|---|---|
| `init` | Generates the instance secret key and the database password into the `grund-data` volume on first start, then exits. It never overwrites them | nowhere |
| `postgres` | PostgreSQL 18, where everything grund knows is kept | the compose network only |
| `nats` | Wakes background work (mail) as soon as it is queued. grund works without it by polling every 5 s | the compose network only |
| `mailpit` | Catches every mail grund sends, so sign-up works without a mail server. **It delivers nothing** | http://localhost:8025 |
| `grund` | The dashboard and API. Runs database migrations on every start | http://localhost:8080 (bound to 127.0.0.1) |

- **Health.** Every service has a health check, and grund starts only once
  PostgreSQL, NATS and Mailpit are healthy and `init` has finished.
  `docker compose ps` shows the state; `curl localhost:8080/health/ready`
  shows what grund itself depends on and which build is running.
- **Data.** Two named volumes: `grund-postgres` (the database) and
  `grund-data` (the secret key and the database password). They survive
  `docker compose down`; `docker compose down -v` deletes them, and with them
  every account.
- **Restarts.** Every long-running service restarts unless stopped.
- **Hardening.** grund runs as a non-root user in a read-only container with
  no capabilities. The database and NATS are not published outside the
  compose network.

## What compose deliberately does not do

- **TLS.** grund serves plain http on 127.0.0.1:8080. Browsers only keep a
  session over plain http on `localhost`, and grund refuses to start with a
  plain-http `GRUND_PUBLIC_URL` on any other name. To serve other machines,
  put a TLS-terminating proxy (Caddy, Traefik, nginx) in front, set
  `GRUND_PUBLIC_URL=https://your.name`, and set
  `GRUND_TRUSTED_PROXY_HOPS=1` so sign-in limits see the real client address.
- **Backups.** Nothing backs up the volumes. If the disk dies, every account
  goes with it. Back up both volumes: `grund-postgres` with `pg_dump` (or a
  volume snapshot while stopped), and `grund-data`, without which the
  database password and the instance key are lost. Until grund manages this
  itself, restoring is your job, and you should try it once before relying
  on it.
- **Real mail.** Mailpit catches everything. For real users, set
  `GRUND_SMTP_URL` (and `GRUND_MAIL_FROM`) in `.env` to your provider, e.g.
  `smtp://user:password@smtp.example.com:587?tls=required`.
- **Updates.** Nothing updates grund on its own. `git pull` and
  `docker compose up -d` rebuild and restart it (or change `GRUND_IMAGE`).
  Migrations run on start and are forward-only, so going back to an older
  build after a migration is not supported.
- **More than one machine.** This is one machine. If it goes down, grund
  goes down with it.

## Settings

Every setting, with its default and what it does, is in `.env.example`.
Copy it to `.env`, uncomment what you change, and `docker compose up -d`.
Two settings go together: when you change `GRUND_PORT`, also change
`GRUND_PUBLIC_URL`, because links in mail and the check on where forms were
posted from use it.

## Secrets

Nothing secret is committed or typed in. `grund init` writes
`secret.key` (owner-only) and `postgres-password` into `grund-data` on the
first start. The password file is readable by the other containers that
mount the volume, because the PostgreSQL image reads it as its own user;
the volume is mounted only into `init`, `postgres` and `grund`.

To use an existing secret instead, set `GRUND_SECRET_KEY` in `.env` (64
hex characters, `openssl rand -hex 32`). grund refuses to start with a
value copied from an example, a key that is not 64 hex characters, or no
key at all, unless `GRUND_DEV_MODE=true`.
