# Authentication

Status: accepted design. Built: §1–§5, §7, §8, §9 and §12, including
social sign-in behind the license gate. The API tokens (§6) are marked
where they are not built. Decisions that belong to Kasper are marked *Decision for
Kasper* and are not settled until he says so. 
## What exists today

A server that starts, migrates and reports its health (`grund-server`), a
store crate with no tables yet (`grund-store`), a pure domain crate
(`grund-domain`), and a compose file that runs a whole instance. There is
no account, session or page yet. Prior art read for this design, and what
it does that we do not repeat:

- forest/forage (users, OAuth, sessions): no dummy hash, so an unknown user
  answers faster than a wrong password. It links an OAuth identity to any
  account whose address matches, verified or not. Session ids are stored in
  plaintext, there is no CSRF token on the login form, no PKCE or nonce,
  and no rate limit on sign-in.
- tiny-auth (Ed25519 JWTs): the shape we keep for tokens. It uses a dummy
  hash for unknown users, stores only digests of opaque secrets, rotates the
  CSRF token after login and keeps a strict CSP. We keep all of that.

## The unifying concept

**The browser holds only opaque random strings; the server keeps only
their digests, and every decision that could reveal whether an account
exists is made where the caller cannot see or time it.** Sessions, email
links and CSRF tokens are random values whose SHA-256 (or HMAC) is what
PostgreSQL stores. Sign-in does the same work whether or not the account
exists. A password-reset request records only "someone asked" and returns;
whether an account exists is decided later, by a background worker, after
the response has left.

## 1. Accounts, organisations and what is event-sourced

An **account** is a person: a unique username, one email address, and a
password and/or linked social identities. Every account belongs to at
least one **organisation**. Signing up creates a personal organisation
whose slug is the username, and makes the account its `owner`. Everything
grund will manage later (apps, machines, releases) hangs off an
organisation id, never off an account.

### Decision

- **Event-sourced (mire), because their history is the product:** the
  account (`grund-account`) and the organisation (`grund-organisation`)
  streams. An account's security history (registered, email verified,
  password changed or reset, identity linked) is what an audit log (a
  planned Business feature) and support will read. An organisation's
  membership history is the same kind of record.
- Both aggregates implement `mire::Snapshot` from day one (skills D-31),
  every 100 events. Neither stream is bounded: password resets and
  membership changes accumulate for the life of the account.
- **Events carry no personal data and no credentials.** They hold ids,
  timestamps, the username and organisation slug (public handles, like a
  GitHub login), and a SHA-256 digest of the verified email address, never
  the address. Email addresses, password hashes and provider subject ids
  live in plain tables that are the truth for that data and can be erased.
  The log is append-only and replayed forever; an address in it could never
  be removed.
- **Read models in the same transaction:** `grund_accounts`,
  `grund_organisations` and `grund_memberships` are projections, written
  by one `apply_*` function per aggregate inside the transaction that
  records the event, and guarded by `stream_version`. A `ProjectionRunner`
  calls the same functions for catch-up and rebuilds.
- **Plain tables, because current state is all that matters and rows are
  deleted:** passwords, emails, identities, sessions, email-link tokens,
  rate-limit counters, social sign-in flows and the outbox. A session's
  history is not worth replaying, and a counter's never is.
- **The username is unique through the read model's unique index**, which
  is written in the same transaction as the `Registered` event, so a
  second writer fails its commit. The event log stays the truth; the index
  only refuses a conflicting write. The email is unique through
  `grund_account_emails`.

Grammar:

- **Username** (and personal organisation slug): 3–32 characters of `a–z`
  and `0–9`, with single hyphens between them. It is compared and stored in
  lowercase, and case-insensitive on input. Names that would read as grund
  (`admin`, `root`, `grund`, `api`, `app`, `www`, `support`, `security`,
  `settings`, `login` and similar) are reserved.
- **Email**: trimmed, one `@`, at most 254 bytes, compared case-insensitively
  (lowercased whole). No plus-address or dot folding: that is the mail
  provider's business.

App addresses are planned as `<app>-<account>.grund.run` (grund/website
`design/app-domains.md`). With hyphens allowed in both parts, `a-b-c` could
split two ways, so the address is **allocated as one unique label, the way
Vercel does it**, and never parsed back into app and account. The first
claimant gets the plain label, and a collision gets a short suffix. The
account stays in the address (Kasper, 2026-09-24: "we can just design them
kinda like vercel if needed. i do like adding the account in there as
well"). So slugs keep hyphens, and the address registry, not this grammar,
guarantees uniqueness *(not built)*. Both parts also have a minimum length,
which keeps one- and two-letter labels from being squatted or used as
look-alikes (Kasper: "require prefixes of a certain length"). Account slugs
already need 3 characters; the proposal is 3 for the app prefix too, and the
exact minimum is *Decision for Kasper*.

## 2. Passwords

### Decision

- **Argon2id, m = 19 456 KiB (19 MiB), t = 2, p = 1**, 16-byte random
  salt, 32-byte output, stored as a PHC string. These are OWASP's first
  recommended Argon2id parameters. RFC 9106's 2 GiB default does not fit
  a small machine, and 64 MiB (tiny-auth) costs four times the memory per
  concurrent sign-in for a single-machine product.
- **At most four hashes at once per process** (a semaphore). A sign-in
  flood queues for a slot inside the request timeout instead of taking the
  machine's memory. Peak hashing memory is about 76 MiB.
- Passwords are **12 to 1024 characters**, with no composition rules, and
  may not equal the username or the email address. NIST SP 800-63B rev. 4
  asks for 15 when a password is the only factor. *Decision for Kasper:* 12
  (as tiny-auth and forest) or 15.
- **No pepper.** A pepper adds a key that, if lost or rotated, invalidates
  every password. The instance key already protects everything else, and
  losing it must not lock everyone out.
- A hash made with other parameters is **rehashed at the next successful
  sign-in**, so the parameters can change without a migration.
- **Unknown accounts are verified against a dummy hash** made at startup
  with the same parameters, so "no such account" and "wrong password" cost
  the same.

## 3. Sessions (the dashboard)

### Decision

- A session is **32 random bytes** in the cookie, base64url. The server
  stores **only their SHA-256**, so a database leak yields no usable session.
- Cookie: `__Host-grund_session`, `Path=/; HttpOnly; Secure; SameSite=Lax`.
  On a plain-http loopback origin (compose on localhost) browsers refuse
  `Secure` and the `__Host-` prefix, so there the cookie is `grund_session`
  without `Secure`. grund refuses to start on plain http anywhere but
  loopback, unless GRUND_DEV_MODE is on.
- **Lifetime**: an idle timeout of 7 days (`GRUND_SESSION_IDLE_TIMEOUT`) and
  an absolute maximum of 30 days (`GRUND_SESSION_MAX_AGE`, at most 90).
  Expiry is checked on every read. `last_seen_at` is written at most once a
  minute per session.
- **Rotation on sign-in**: every successful sign-in mints a new session and
  revokes the one the browser presented, if any. The CSRF token changes with
  it (below). A password reset revokes every session of the account.
- **Listing and revoking**: `/settings/sessions` lists the account's active
  sessions (when started, last seen, the browser's User-Agent, the client
  address) and revokes any of them, or all but the current one. Another
  account's session id is a 404, the same as a missing one.

## 4. CSRF

### Decision

Every form that changes state carries a hidden `csrf` field, checked in
every mutating handler:

- **Signed in**: the token is `HMAC-SHA256(csrf key, "session/" ||
  session id)`. It is bound to the session, so it rotates with it at sign-in.
- **Signed out** (sign-in, sign-up, reset, verify): a double-submit token.
  A random nonce goes in `__Host-grund_csrf` (HttpOnly, SameSite=Lax), and
  the form carries `HMAC(csrf key, "anonymous/" || nonce)`. The nonce is
  discarded at sign-in.
- Tokens are compared in constant time.
- **Origin check as a second, independent layer**: a state-changing request
  whose `Sec-Fetch-Site` is present and not `same-origin`/`none`, or whose
  `Origin` is present and is not GRUND_PUBLIC_URL, is refused (403) before
  the token is looked at.
- The CSP's `form-action 'self'` stops a page of ours from posting anywhere
  else. Social sign-in starts from a link, not a form, so the redirect to
  the provider is not a form submission `form-action` would block (the
  L-01 lesson from tiny).

## 5. Flows

### Sign-up

`POST /signup` with username, email and password.

1. CSRF and Origin. Sign-up enabled (`GRUND_SIGNUP_ENABLED`). Per-address
   limit.
2. Validate. A taken username is said plainly: usernames are public.
3. Hash the password (on every path).
4. If the email already belongs to an account, create nothing. Instead,
   queue a mail to that address: "someone tried to sign up with your
   address; if it was you, sign in or reset your password."
5. Otherwise, in one transaction: `Registered` on the account stream,
   `Created` and `MemberAdded(owner)` on a new organisation stream, the
   email and password rows, the three projections, a verification link
   token, and the verification mail in the outbox.
6. Both paths redirect to the same page, which names no address: "we sent a
   link to the address you entered".

Sign-in needs a verified email.

### Email verification

The mail carries `/verify?token=<32 random bytes>`, valid for 24 hours,
stored as a SHA-256. Opening it shows a page with a confirm button. The
`POST` consumes the token and records `EmailVerified`. A `GET` never
consumes anything, because mail scanners follow links. Verifying does not
sign the browser in: the link proves the mailbox, not the password.

### Sign-in

`POST /login` with an email or username, and a password.

1. CSRF and Origin. Per-address attempt limit.
2. If this account name has failed too often in the current window, answer
   "too many attempts" without checking the password. Names that do not
   exist are counted too, so this says nothing about whether one does.
3. Look the name up (by email if it contains `@`, else by username), and
   verify the password against the stored hash or the dummy hash.
4. On failure, count it, and answer the same page, status and text for
   "no such account" and "wrong password".
5. On success with an unverified email: queue a fresh verification mail
   (rate-limited) and say "confirm your email first". No session.
6. On success: reset the failure count, rehash if needed, rotate the
   session, set the cookie, and redirect 303 to `return_to` (a same-origin
   path only) or `/`.

### Sign-out

`POST /logout` revokes the current session and clears the cookie.

### Password reset

1. `POST /reset` with an email. CSRF and Origin, per-address limit, then a
   per-email limit (3 an hour): over it, nothing is queued. Otherwise one
   outbox row (`auth.password_reset_requested`) records the address. **The
   handler never looks the address up.**
2. Every request gets the same page: "if an account exists for that
   address, we sent a link".
3. The outbox worker resolves the row later. If an account has that
   address, it creates a reset token (30 minutes, SHA-256 stored,
   invalidating older ones) and queues the reset mail. If not, it sends
   nothing.
4. `GET /reset/confirm?token=` shows the new-password form (or "this link
   has expired"). `POST` sets the password, consumes the token, marks the
   email verified (the link proved the mailbox), records `PasswordChanged`,
   and revokes every session of the account.

### Social sign-in (commercial; §7)

GitHub, then Google, then any OpenID Connect provider:

1. `GET /auth/<provider>/start` refuses unless `Entitlements` allows social
   sign-in. It creates a flow row (random id, `state`, a PKCE S256
   verifier, an OIDC `nonce`, 10 minutes), puts the flow id in
   `__Host-grund_oauth`, and redirects to the provider.
2. `GET /auth/<provider>/callback` needs the cookie, the matching `state`,
   and an unexpired, unused flow. It exchanges the code with the PKCE
   verifier and the client secret.
   - **GitHub**: the profile (`/user`) and the primary verified address
     (`/user/emails`).
   - **OIDC and Google**: the ID token from the token endpoint. We check its
     `iss`, `aud`, `exp` and `nonce`, and read `email` and
     `email_verified`. The ID token arrives directly from the token
     endpoint over TLS, so its signature is not checked (OIDC Core
     §3.1.3.7 allows this).
3. **The linking rule:**
   - The identity (provider, subject) is already linked: sign in to that
     account.
   - The provider's address is **not verified**: refuse. Nothing is created
     or linked.
   - The verified address matches no account: a "choose a username" page.
     This creates an account with no password, with the address verified,
     and the identity linked.
   - The verified address matches an existing account: **link only after
     the person proves they own that account.** Today the proof is its
     password on a "connect GitHub to your account" page. It is
     rate-limited like sign-in, and succeeds only while the flow is fresh.
     An address match alone never links, whoever verified the address.
     Accounts without a password first set one through password reset,
     which proves the mailbox.

   *Decision for Kasper:* this rule, or also accepting a proof by an email
   link to the existing address.

## 6. Tokens for the API, the CLI and the agent

### Decision

- The Connect API (`grund.account.v1`) accepts the **dashboard session
  cookie** today, for same-origin calls from the dashboard. A
  cookie-authenticated call with a foreign `Origin` is refused. A
  cross-site page cannot send the `application/json` or
  `application/proto` Connect content types without a CORS preflight,
  which grund never grants.
- **Personal access tokens** for the CLI *(not built)*: `grund_pat_` plus
  32 random bytes in base62. The prefix lets secret scanners find leaked
  tokens. Only the SHA-256 is stored, scoped to an organisation, and each
  token has an expiry and a last-used time. The CLI gets one through the
  OAuth device authorization flow (RFC 8628) against the dashboard, so the
  person signs in with the browser they already use.
- **Machine agents** *(not built)* enrol with a one-time join token and
  receive short-lived **Ed25519 JWTs** (10 minutes, `aud` = the control
  plane) minted by the control plane, refreshed over their own mTLS or
  signed channel. Any grund component validates them locally from the
  control plane's JWKS, the tiny-auth shape (skills `http-api`).
- Bearer JWTs for people are deliberately not issued. A browser session
  is revocable at once, and a JWT cannot be revoked before it expires.

## 7. Entitlements (the commercial seam)

### Decision

One type, `Entitlements`, on `State` answers "may this instance use
feature X": `state.entitlements().require(Feature::SocialLogin)`. It is
built once at startup from the license key (docs/design/licensing.md).
Handlers ask it and nothing else. There is no flag, config value or `cfg`
anywhere else that turns a commercial feature on.

- No license, an invalid one, or one that is expired or does not include
  the feature: the feature is off. grund still starts, and it logs why. An
  expired license must never turn into an outage.
- Social sign-in configured but not entitled: the sign-in page shows no
  provider buttons. `/auth/<provider>/start` and `/callback` answer 403
  with a page that says a license is needed.

## 8. Limits and lockout

Counters are rows in `grund_throttle`, fixed windows keyed by
`HMAC(throttle key, scope || value)`, so no address or account name is
stored raw. Each check is one upsert.

| What | Default | Env var | Max / note |
|---|---|---|---|
| Failed sign-ins per account name | 10 per 15 min, then locked for the rest of the window | `GRUND_LOGIN_FAILURES_PER_ACCOUNT` | at least 3 |
| Sign-in attempts per client address | 100 per 15 min | `GRUND_LOGIN_ATTEMPTS_PER_ADDRESS` | 0 = off |
| Reset and verification mails per email | 3 per hour | `GRUND_MAIL_REQUESTS_PER_EMAIL` | at least 1 |
| Sign-up, reset and resend requests per address | 20 per hour | `GRUND_MAIL_REQUESTS_PER_ADDRESS` | 0 = off |
| Concurrent password hashes | 4 per process | none | fixed; see §2 |
| Password length | 12–1024 characters | none | |
| Session idle / absolute lifetime | 7 / 30 days | `GRUND_SESSION_IDLE_TIMEOUT` / `GRUND_SESSION_MAX_AGE` | 90 days |
| Verification / reset link | 24 h / 30 min | none | single use |
| Social sign-in flow | 10 min | none | single use |

**Why a table, not an in-process window (skills D-13).** Sign-in already
needs PostgreSQL (to read the hash), so the counter adds a statement to a
path that is ~50 ms of hashing, not a new dependency or failure mode. An
in-process window would multiply the lockout bound by the number of
replicas and forget it on every restart, which is the wrong trade for a
credential-guessing defence. The admission path that D-13 protects, cheap
authenticated API calls, is not this one.

**The per-address limits need the real client address.** GRUND_TRUSTED_PROXY_HOPS
says how many proxies to trust in `X-Forwarded-For`. Where the address is
not preserved (every request arrives from one proxy address), turn the
per-address limits off, or they throttle everyone together. Per-account
limits hold regardless.

**Lockout is a denial-of-service lever.** Anyone can lock a known username
for 15 minutes by failing on purpose. Password reset still works during a
lock, and the lock expires. That trade is accepted.

## 9. Mail

Mail goes through `grund_outbox`: the row is written in the same
transaction as the change it announces, and a worker (a notmad component,
added last so it drains last) delivers it after commit. NATS publishes a
wake-up after the commit, and the worker polls every
`GRUND_WORK_POLL_INTERVAL` regardless.

- Delivery is at least once. The outbox id is derived from what caused the
  mail, so a retry never makes a second row.
- Failures back off exponentially (2^attempts seconds, capped at 5 min).
- A delivered row keeps no recipient and no link: both are scrubbed on
  delivery. Delivered rows are deleted after 7 days (skills D-11).
- SMTP comes from `GRUND_SMTP_URL` (lettre; STARTTLS or TLS as the URL
  says). Without it, mail waits in the outbox and readiness reports the
  backlog.
- Templates are minijinja (text and HTML), embedded in the binary.

## 10. Threat model

Required here by skills D-25: this service holds credentials and a tenant
boundary.

**Assets:** password hashes; session and email-link tokens (their digests);
the instance secret key; email addresses; which accounts exist; each
organisation's resources (later: apps, machines, secrets).

**Trust boundaries:**

1. The browser ↔ grund.
2. grund ↔ PostgreSQL. Trusted, and on a private network.
3. grund ↔ the SMTP server and the OAuth providers. We send to them and
   read replies, but trust only what TLS and the protocol guarantee.
4. Organisation ↔ organisation inside one instance. Enforced by grund; there
   is no row-level security.

**Adversaries and controls:**

| Adversary | Attack | Control |
|---|---|---|
| Anonymous, online | guess passwords | per-name lockout, per-address limit, Argon2id, 4-hash cap |
| Anonymous | learn whether an address or name has an account | the dummy hash; identical sign-in answers; reset decided off the request path; identical sign-up answers for a taken address |
| Anonymous | mail-bomb an address through reset or resend | 3 mails per address per hour; per-address request limit |
| Cross-site page | CSRF on any form, login CSRF | session-bound or double-submit HMAC token, the Origin and Sec-Fetch-Site check, `SameSite=Lax`, `form-action 'self'` |
| Cross-site page | OAuth login CSRF or code injection | `state` bound to a `__Host-` cookie, PKCE S256, `nonce`, a single-use 10-minute flow |
| Someone who registers the victim's address first (pre-hijacking) | an unverified account squats the victim's address | an unverified account cannot sign in; the victim's reset verifies the address, replaces the password and revokes every session |
| Attacker with an OAuth identity carrying the victim's verified address | take over by address match | never linked without the account's password (§5) |
| Attacker who reads the database | replay sessions or links | only SHA-256 digests are stored; hashes are Argon2id; pending outbox rows do hold live links until delivered (up to 24 h) |
| Attacker who reads logs | tokens, addresses | never logged: the trace span has method and path only, no query string; addresses are never a log field |
| Member of organisation A | read or act on organisation B | every query binds the organisation from the session's account; another org's resource is 404 (second-account tests) |
| XSS | steal the session | HttpOnly cookie, a strict CSP with no inline script, autoescaped templates |

**Not defended (stated, not fixed):**

- **Compromise of the instance itself.** Whoever can read the secret key
  and the database can forge CSRF tokens and read every pending link. The
  key is protected by file permissions.
- **Timing of sign-up for a taken address.** That path skips a handful of
  inserts (Estimate: a few ms against ~50 ms of hashing). It is not
  claimed to be constant-time. Sign-in and reset are.
- **Targeted lockout** for 15 minutes (§8).
- **A mailbox compromise** is an account compromise: reset trusts the
  mailbox. There is no second factor yet *(not built)*.
- **Breached-password screening** *(not built)*.
- **Session binding to a device** (token binding, DPoP): a stolen cookie
  works until revoked or expired.

## 11. What is deliberately not in this version

Invitations and more than one member per organisation, organisation
switching in the UI, changing email or username, deleting an account,
second factors, passkeys, personal access tokens and the device flow,
agent tokens, an audit-log view, and admin accounts. Each is a later
feature with its own design; none is presented as built.

## 12. Verification

The accepttests (`crates/grund/tests/accepttest/`) run every flow against
the real binary, real PostgreSQL, NATS and Mailpit:

- **Sign-up and verification**: the link arrives by mail. Sign-in is
  refused before verification and allowed after it.
- **Sign-in and sign-out**: both by username and by email; wrong password
  and unknown account give identical answers; the session cookie's flags;
  the session rotates at sign-in.
- **Reset**: the same answer for known and unknown addresses; the link
  works once; old sessions die.
- **CSRF and Origin**: a request without the token, or from a foreign
  origin, is refused.
- **Limits**: the per-name lockout, including for a name that does not
  exist.
- **Sessions**: listing and revoking; **a second account's session is a
  404**.
- **The gate**: social sign-in configured without a license, or with a key
  this build does not trust, starts, shows no buttons, and refuses every
  `/auth/*` route with 403.
- **Social sign-in with a license** (`crates/grund-server/tests/social_flow.rs`,
  in process). It uses a license signed by a key generated inside the test,
  a mock OIDC provider on localhost, and real PostgreSQL:
  - the redirect carries `state`, a PKCE S256 challenge and a `nonce`;
  - a new identity chooses a username and becomes an account, and then
    signs straight in;
  - an identity whose address has an account links only with that
    account's password, and a used flow links nothing again;
  - an unverified address, or a callback with a `state` from another
    browser, is refused and creates nothing.
  No real GitHub, Google or OIDC app exists yet. Those are Kasper's to
  create, so the provider side is proven against the mock only
  (*Not established* against the real providers).

Timing equality for sign-in is measured, not assumed:

- **In the tests.** The sign-in test interleaves unknown-account and
  wrong-password attempts, nine of each, and requires their medians to be
  within 1.5x of each other. Interleaving matters: run in two batches on a
  busy CI runner, the first batch measured 61 ms and the second 27 ms,
  from load alone (pipeline 3, 2026-09-24).
- **By hand.** Observed on 2026-09-24 on an idle development machine, with
  a release build and 20 interleaved attempts of each: median 10.8 ms for
  an unknown account and 10.5 ms for a wrong password (min 8.4 ms and max
  14.2 ms for both).
