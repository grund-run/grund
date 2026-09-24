# Licensing and the commercial boundary

Status: proposal. **No license is chosen.** The choice is Kasper's, and until
he makes it no license is granted, the README says "License: to be decided",
and Cargo.toml names none. What is built is only the verification seam
(§4): grund can check a signed license key offline and turn features on
from it. No key has been issued, and the production key list is empty.

## What exists today

- grund is public from its first commit (git.kjuulh.io/grund/grund, mirrored
  to github.com/grund-run/grund) with no license file.
- The product promise, from the site and `product`: *you can always run all
  of grund yourself, dashboard included; hosted services are a convenience,
  never a requirement.* Pricing is by the machine for hosted plans: Homelab
  (first machine free, then €3), Pro €10, Business €49 + €10.
- The first commercial feature is **social sign-in** (GitHub, Google, OIDC).
  It is behind `Entitlements` (docs/design/auth.md §7), and without a valid
  license it stays off.

## The unifying concept

**The license decides who may sell grund as a service; the license key
decides which features one instance has.** These are separate questions.
The first is about competitors and contributors, and is answered once in a
LICENSE file. The second is about customers, and is answered per instance
by a signed key that works offline.

## 1. The options for the open-source license

### A. AGPL-3.0 core, plus a commercial license for the gated features

Everything is AGPL. Commercial features live in the same tree, and grund
also sells a commercial license (dual licensing) that lifts AGPL
obligations and unlocks the gated features by key.

- **Self-hosters**: free to run everything that is not gated, for any
  purpose, including a business. The AGPL only bites when they modify grund
  and offer it over a network. Most never notice.
- **Contributors**: they must sign a CLA (or grant a license back), or grund
  cannot relicense their code commercially. A CLA is friction, and some
  people refuse one.
- **Competitors hosting grund**: allowed, but they must publish their
  modifications under the AGPL. That deters closed forks, not hosting as
  such. A cloud could still host unmodified grund.
- **Seen in**: Grafana, Plausible, Mattermost (partially), n8n (before its
  own license).
- **The gated features' code is AGPL too**, so the key check is a courtesy,
  not a lock: anyone may remove it and redistribute under the AGPL.

### B. Apache-2.0 or MIT core, plus a source-available `ee/` directory

The core is permissive. Commercial features live in `ee/` under a separate
license: source-available, free to read and modify, but production use
needs a paid key (the GitLab EE / Cal.com / PostHog shape).

- **Self-hosters**: the core is as free as it gets. `ee/` is visible but
  not free to use in production.
- **Contributors**: no CLA needed for the core (the license is
  permissive). `ee/` contributions need one, or are simply not taken.
- **Competitors hosting grund**: they may host the core freely and
  commercially, and even close their fork. The only protection is `ee/` and
  the brand.
- **The boundary is a directory**, visible in code review, which suits the
  one-`Entitlements`-seam design: the seam lives in the core, and the
  features it gates move to `ee/`.

### C. FSL or BSL (source-available, converting to open source later)

Functional Source License (Sentry), or Business Source License (MariaDB,
formerly HashiCorp): everything is source-available with one restriction,
**no competing commercial offering**. Each release converts to Apache-2.0
or MIT after two years (FSL) or a set date (BSL, typically four years).

- **Self-hosters**: may use everything internally, commercially too.
  Hosting grund for others as a competing product is not allowed.
- **Contributors**: a CLA is still usual. Some contributors will not work
  on a non-OSI license.
- **Competitors hosting grund**: forbidden for two years per release. This
  is the strongest protection of the three.
- **Not open source by the OSI definition** until conversion. That conflicts
  with "open source first" in the site's copy and the product voice. The
  words would have to change to "source available".

## 2. Side by side

| | AGPL + commercial | Apache/MIT + `ee/` | FSL/BSL |
|---|---|---|---|
| OSI open source | yes | the core yes, `ee/` no | not until conversion |
| Self-hosting the free features, commercially | yes | yes | yes |
| A competitor hosts grund | yes, if they publish changes | yes, even closed | no (for 2–4 years) |
| CLA needed | yes (to relicense) | for `ee/` only | usually |
| Matches "open source first" | yes | yes, with care about `ee/` | no: must say "source available" |
| Commercial features' code | AGPL (removable gate) | proprietary, source-visible | FSL |
| Contributor friction | medium | low | medium–high |

## 3. Recommendation

**AGPL-3.0 for everything, with a commercial license sold as a key, and a
CLA from the start** (option A). *Decision for Kasper.*

- It is the only option that keeps both site promises, "open source" and
  "you can always run all of grund yourself", without rewording.
- The AGPL's network clause is the right shape for a platform: it deters a
  closed hosted fork, which is the likeliest real threat to a small
  company, without forbidding hosting outright.
- The gated features are few and are conveniences (social sign-in, SSO,
  audit log). People pay because the key is cheap and it funds the work,
  not because the gate is unbreakable. That matches the pricing (€3 to €10
  per machine) and the "fair, like Tailscale" stance.
- A CLA from the first outside contribution keeps option B or C open later.
  Relicensing without one is impossible once others have contributed.

If protection against hosted competitors becomes the priority, FSL is the
fallback, at the cost of the "open source" wording. Option B is weakest
against that threat, and it splits the codebase for little gain at this
size.

## 4. License keys: offline, signed, no phone-home

Built as a seam (`crates/grund-server/src/license.rs`,
`crates/grund-server/src/services/entitlements.rs`), and tested with keys
generated inside the tests.

### Format

A key is a compact token: `grund-license-v1.<payload>.<signature>`.

- **payload**: base64url of a JSON object:
  - `v`: format version, 1;
  - `kid`: which signing key;
  - `id`: the license's own id, for support and revocation lists;
  - `customer`: an opaque customer reference, not a name or address;
  - `plan`: `homelab`, `pro` or `business`;
  - `features`: e.g. `["social_login"]`;
  - `machines`: optional, the licensed machine count;
  - `issued_at`, `not_before`, `expires_at`: Unix seconds.
- **signature**: base64url of the Ed25519 signature over the bytes
  `grund-license-v1.` followed by the payload text.

### Verification

Verification is local and offline: grund embeds the public keys it trusts,
by `kid`. It checks, in order:

1. the prefix;
2. the `kid` is known;
3. the signature;
4. the version;
5. `not_before`;
6. `expires_at`.

All of it runs at startup, and `Entitlements` holds the result. There is
no network call, now or later: an air-gapped homelab stays licensed. The
trusted key list is compiled in, so changing it means a new build; an
operator cannot configure their own key and mint themselves a license. The
code is open, so anyone can patch that out; the gate is a commercial
boundary, not DRM.

### Failure behaviour

A missing, malformed, badly signed, not-yet-valid or expired key turns the
gated features off. grund still starts, and logs which of these happened.
A license lapsing must never become an outage.

### Subscriptions

A subscription is a series of keys:

- The billing system mints a key valid for the paid period plus a grace
  period (a month plus 14 days) at each renewal.
- The customer pastes it into `GRUND_LICENSE_KEY`, or the hosted dashboard
  delivers it *(not built)*.
- Cancelling means no new key: features stop at `expires_at`.
- Upgrading a plan mints a key with more `features`.
- Revoking a key before its expiry (fraud, chargeback) needs a revocation
  list, which an offline check cannot see. The mitigation is short key
  lifetimes. An *optional* online refresh that fetches a newer key could
  come later, but must never be required *(not built)*.

### Keys and rotation

- Signing keys are Ed25519 and are held by grund's billing side, never in
  this repository.
- Each has a `kid`. A new key is added to the embedded list one release
  before it signs anything, and an old one is removed only after every key
  it signed has expired.
- *Kasper must create the first production signing key* and add its public
  half to `TRUSTED_KEYS`. Until he does, no production key can verify.

## 5. What is deliberately not decided or built

- The LICENSE file and the CLA text.
- Pricing enforcement beyond feature flags. `machines` is carried in the
  key but not enforced: there are no machines yet.
- Online key refresh, revocation lists, and key delivery through the
  hosted dashboard.
