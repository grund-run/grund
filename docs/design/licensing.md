# Licensing and the commercial boundary

Status: proposal. **No license is chosen.** The choice is Kasper's, and until
he makes it no license is granted, the README says "License: to be decided",
and Cargo.toml names none. What is built is only the verification seam
(§7): grund can check a signed license key offline and turn features on
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

## 1. What comparable products chose

Observed on 2026-09-24. The sources are the GitHub API (the `license` field
and star counts) and each repository's own LICENSE file and its git
history. Where GitHub reports `NOASSERTION`, the LICENSE file was read. A
reason is given only where the project stated one; otherwise it reads *not
established*.

| Shape | Projects (stars, rounded) |
|---|---|
| **Permissive only** (MIT, Apache-2.0, BSD) | Coolify 62k (Apache), Dokku 32k (MIT), Kamal 15k (MIT), CapRover 15k (Apache), Uncloud 5.5k (Apache), k3s 34k (Apache), Supabase 111k (Apache), Keycloak 37k (Apache), Appwrite 57k (BSD), Headscale 44k and Tailscale's client 37k (BSD), Valkey 27k (BSD), Portainer 39k (zlib), Cal.com 49k (MIT since 2026-04-15) |
| **Permissive core plus a proprietary directory** (open core) | GitLab (MIT, plus `ee/`), PostHog 40k (MIT, plus `ee/`), Infisical 29k (MIT, plus `ee/`), authentik 26k (MIT, plus `authentik/enterprise/`), Dokploy 37k (Apache, plus `/proprietary`, since 2026-01-21) |
| **AGPL only** | Grafana 77k, Immich 115k, Plausible 29k, Mastodon 50k, Nextcloud 37k, Coder 17k, Documenso 15k, MinIO 61k (repository archived) |
| **AGPL plus a commercial directory** | **Metabase** (AGPL, plus `enterprise/` under the Metabase Commercial License), Bitwarden server 20k (AGPL, plus `bitwarden_license/`), Mattermost 39k (AGPL or commercial for source; compiled builds under MIT) |
| **AGPL with permissive exceptions** | Zitadel 15k (AGPL-3.0-only; `proto/` Apache, clients and login MIT) |
| **Source-available** (not OSI) | Sentry (FSL-1.1, becoming Apache), Terraform (BSL from 1.6), Outline 41k (BSL), n8n 206k (Sustainable Use License, plus `.ee.` files), Redis (RSALv2/SSPL, and AGPL since 8.0), Elasticsearch (SSPL/ELv2, and AGPL since 2024) |

### How licenses moved

The history matters more than the snapshot. It shows which choices
companies came to regret:

- **Permissive → AGPL, kept:**
  - Grafana relicensed Apache → AGPLv3 on 2021-04-20. It stated why:
    "It's hard to say you're an open source company when you're using a
    license that isn't accepted by OSI" (it rejected SSPL), and
    "Unmodified distributions are not affected." A cloud partner (AWS) got
    a commercial arrangement instead.
  - MinIO: Apache → AGPL, 2021-04-23.
  - Zitadel: Apache → AGPL-3.0-only with v3, 2025-04-02. It kept
    community commits from before v3 under Apache, because it could not
    relicense them.
- **Permissive → source-available → back to AGPL:**
  - Elasticsearch: Apache → SSPL/Elastic License in 2021, and AGPL added
    on 2024-09-13.
  - Redis: BSD → RSALv2/SSPL on 2024-03-20, and AGPL added on 2025-05-01.
  - Both source-available moves were answered by forks under the old
    license (OpenSearch, and Valkey under BSD with 27k stars).
- **Open source → BSL, forked:** Terraform went MPL → BSL. OpenTofu (MPL,
  30k stars) is the fork.
- **Against the trend:**
  - Coolify: AGPL → Apache in August 2022 (reason *not established*).
  - Cal.com: AGPL core plus commercial `ee/` → MIT on 2026-04-15, in a
    commit titled "refactor: Cal.diy" (reason *not established*).
  - Dokploy: Apache → Apache plus a `/proprietary` directory on
    2026-01-21.

**The pattern:** the companies whose business is running their own
software as a service kept moving away from permissive licenses, and
source-available licenses cost them a fork. AGPL is where several of them
landed, because it is the strongest protection that still counts as open
source. Nobody who started on AGPL had to relicense to protect their
business. Coolify and Cal.com moved away from AGPL toward permissive, and
neither gave a public reason in the repository.

## 2. The case against Apache-2.0 or MIT for grund

grund's business is the hosted dashboard, rented machines and the licensed
features (above, "What exists today"; skills `product`).
That shapes every argument below.

1. **A permissive license lets anyone sell hosted grund, closed.** A hosting
   company or a competitor could take grund, keep its changes private, and
   offer "managed grund" beside its own servers. grund's hosted plans would
   compete with their own code, improved in private. Under the AGPL (§13)
   they may still host it, but everyone using their hosted version gets the
   source of their changes, so there is no closed fork to compete with.
   This is the exact threat Grafana, MinIO, Zitadel, Elastic and Redis
   relicensed to answer.
2. **Permissive forces the moat into proprietary code.** Under MIT or Apache,
   the only protected value is what grund keeps out of the open license:
   GitLab's `ee/`, PostHog's, authentik's `enterprise/`. That pulls
   features out of the open edition over time. Under the AGPL the whole
   platform is protected, and the proprietary part can stay small (just
   the licensed conveniences), which keeps "the self-hosted edition is
   free and complete" true.
3. **You cannot tighten later without paying for it.** Starting permissive
   and tightening later is the move that produced OpenSearch, Valkey and
   OpenTofu. Tightening also needs every contributor's permission, and
   Zitadel had to leave its pre-v3 community code under Apache. Starting
   under the AGPL means that conversation never has to happen, and loosening
   later (AGPL to Apache) is always possible, uncontroversial, and needs
   nobody's permission beyond grund's own copyright.
4. **Apache's usual advantages do not favour it over the AGPL.**
   - Apache-2.0 has an explicit patent grant, but so does AGPL-3.0 (§11,
     shared with GPL-3.0). MIT has none.
   - Apache-2.0 and MIT dependencies can be combined into an AGPL-3.0 work,
     so the Rust ecosystem (almost all MIT/Apache) poses no compatibility
     problem.
5. **"Open source first" is a promise the AGPL keeps literally.** The AGPL
   is OSI-approved. FSL, BSL and SSPL are not, and the site would have to
   say "source available" instead.

## 3. The honest case for Apache-2.0 or MIT

Arguments that are real, and what each costs grund:

1. **Some companies ban the AGPL outright.**
   - Google's policy says: "Code licensed under the GNU Affero General
     Public License (AGPL) MUST NOT be used at Google" (fetched
     2026-09-24). Other large companies have similar rules.
   - *For grund:* those buyers are not the first audience (self-hosters,
     homelabs, small SaaS). When they do come, a commercial license sold to
     them (Mattermost's and Metabase's model) turns the ban into revenue.
     It is a sales conversation, not a lost user.
2. **Contributors shy away from copyleft and from CLAs.**
   - Grafana and Coder require a CLA, and a CLA is friction.
   - *For grund:* take contributions under Apache-2.0 instead, with a DCO
     sign-off. That is Zitadel's model: "all contributions must be
     licensed under the Apache License 2.0 … This approach avoids the need
     for a Contributor License Agreement." Apache-licensed contributions
     can be shipped under the AGPL and sold under a commercial license, so
     grund keeps full freedom without a CLA.
3. **Libraries and clients must be embeddable.**
   - An AGPL client library would push AGPL obligations onto every program
     that embeds it.
   - *For grund:* license the contract and the clients permissively, as
     Zitadel does (`proto/` Apache; clients MIT). That covers `proto/`,
     `crates/grund-proto`, and the future SDK and CLI. The AGPL covers the
     server and the agent.
4. **Adoption.** The most-starred projects in this space (Coolify, Dokku,
   Supabase) are permissive, and permissive is frictionless.
   - *For grund:* Immich (115k), Grafana (77k) and Plausible grew as large
     under the AGPL. The license did not stop self-hosters, who run
     unmodified software and owe nothing.

## 4. What the AGPL means for the people who use grund

State these in the FAQ when the license is announced:

- **Self-hosting unmodified grund**, including for a business: no
  obligations beyond keeping the notices.
- **Self-hosting a modified grund** that others use over the network (your
  team, your customers): offer them the source of your modified version.
- **The apps you deploy on grund are not affected.** They are separate
  programs that grund starts, routes to and monitors. grund does not link
  into them, and they do not link grund. A SaaS running on grund stays
  under whatever license its owner chose.
- **Hosting grund for others** is allowed, but modifications must be
  published to those users. Unmodified hosting is allowed too; the
  commercial features still need a key.
- **The contract and clients** (proto, SDK, CLI) are Apache-2.0, so
  anything may embed them.

## 5. Where the commercial features live

Two ways to combine the AGPL with licensed features:

| | Everything AGPL, gate is a courtesy | AGPL plus a commercial directory (Metabase) |
|---|---|---|
| The code of social sign-in, SSO, audit log | AGPL, in the tree | `ee/`, under a grund Commercial License: source-visible, use needs a license |
| Anyone may remove the key check and use it | yes, legally | no: the key check is backed by the license |
| "The self-hosted edition is free and complete" | the free edition is everything | the free edition is everything outside `ee/` |
| Contributions to the paid features | AGPL, like everything else | taken under Apache-2.0, like everything else |
| Seen in | Plausible (no paid features in the code) | Metabase, Bitwarden, Cal.com until 2026 |

Metabase is the closest match to what grund plans. Its LICENSE reads:
"Outside of the top-level 'enterprise' directory, source code … is
licensed under the AGPL. Within the top-level 'enterprise' directory,
source code … is licensed under the Metabase Commercial License". Its
`enterprise/LICENSE.txt` adds: "Access to files in this directory … does
not constitute permission to use this code or Metabase Enterprise Edition
features." Metabase ships two builds. grund can ship one binary whose
`ee` features activate only with a key (§6), because the license, not the
build, is what forbids unlicensed use.

## 6. Recommendation

*Decision for Kasper.* The recommendation is **the AGPL open core, in
Metabase's shape:**

1. **AGPL-3.0-only** for the server and the agent (`crates/grund`,
   `grund-server`, `grund-store`, `grund-domain`). "-only", as Zitadel and
   Elasticsearch use: grund decides which license versions apply, not a
   future FSF revision.
2. **Apache-2.0** for `proto/`, `crates/grund-proto` and the future SDK and
   CLI, so anyone can build on grund's API.
3. **A top-level `ee/` under a grund Commercial License** for the licensed
   features. Social sign-in is the first; it moves there when this is
   decided. The source stays readable, and use needs a key.
4. **Contributions under Apache-2.0 with a DCO sign-off, and no CLA**
   (Zitadel's model), so grund can ship them under the AGPL, the commercial
   license and any future license.
5. **A commercial license for sale** to companies whose policy bans the
   AGPL, or who want to change grund without publishing the change.

Why this rather than Apache plus `ee/` (GitLab, PostHog): it is the same
open-core split, but the open part is protected against a closed hosted
fork, which is the threat that matters for a company that sells hosting.
Why this rather than everything AGPL with a courtesy gate (the previous
recommendation): the paid features become a license term, not just a
check that anyone may lawfully delete, and nothing else changes for
self-hosters.

What it would take, once decided:
- a LICENSE (AGPL text plus a header like Metabase's saying which
  directories are licensed how), `ee/LICENSE` and a LICENSING.md;
- SPDX headers or per-crate `license` fields (`AGPL-3.0-only`,
  `Apache-2.0`);
- moving `services/social.rs`, `web/social.rs` and the flow migration into
  an `ee` crate;
- a CONTRIBUTING.md that states the Apache-2.0 inbound rule and the DCO;
- a license FAQ on grund.sh (§4), and the site's "open source" wording
  kept as it is.

## 7. License keys: offline, signed, no phone-home

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

## 8. What is deliberately not decided or built

- The LICENSE file, LICENSING.md, `ee/LICENSE` and CONTRIBUTING.md (the
  list in §6).
- Pricing enforcement beyond feature flags. `machines` is carried in the
  key but not enforced: there are no machines yet.
- Online key refresh, revocation lists, and key delivery through the
  hosted dashboard.
