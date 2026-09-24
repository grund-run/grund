# Threat model

grund holds credentials and a tenant boundary, so it keeps a threat model
(skills D-25). It lives with the design it defends rather than restated here:

- Accounts, sessions, sign-in, mail links and social sign-in:
  [docs/design/auth.md §10](docs/design/auth.md#10-threat-model) (assets,
  trust boundaries, adversaries and controls, and what is not defended).
- License keys and the commercial gate:
  [docs/design/licensing.md](docs/design/licensing.md).

Each new feature that adds an asset or a boundary adds its section to its own
design document and a line here.
