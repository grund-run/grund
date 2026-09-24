# Contributing to grund

Thank you for helping. Two rules make a contribution acceptable, and
neither needs a contributor agreement.

## 1. You license your contribution under Apache-2.0

Every contribution, to any part of this repository, is accepted under the
[Apache License, Version 2.0](LICENSES/Apache-2.0.txt). That is what lets
grund ship your work under the licenses the repository uses (the AGPL for
the core, Apache-2.0 for the API contract, and the grund Commercial License
for `ee/`), without asking you to sign anything or assign your copyright.
You keep your copyright.

## 2. You sign off every commit (Developer Certificate of Origin)

Add a `Signed-off-by:` line to each commit with `git commit -s`. It
certifies the Developer Certificate of Origin, reproduced below, and that
the license you submit under is Apache-2.0 (rule 1).

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## How we work

- In Rust, the only comments are doc comments on public items; `cargo run
  -q -p comment-policy` checks it, and CI runs it.
- Before opening a pull request, run the gates in the README ("Verify").
- For anything larger than a fix, open an issue first, so we agree on the
  shape before you spend the time.
- Security problems: do not open a public issue. Mail the maintainer
  instead (the address on the commits).
