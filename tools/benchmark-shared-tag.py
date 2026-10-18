#!/usr/bin/env python3
"""Branch-only tag attribution proof; never creates a tag or publishes."""

import importlib.util
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
VERSION = "v0.0.0-alpha.999999"
BRANCH = "ci/ciperf-shared-tag"

spec = importlib.util.spec_from_file_location("release", ROOT / "tools/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def benchmark_identity():
    if (os.environ.get("CI_PIPELINE_EVENT") != "push"
            or os.environ.get("CI_COMMIT_BRANCH") != BRANCH
            or os.environ.get("CI_COMMIT_TAG") != VERSION):
        release.fail("benchmark requires its non-tag push branch and simulated version")
    release.REVISION = release.output("git", "rev-parse", os.environ["CI_COMMIT_SHA"] + "^{commit}")
    if release.output("git", "rev-parse", "HEAD") != release.REVISION:
        release.fail("benchmark checkout does not match its public commit")


def main():
    os.chdir(ROOT)
    commands = {
        "prepare": release.prepare,
        "verify-amd64": lambda: release.verify(("amd64",)),
        "verify-arm64": lambda: release.verify(("arm64",)),
        "merge-images": release.merge_images,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        release.fail("benchmark permits only local preparation and verification, never publication")
    release.identity = benchmark_identity
    benchmark_identity()
    commands[sys.argv[1]]()
    print(f"BENCHMARK_VERIFIED {sys.argv[1]} {VERSION} {release.REVISION}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(f"benchmark: {error}", file=sys.stderr)
        sys.exit(1)
