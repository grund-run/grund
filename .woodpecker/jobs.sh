#!/bin/sh
# Bound concurrent Rust compilations on ratchet's 31 GiB host (agent 1),
# for every event. Agent 5 keeps its default job count.
if [ "${CI_MACHINE:-}" = 0c1ad77f1697 ]; then
    CARGO_BUILD_JOBS=4
    export CARGO_BUILD_JOBS
fi
