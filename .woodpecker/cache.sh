#!/bin/sh
# Source after sccache is installed. The public repository does not embed an
# internal cache address: only trusted push jobs receive its endpoint/password.
if [ "${CI_MACHINE:-}" = 0c1ad77f1697 ]; then
    CARGO_BUILD_JOBS=4
    export CARGO_BUILD_JOBS
    if [ -n "${CI_CACHE_PUBLIC_ENDPOINT:-}" ] && [ -n "${SCCACHE_WEBDAV_PASSWORD:-}" ]; then
        authority=${CI_CACHE_PUBLIC_ENDPOINT#http://}
        host=${authority%%:*}
        port=${authority#*:}
        port=${port%%/*}
        if nc -z -w 2 "$host" "$port" 2>/dev/null; then
            SCCACHE_WEBDAV_ENDPOINT=$CI_CACHE_PUBLIC_ENDPOINT
            SCCACHE_WEBDAV_USERNAME=public
            SCCACHE_MULTILEVEL_CHAIN=webdav
            export SCCACHE_WEBDAV_ENDPOINT SCCACHE_WEBDAV_USERNAME SCCACHE_MULTILEVEL_CHAIN
            if sccache --start-server; then
                unset SCCACHE_MEMCACHED_ENDPOINT
                export RUSTC_WRAPPER=sccache
                echo 'using ratchet public disk-backed compile cache'
                return 0
            fi
        fi
    fi
fi
unset SCCACHE_WEBDAV_ENDPOINT SCCACHE_WEBDAV_USERNAME SCCACHE_WEBDAV_PASSWORD SCCACHE_MULTILEVEL_CHAIN CI_CACHE_PUBLIC_ENDPOINT

# Keep agent 5's existing local memcached first and the shared endpoint
# second. The protocol probe distinguishes memcached from ratchet's WebDAV.
gateway=$(ip route | awk '/^default/ {print $3; exit}')
if [ -n "$gateway" ] &&
    printf 'version\r\n' | nc -w 1 "$gateway" 11311 2>/dev/null | grep -q '^VERSION'; then
    SCCACHE_MEMCACHED_ENDPOINT=tcp://$gateway:11311
    export SCCACHE_MEMCACHED_ENDPOINT
    echo "using this agent's own compile cache"
fi
if [ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]; then
    address=${SCCACHE_MEMCACHED_ENDPOINT#tcp://}
    if nc -z -w 3 "${address%:*}" "${address##*:}" && sccache --start-server; then
        export RUSTC_WRAPPER=sccache
        return 0
    fi
fi
unset SCCACHE_MEMCACHED_ENDPOINT RUSTC_WRAPPER
echo 'compile cache unreachable; compiling directly'
