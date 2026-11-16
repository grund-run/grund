set -eu
: "${PGDATA:?PGDATA must be set}"
root=/var/lib/postgresql/data
kept_days=7
chown postgres:postgres "$root"
log() { printf 'grund: %s\n' "$*" >&2; }
fail() { log "$*"; exit 1; }
stash="$root/.grund/postgres"
install -d -o postgres -g postgres -m 0700 "$root/.grund" "$stash"

if [ "$(cat "$stash/$PG_MAJOR.version" 2>/dev/null)" != "$(postgres --version)" ]; then
    tar -czf "$stash/$PG_MAJOR.tar.gz.tmp" -C /usr/local bin lib share/postgresql
    mv "$stash/$PG_MAJOR.tar.gz.tmp" "$stash/$PG_MAJOR.tar.gz"
    postgres --version > "$stash/$PG_MAJOR.version"
fi

upgraded="$PGDATA.$PG_MAJOR.upgraded"
if [ ! -e "$PGDATA" ] && [ -s "$upgraded/PG_VERSION" ] && [ -e "$stash/upgrade.done" ]; then
    mv "$upgraded" "$PGDATA"
    log "finished an interrupted upgrade to PostgreSQL $PG_MAJOR"
fi

upgrade() {
    old=$1
    [ -s "$stash/$old.tar.gz" ] ||
        fail "this volume holds a PostgreSQL $old cluster but not the PostgreSQL $old binaries pg_upgrade needs; restart the PostgreSQL $old template once with this grund release so it keeps them, then deploy PostgreSQL $PG_MAJOR again"
    binaries="/tmp/grund-postgres-$old"
    rm -rf "$binaries"
    mkdir -p "$binaries"
    tar -xzf "$stash/$old.tar.gz" -C "$binaries"
    bin="$binaries/bin"
    kept="$PGDATA.$old"
    "$bin/postgres" --version >/dev/null ||
        fail "the kept PostgreSQL $old binaries do not run in the PostgreSQL $PG_MAJOR image; nothing was changed"
    [ ! -e "$kept" ] ||
        fail "$kept already exists from an earlier upgrade; nothing was changed"
    rm -rf "$upgraded" "$PGDATA.$PG_MAJOR.abandoned"
    need=$(du -sk "$PGDATA" | cut -f1)
    free=$(df -Pk "$root" | awk 'NR == 2 { print $4 }')
    [ "$free" -gt $((need + need / 5 + 262144)) ] ||
        fail "upgrading copies the cluster and keeps the PostgreSQL $old one for rollback: it needs about $((need / 1024 + need / 5120 + 256)) MiB free and $((free / 1024)) MiB is; nothing was changed"
    log "upgrading PostgreSQL $old to $PG_MAJOR with pg_upgrade --copy; the PostgreSQL $old cluster is kept at $kept"
    started=$(date +%s)
    work="$stash/upgrade"
    rm -rf "$work"
    install -d -o postgres -g postgres -m 0700 "$work"
    printf 'local all all trust\n' > "$work/hba"
    chown postgres:postgres "$work/hba"
    rm -f "$PGDATA/postmaster.pid"
    local_only="-c listen_addresses= -c unix_socket_directories=$work -c hba_file=$work/hba"
    gosu postgres "$bin/pg_ctl" -D "$PGDATA" -o "$local_only" -l "$work/old.log" -w -t 3600 start >/dev/null ||
        { cat "$work/old.log" >&2; fail "the PostgreSQL $old cluster did not start for the upgrade; nothing was changed"; }
    query() { gosu postgres "$bin/psql" -h "$work" -U "${POSTGRES_USER:-postgres}" -d template1 -XAtc "$1"; }
    if ! super=$(query "select rolname from pg_authid where oid = 10") ||
        ! settings=$(query "select pg_encoding_to_char(encoding), datlocprovider, datcollate, datctype, coalesce(datlocale, '') from pg_database where datname = 'template0'"); then
        gosu postgres "$bin/pg_ctl" -D "$PGDATA" -m fast -w -t 3600 stop >/dev/null
        fail "could not read the PostgreSQL $old cluster's superuser and locale; nothing was changed"
    fi
    gosu postgres "$bin/pg_ctl" -D "$PGDATA" -m fast -w -t 3600 stop >/dev/null
    encoding=$(printf %s "$settings" | cut -d'|' -f1)
    provider=$(printf %s "$settings" | cut -d'|' -f2)
    collate=$(printf %s "$settings" | cut -d'|' -f3)
    ctype=$(printf %s "$settings" | cut -d'|' -f4)
    locale=$(printf %s "$settings" | cut -d'|' -f5)
    case $provider in
        c) providers="--locale-provider=libc" ;;
        i) providers="--locale-provider=icu --icu-locale=$locale" ;;
        b) providers="--locale-provider=builtin --builtin-locale=$locale" ;;
        *) fail "unknown locale provider $provider; nothing was changed" ;;
    esac
    if [ "$("$bin/pg_controldata" "$PGDATA" | sed -n 's/^Data page checksum version: *//p')" = 0 ]; then
        checksums=--no-data-checksums
    else
        checksums=--data-checksums
    fi
    new="$PGDATA.$PG_MAJOR.new"
    rm -rf "$new"
    install -d -o postgres -g postgres -m 0700 "$new"
    gosu postgres initdb -D "$new" -U "$super" -E "$encoding" $providers \
        --lc-collate="$collate" --lc-ctype="$ctype" $checksums -A trust >"$work/initdb.log" 2>&1 ||
        { cat "$work/initdb.log" >&2; rm -rf "$new"; fail "initdb for PostgreSQL $PG_MAJOR failed; nothing was changed"; }
    if ! (cd "$work" && gosu postgres pg_upgrade -b "$bin" -B /usr/local/bin -d "$PGDATA" -D "$new" \
        -U "$super" --copy -o "$local_only" -O "$local_only" >"$work/pg_upgrade.log" 2>&1); then
        cat "$work/pg_upgrade.log" >&2
        find "$new" -name '*.log' -path '*pg_upgrade_output.d*' -exec cat {} + >&2 2>/dev/null || true
        rm -rf "$new"
        fail "pg_upgrade failed; the PostgreSQL $old cluster is unchanged. Deploy the PostgreSQL $old template to run it again"
    fi
    for file in pg_hba.conf pg_ident.conf; do
        [ ! -e "$PGDATA/$file" ] || cp -p "$PGDATA/$file" "$new/$file"
    done
    if grep -qv '^#' "$PGDATA/postgresql.auto.conf" 2>/dev/null; then
        log "ALTER SYSTEM settings of PostgreSQL $old were not carried over; they are in $kept/postgresql.auto.conf"
    fi
    rm -rf "$new/pg_upgrade_output.d"
    mv "$new" "$upgraded"
    date +%s > "$stash/upgrade.done"
    mv "$PGDATA" "$kept"
    mv "$upgraded" "$PGDATA"
    printf '{"from":%s,"to":%s,"method":"pg_upgrade --copy","finished_at":%s,"seconds":%s,"kept":"%s"}\n' \
        "$old" "$PG_MAJOR" "$(date +%s)" "$(($(date +%s) - started))" "$kept" > "$stash/upgrade.json"
    rm -rf "$work" "$binaries" "$stash/$old.tar.gz" "$stash/$old.version"
    log "upgraded PostgreSQL $old to $PG_MAJOR in $(($(date +%s) - started)) s; the PostgreSQL $old cluster stays at $kept for $kept_days days, for a rollback by deploying the PostgreSQL $old template"
}

rollback() {
    newer=$1
    kept="$PGDATA.$PG_MAJOR"
    [ "$(cat "$kept/PG_VERSION" 2>/dev/null)" = "$PG_MAJOR" ] ||
        fail "this volume holds a PostgreSQL $newer cluster and no kept PostgreSQL $PG_MAJOR cluster to roll back to; deploy the PostgreSQL $newer template, or restore a backup into a new volume"
    abandoned="$PGDATA.$newer.abandoned"
    rm -rf "$abandoned"
    mv "$PGDATA" "$abandoned"
    mv "$kept" "$PGDATA"
    rm -f "$stash/upgrade.done" "$stash/upgrade.json"
    log "rolled back to the PostgreSQL $PG_MAJOR cluster kept by the upgrade; writes made on PostgreSQL $newer are not in it and stay at $abandoned until the next upgrade"
}

if [ -s "$PGDATA/PG_VERSION" ]; then
    version=$(cat "$PGDATA/PG_VERSION")
    if [ "$version" -lt "$PG_MAJOR" ]; then
        upgrade "$version"
    elif [ "$version" -gt "$PG_MAJOR" ]; then
        rollback "$version"
    fi
fi

if [ -e "$stash/upgrade.done" ] && [ $(($(date +%s) - $(cat "$stash/upgrade.done"))) -gt $((kept_days * 86400)) ]; then
    for kept in "$PGDATA".[0-9]*; do
        [ -e "$kept" ] || continue
        rm -rf "$kept"
        log "removed $kept, kept for rollback since an upgrade more than $kept_days days ago"
    done
    rm -f "$stash/upgrade.done"
fi

if [ -s "$PGDATA/PG_VERSION" ]; then
    if [ ! -s "$PGDATA/postgresql.conf" ]; then
        cp "$(pg_config --sharedir)/postgresql.conf.sample" "$PGDATA/postgresql.conf"
    fi
    if [ ! -e "$PGDATA/pg_hba.conf" ]; then
        printf '%s\n' 'local all all scram-sha-256' > "$PGDATA/pg_hba.conf"
    fi
    if ! grep -Fqx 'host all all all scram-sha-256' "$PGDATA/pg_hba.conf"; then
        printf '\n%s\n' 'host all all all scram-sha-256' >> "$PGDATA/pg_hba.conf"
    fi
    if [ ! -e "$PGDATA/pg_ident.conf" ]; then
        : > "$PGDATA/pg_ident.conf"
    fi
    chown postgres:postgres "$PGDATA/postgresql.conf" "$PGDATA/pg_hba.conf" "$PGDATA/pg_ident.conf"
    chmod 0600 "$PGDATA/postgresql.conf" "$PGDATA/pg_hba.conf" "$PGDATA/pg_ident.conf"
fi
exec /usr/local/bin/docker-entrypoint.sh postgres -c 'listen_addresses=*'
