set -eu
: "${PGDATA:?PGDATA must be set}"
chown postgres:postgres /var/lib/postgresql/data
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
