set -euo pipefail
umask 027

[[ -n ${CLICKHOUSE_ADMIN_USER:-} && $CLICKHOUSE_ADMIN_USER =~ ^[A-Za-z_][A-Za-z0-9_]*$ \
    && $CLICKHOUSE_ADMIN_USER != default && $CLICKHOUSE_ADMIN_USER != "${CLICKHOUSE_USER:-}" ]] \
    || { printf '%s\n' 'ClickHouse startup: CLICKHOUSE_ADMIN_USER must be a distinct non-default XML identifier' >&2; exit 1; }
[[ -n ${CLICKHOUSE_ADMIN_PASSWORD:-} ]] \
    || { printf '%s\n' 'ClickHouse startup: CLICKHOUSE_ADMIN_PASSWORD is required' >&2; exit 1; }
[[ $(id -u) == 0 ]] \
    || { printf '%s\n' 'ClickHouse startup: root startup is required to prepare admin configuration' >&2; exit 1; }

export CLICKHOUSE_ADMIN_PASSWORD_SHA256
CLICKHOUSE_ADMIN_PASSWORD_SHA256=$(printf '%s' "$CLICKHOUSE_ADMIN_PASSWORD" | sha256sum)
CLICKHOUSE_ADMIN_PASSWORD_SHA256=${CLICKHOUSE_ADMIN_PASSWORD_SHA256%% *}
mkdir -p /etc/clickhouse-server/users.d
cat > /etc/clickhouse-server/users.d/grund-admin.xml <<XML
<clickhouse>
    <users>
        <$CLICKHOUSE_ADMIN_USER>
            <password_sha256_hex from_env="CLICKHOUSE_ADMIN_PASSWORD_SHA256"/>
            <networks><ip>::/0</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </$CLICKHOUSE_ADMIN_USER>
    </users>
</clickhouse>
XML
chown root:clickhouse /etc/clickhouse-server/users.d/grund-admin.xml
chmod 0640 /etc/clickhouse-server/users.d/grund-admin.xml
