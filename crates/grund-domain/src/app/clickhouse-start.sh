#!/bin/bash
set -euo pipefail
umask 027

fail() {
    printf 'ClickHouse startup: %s\n' "$1" >&2
    exit 1
}

[[ -n ${CLICKHOUSE_USER:-} ]] || fail 'CLICKHOUSE_USER is required'
[[ $CLICKHOUSE_USER =~ ^[A-Za-z_][A-Za-z0-9_]*$ && $CLICKHOUSE_USER != default ]] \
    || fail 'CLICKHOUSE_USER must be a non-default XML identifier'
[[ -n ${CLICKHOUSE_PASSWORD:-} ]] || fail 'CLICKHOUSE_PASSWORD is required'
[[ ${CLICKHOUSE_DB:-grund} == grund ]] || fail 'CLICKHOUSE_DB must be grund'
[[ ${CLICKHOUSE_MAX_SERVER_MEMORY_USAGE:-} =~ ^[1-9][0-9]*$ ]] \
    || fail 'CLICKHOUSE_MAX_SERVER_MEMORY_USAGE must be a positive byte integer'
[[ $(id -u) == 0 ]] || fail 'root startup is required to prepare the owned volume'

awk '$5 == "/var/lib/clickhouse" { n = split($6, options, ","); for (i = 1; i <= n; i++) if (options[i] == "rw") writable = 1 } END { exit !writable }' \
    /proc/self/mountinfo || fail '/var/lib/clickhouse must be a writable owned mount'

clickhouse_uid=$(id -u clickhouse)
clickhouse_gid=$(id -g clickhouse)
if [[ $(stat -c '%u:%g' /var/lib/clickhouse) != "$clickhouse_uid:$clickhouse_gid" ]]; then
    chown -R "$clickhouse_uid:$clickhouse_gid" /var/lib/clickhouse \
        || fail 'cannot prepare the owned volume'
fi
clickhouse su "$clickhouse_uid:$clickhouse_gid" bash -c \
    'probe=$(mktemp /var/lib/clickhouse/.grund-writable.XXXXXX) && printf "writable\n" > "$probe" && rm "$probe"' \
    || fail 'the owned volume is not writable by clickhouse'

runtime=/run/grund-clickhouse
mkdir -p "$runtime/http" /etc/clickhouse-server/config.d /etc/clickhouse-server/users.d
chown root:root "$runtime" "$runtime/http"
chmod 0755 "$runtime" "$runtime/http"
rm -f "$runtime/http/ready" "$runtime/http/ready.new"
chown root:"$clickhouse_gid" /etc/clickhouse-server/users.d
chmod 2750 /etc/clickhouse-server/users.d

cat > /etc/clickhouse-server/config.d/grund.xml <<'XML'
<clickhouse>
    <listen_host replace="replace">0.0.0.0</listen_host>
    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
    <mysql_port remove="remove"/>
    <postgresql_port remove="remove"/>
    <interserver_http_port remove="remove"/>
    <path>/var/lib/clickhouse/</path>
    <user_files_path>/run/grund-clickhouse/http/</user_files_path>
    <logger>
        <level>warning</level>
        <console>1</console>
        <log remove="remove"/>
        <errorlog remove="remove"/>
    </logger>
    <max_server_memory_usage from_env="CLICKHOUSE_MAX_SERVER_MEMORY_USAGE"/>
    <max_connections>32</max_connections>
    <max_concurrent_queries>4</max_concurrent_queries>
    <background_pool_size>2</background_pool_size>
    <background_merges_mutations_concurrency_ratio>2</background_merges_mutations_concurrency_ratio>
    <background_schedule_pool_size>8</background_schedule_pool_size>
    <background_buffer_flush_schedule_pool_size>2</background_buffer_flush_schedule_pool_size>
    <background_message_broker_schedule_pool_size>2</background_message_broker_schedule_pool_size>
    <background_distributed_schedule_pool_size>2</background_distributed_schedule_pool_size>
    <background_fetches_pool_size>2</background_fetches_pool_size>
    <background_move_pool_size>2</background_move_pool_size>
    <background_common_pool_size>2</background_common_pool_size>
    <mark_cache_size>16777216</mark_cache_size>
    <index_mark_cache_size>4194304</index_mark_cache_size>
    <uncompressed_cache_size>0</uncompressed_cache_size>
    <query_cache><max_size_in_bytes>0</max_size_in_bytes></query_cache>
    <merge_tree>
        <number_of_free_entries_in_pool_to_execute_mutation>1</number_of_free_entries_in_pool_to_execute_mutation>
        <number_of_free_entries_in_pool_to_lower_max_size_of_merge>1</number_of_free_entries_in_pool_to_lower_max_size_of_merge>
        <number_of_free_entries_in_pool_to_execute_optimize_entire_partition>1</number_of_free_entries_in_pool_to_execute_optimize_entire_partition>
        <max_bytes_to_merge_at_max_space_in_pool>67108864</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>
    <query_log remove="remove"/>
    <query_thread_log remove="remove"/>
    <query_views_log remove="remove"/>
    <query_metric_log remove="remove"/>
    <part_log remove="remove"/>
    <trace_log remove="remove"/>
    <text_log remove="remove"/>
    <metric_log remove="remove"/>
    <asynchronous_metric_log remove="remove"/>
    <error_log remove="remove"/>
    <crash_log remove="remove"/>
    <processors_profile_log remove="remove"/>
    <http_handlers replace="replace">
        <rule>
            <url>/ping</url>
            <methods>GET,HEAD</methods>
            <handler>
                <type>static</type>
                <response_content>file://ready</response_content>
            </handler>
        </rule>
        <rule>
            <methods>GET,HEAD,POST,OPTIONS</methods>
            <handler>
                <type>dynamic_query_handler</type>
                <query_param_name>query</query_param_name>
            </handler>
        </rule>
    </http_handlers>
</clickhouse>
XML
chmod 0644 /etc/clickhouse-server/config.d/grund.xml

cat > /etc/clickhouse-server/users.d/grund-profile.xml <<'XML'
<clickhouse>
    <profiles>
        <default>
            <max_threads>2</max_threads>
            <max_insert_threads>1</max_insert_threads>
            <max_memory_usage from_env="CLICKHOUSE_MAX_SERVER_MEMORY_USAGE"/>
            <max_block_size>8192</max_block_size>
            <preferred_block_size_bytes>1048576</preferred_block_size_bytes>
            <max_insert_block_size>65536</max_insert_block_size>
            <min_insert_block_size_rows>65536</min_insert_block_size_rows>
            <min_insert_block_size_bytes>8388608</min_insert_block_size_bytes>
            <log_queries>0</log_queries>
            <query_profiler_real_time_period_ns>0</query_profiler_real_time_period_ns>
            <query_profiler_cpu_time_period_ns>0</query_profiler_cpu_time_period_ns>
        </default>
    </profiles>
</clickhouse>
XML

export CLICKHOUSE_USER CLICKHOUSE_PASSWORD CLICKHOUSE_MAX_SERVER_MEMORY_USAGE
export CLICKHOUSE_CONFIG=/etc/clickhouse-server/config.xml
export CLICKHOUSE_UID="$clickhouse_uid" CLICKHOUSE_GID="$clickhouse_gid"
export CLICKHOUSE_RUN_AS_ROOT=0 CLICKHOUSE_DO_NOT_CHOWN=1
export CLICKHOUSE_SKIP_USER_SETUP=0 CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0
export CLICKHOUSE_WATCHDOG_ENABLE=0
unset CLICKHOUSE_PASSWORD_FILE CLICKHOUSE_ALWAYS_RUN_INITDB_SCRIPTS

server_pid=
cleanup() {
    rm -f "$runtime/http/ready" "$runtime/http/ready.new"
    if [[ -n $server_pid ]]; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

CLICKHOUSE_DB= /entrypoint.sh > /dev/null &
server_pid=$!

client() {
    timeout --signal=KILL 2 clickhouse-client --host 127.0.0.1 --port 9000 \
        --connect_timeout=1 --receive_timeout=1 --send_timeout=1 "$@" 2>/dev/null
}

startup_deadline=$((SECONDS + 60))
database_ready=0
startup_ready=0
while kill -0 "$server_pid" 2>/dev/null; do
    if [[ $database_ready == 0 ]] && client --query 'CREATE DATABASE IF NOT EXISTS grund' > /dev/null; then
        database_ready=1
    fi
    if [[ $database_ready == 1 ]] \
        && result=$(client --database grund --query 'SELECT 1') \
        && [[ $result == 1 ]]; then
        if [[ ! -f $runtime/http/ready ]]; then
            printf 'Ok.\n' > "$runtime/http/ready.new"
            chmod 0644 "$runtime/http/ready.new"
            mv "$runtime/http/ready.new" "$runtime/http/ready"
        fi
        if ! wget -q -T 1 -t 1 -O /dev/null http://127.0.0.1:8123/ping; then
            rm -f "$runtime/http/ready"
        else
            startup_ready=1
        fi
    else
        rm -f "$runtime/http/ready"
    fi
    if [[ $startup_ready == 0 && $SECONDS -ge $startup_deadline ]]; then
        fail 'authenticated query and /ping readiness did not succeed within 60 seconds'
    fi
    sleep 1
done

rm -f "$runtime/http/ready"
set +e
wait "$server_pid"
status=$?
server_pid=
exit "$status"
