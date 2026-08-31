#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MONITOR=${V2RAY_AGENT_TRAFFIC_MONITOR_UNDER_TEST:-${SCRIPT_DIR}/../shell/traffic_monitor.sh}
if [[ ! -f ${MONITOR} ]]; then
    MONITOR=${SCRIPT_DIR}/traffic_monitor.sh
fi
TEST_ROOT=$(mktemp -d "${SCRIPT_DIR}/.traffic-test.XXXXXX")
AGENT_DIR=${TEST_ROOT}/agent
TRAFFIC_DIR=${AGENT_DIR}/traffic
XRAY_CONF_DIR=${AGENT_DIR}/xray/conf

cleanup() {
    rm -rf -- "${TEST_ROOT}"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_jq() {
    local file=$1 expression=$2 message=$3
    jq -e "${expression}" "${file}" >/dev/null || fail "${message}"
}

assert_file() {
    [[ -f $1 ]] || fail "missing file: $1"
}

assert_no_file() {
    [[ ! -e $1 ]] || fail "unexpected file: $1"
}

run_monitor() {
    env \
        V2RAY_AGENT_BASE_DIR="${AGENT_DIR}" \
        V2RAY_AGENT_TRAFFIC_DIR="${TRAFFIC_DIR}" \
        V2RAY_AGENT_XRAY_CONF_DIR="${XRAY_CONF_DIR}" \
        V2RAY_AGENT_TEST_MODE=1 \
        V2RAY_AGENT_NOW_DATE="${NOW_DATE}" \
        V2RAY_AGENT_NOW_EPOCH="${NOW_EPOCH}" \
        V2RAY_AGENT_STATS_FILE="${STATS_FILE}" \
        bash "${MONITOR}" "$@"
}

write_stats() {
    local target=$1 vless_up=$2 vless_down=$3 vmess_up=$4 vmess_down=$5 admin=$6
    jq -n \
        --argjson a "${vless_up}" --argjson b "${vless_down}" \
        --argjson c "${vmess_up}" --argjson d "${vmess_down}" \
        --argjson e "${admin}" '{
        stat: [
            {name: "inbound>>>VLESSTCP>>>traffic>>>uplink", value: $a},
            {name: "inbound>>>VLESSTCP>>>traffic>>>downlink", value: $b},
            {name: "inbound>>>VMessWS>>>traffic>>>uplink", value: $c},
            {name: "inbound>>>VMessWS>>>traffic>>>downlink", value: $d},
            {name: "inbound>>>ADMIN>>>traffic>>>uplink", value: $e},
            {name: "user>>>alice-VLESS>>>traffic>>>uplink", value: 999999}
        ]
    }' >"${target}"
}

mkdir -p "${XRAY_CONF_DIR}" "${TRAFFIC_DIR}"

jq -n '{
    inbounds: [
        {tag: "VLESSTCP", listen: "0.0.0.0", port: 443, settings: {}},
        {tag: "VMessWS", listen: "127.0.0.2", port: 443, settings: {}}
    ]
}' >"${XRAY_CONF_DIR}/02_public_inbounds.json"

jq -n '{
    inbounds: [
        {tag: "ADMIN", listen: "127.0.0.1", port: 8443, settings: {}}
    ]
}' >"${XRAY_CONF_DIR}/03_admin_inbound.json"

jq -n '{policy: {levels: {"0": {handshake: 2, connIdle: 280}}}}' \
    >"${XRAY_CONF_DIR}/12_policy.json"
jq -n '{routing: {domainStrategy: "AsIs", rules: [
    {type: "field", protocol: ["bittorrent"], outboundTag: "blocked"}
]}}' >"${XRAY_CONF_DIR}/09_routing.json"

STATS_FILE=${TEST_ROOT}/stats-zero.json
write_stats "${STATS_FILE}" 0 0 0 0 0
NOW_DATE=2026-08-31
NOW_EPOCH=1788134400

discovered=$(run_monitor discover-ports)
jq -e '
    ([.[] | select(.port == "443") | .tag] | sort) == ["VLESSTCP", "VMessWS"]
    and ([.[] | select(.port == "8443") | .tag] == ["ADMIN"])
' <<<"${discovered}" >/dev/null || fail 'inbound ports were not discovered'
assert_jq "${TRAFFIC_DIR}/config.json" '
    .version == 2 and .coverage == "xray-ports"
    and (.ports | type) == "object" and has("users") == false
' 'port-only config was not initialized'

# Refuse to expose StatsService on a non-loopback address.
config_tmp=${TEST_ROOT}/config-unsafe-api.json
jq '.enabled = true | .api = "0.0.0.0:10085"' \
    "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"
if run_monitor sync-config >/dev/null 2>&1; then
    fail 'non-loopback StatsService address was accepted'
fi
config_tmp=${TEST_ROOT}/config-safe-api.json
jq '.enabled = false | .api = "127.0.0.1:10085"' \
    "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"

config_tmp=${TEST_ROOT}/config.json
jq '
    .enabled = true
    | .alert_percent = 80
    | .auto_disable = true
    | .ports["443"] = {
        daily_limit: 2000,
        monthly_limit: 0,
        total_limit: 0,
        billing_limit: 0,
        billing_day: 15
      }
' "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"

# 80% threshold: aggregate every Xray inbound tag that listens on port 443.
STATS_FILE=${TEST_ROOT}/stats-threshold.json
write_stats "${STATS_FILE}" 400 400 400 400 100
run_monitor collect

assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].total == 1600' \
    'inbound tags on the same port were not aggregated'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["8443"].total == 100' \
    'second inbound port was not counted independently'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].daily.bytes == 1600' \
    'daily total is incorrect'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].monthly.bytes == 1600' \
    'monthly total is incorrect'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].billing.key == "2026-08-15"' \
    'custom billing key is incorrect'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].disabled == false and has("users") == false' \
    'threshold warning must not disable the port or create user state'
grep -q '端口 443.*达到 80%' "${TRAFFIC_DIR}/alerts.log" || fail 'port threshold alert missing'
assert_no_file "${XRAY_CONF_DIR}/08_traffic_block_outbound.json"

# Polling the same absolute core counters must not count traffic twice.
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].total == 1600' \
    'unchanged core counters were counted twice'
[[ $(grep -c '端口 443.*达到 80%' "${TRAFFIC_DIR}/alerts.log") -eq 1 ]] || \
    fail 'threshold alert was emitted more than once'

# A lock left by a dead collector must not stop future collections.
mkdir "${TRAFFIC_DIR}/collect.lock"
printf '%s\n' '999999' >"${TRAFFIC_DIR}/collect.lock/pid"
run_monitor collect
assert_no_file "${TRAFFIC_DIR}/collect.lock"

# Crossing the daily limit blackholes every inbound tag on that port.
STATS_FILE=${TEST_ROOT}/stats-limit.json
write_stats "${STATS_FILE}" 525 525 525 525 100
NOW_EPOCH=1788134700
run_monitor collect

assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].daily.bytes == 2100' \
    'second delta was not accumulated'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].disabled == true' \
    'over-limit port was not disabled'
assert_jq "${XRAY_CONF_DIR}/09_routing.json" '
    .routing.rules[0].outboundTag == "v2ray-agent-traffic-block"
    and (.routing.rules[0].inboundTag | sort) == ["VLESSTCP", "VMessWS"]
    and (.routing.rules[0] | has("user") | not)
' 'block rule does not cover all inbound tags on the port'
assert_jq "${XRAY_CONF_DIR}/09_routing.json" '
    [.routing.rules[] | select(.outboundTag == "blocked")] | length == 1
' 'existing routing rule was lost'
assert_file "${XRAY_CONF_DIR}/08_traffic_block_outbound.json"
assert_jq "${XRAY_CONF_DIR}/13_traffic_stats.json" '
    .api.listen == "127.0.0.1:10085"
    and .api.services == ["StatsService"]
' 'StatsService is not restricted to loopback'
assert_jq "${XRAY_CONF_DIR}/12_policy.json" '
    .policy.levels["0"].handshake == 2
    and .policy.system.statsInboundUplink == true
    and .policy.system.statsInboundDownlink == true
' 'inbound policy settings were not safely merged'
grep -q '端口 443 已因流量超额自动停用' "${TRAFFIC_DIR}/alerts.log" || \
    fail 'automatic port disable alert missing'

# Daily and natural-month periods reset, lifetime remains cumulative.
STATS_FILE=${TEST_ROOT}/stats-zero-next.json
write_stats "${STATS_FILE}" 0 0 0 0 0
NOW_DATE=2026-09-01
NOW_EPOCH=1788220800
run_monitor collect

assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].daily.bytes == 0' \
    'daily period did not reset'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].monthly.bytes == 0' \
    'monthly period did not reset'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].billing.bytes == 2100' \
    'custom cycle reset too early'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].total == 2100' \
    'lifetime total was reset'
assert_jq "${TRAFFIC_DIR}/state.json" '.ports["443"].disabled == false' \
    'port was not re-enabled after daily reset'
assert_no_file "${XRAY_CONF_DIR}/08_traffic_block_outbound.json"
assert_jq "${XRAY_CONF_DIR}/09_routing.json" '
    [.routing.rules[] | select(
        .outboundTag == "v2ray-agent-traffic-block"
        or .outboundTag == "traffic-block"
    )] | length == 0
' 'managed block rule was not removed'
grep -q '端口 443.*自动恢复' "${TRAFFIC_DIR}/alerts.log" || \
    fail 'automatic port recovery alert missing'

# A custom billing quota resets only on its configured billing day.
config_tmp=${TEST_ROOT}/config-billing.json
jq '.ports["443"].daily_limit = 0 | .ports["443"].billing_limit = 2000' \
    "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"
NOW_DATE=2026-09-14
NOW_EPOCH=1789344000
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '
    .ports["443"].billing.key == "2026-08-15"
    and .ports["443"].disabled == true
' 'custom billing limit was not enforced'

NOW_DATE=2026-09-15
NOW_EPOCH=1789430400
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '
    .ports["443"].billing.key == "2026-09-15"
    and .ports["443"].billing.bytes == 0
    and .ports["443"].disabled == false
' 'custom billing cycle did not reset and restore the port'

# Lifetime quota never resets automatically.
config_tmp=${TEST_ROOT}/config-total.json
jq '.ports["443"].billing_limit = 0 | .ports["443"].total_limit = 2000' \
    "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"
NOW_DATE=2026-10-01
NOW_EPOCH=1790812800
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '
    .ports["443"].total == 2100
    and .ports["443"].daily.bytes == 0
    and .ports["443"].monthly.bytes == 0
    and .ports["443"].disabled == true
' 'lifetime quota must remain enforced across resets'

# Reports preserve prior periods and identify ports rather than users.
report_path=$(run_monitor report daily previous false)
assert_file "${report_path}"
grep -q '"端口"' "${report_path}" || fail 'CSV port header is missing'
grep -q '443' "${report_path}" || fail 'previous daily report has no port data'
assert_file "${TRAFFIC_DIR}/reports/daily-2026-08-31.csv"

printf 'PASS: port traffic monitor tests\n'
