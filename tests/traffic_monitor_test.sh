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
    local target=$1 alice_tcp_up=$2 alice_tcp_down=$3 alice_ws_up=$4 alice_ws_down=$5
    jq -n \
        --argjson a "${alice_tcp_up}" --argjson b "${alice_tcp_down}" \
        --argjson c "${alice_ws_up}" --argjson d "${alice_ws_down}" '{
        stat: [
            {name: "user>>>alice-VLESS_TCP/TLS_Vision>>>traffic>>>uplink", value: $a},
            {name: "user>>>alice-VLESS_TCP/TLS_Vision>>>traffic>>>downlink", value: $b},
            {name: "user>>>alice-VMess_WS>>>traffic>>>uplink", value: $c},
            {name: "user>>>alice-VMess_WS>>>traffic>>>downlink", value: $d},
            {name: "user>>>bob-VLESS_TCP/TLS_Vision>>>traffic>>>uplink", value: 100}
        ]
    }' >"${target}"
}

mkdir -p "${XRAY_CONF_DIR}" "${TRAFFIC_DIR}"

jq -n '{
    inbounds: [{settings: {clients: [
        {id: "alice-uuid", email: "alice-VLESS_TCP/TLS_Vision"},
        {id: "bob-uuid", email: "bob-VLESS_TCP/TLS_Vision"}
    ]}}]
}' >"${XRAY_CONF_DIR}/02_VLESS_TCP_inbounds.json"

jq -n '{
    inbounds: [{settings: {clients: [
        {id: "alice-uuid", email: "alice-VMess_WS"},
        {id: "bob-uuid", email: "bob-VMess_WS"}
    ]}}]
}' >"${XRAY_CONF_DIR}/05_VMess_WS_inbounds.json"

jq -n '{policy: {levels: {"0": {handshake: 2, connIdle: 280}}}}' \
    >"${XRAY_CONF_DIR}/12_policy.json"
jq -n '{routing: {domainStrategy: "AsIs", rules: [
    {type: "field", protocol: ["bittorrent"], outboundTag: "blocked"}
]}}' >"${XRAY_CONF_DIR}/09_routing.json"

STATS_FILE=${TEST_ROOT}/stats-zero.json
write_stats "${STATS_FILE}" 0 0 0 0
NOW_DATE=2026-08-31
NOW_EPOCH=1788134400
run_monitor discover-users >/dev/null

config_tmp=${TEST_ROOT}/config.json
jq '
    .enabled = true
    | .alert_percent = 80
    | .auto_disable = true
    | .users.alice = {
        daily_limit: 2000,
        monthly_limit: 0,
        total_limit: 0,
        billing_limit: 0,
        billing_day: 15
      }
' "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"

# 80% threshold: aggregate two Xray identities into one logical user.
STATS_FILE=${TEST_ROOT}/stats-threshold.json
write_stats "${STATS_FILE}" 400 400 400 400
run_monitor collect

assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.total == 1600' \
    'protocol identities were not aggregated'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.daily.bytes == 1600' \
    'daily total is incorrect'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.monthly.bytes == 1600' \
    'monthly total is incorrect'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.billing.key == "2026-08-15"' \
    'custom billing key is incorrect'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.disabled == false' \
    'threshold warning must not disable user'
grep -q '达到 80%' "${TRAFFIC_DIR}/alerts.log" || fail 'threshold alert missing'
assert_no_file "${XRAY_CONF_DIR}/08_traffic_block_outbound.json"

# Polling the same absolute core counters must not count traffic twice.
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.total == 1600' \
    'unchanged core counters were counted twice'
[[ $(grep -c '达到 80%' "${TRAFFIC_DIR}/alerts.log") -eq 1 ]] || \
    fail 'threshold alert was emitted more than once'

# A lock left by a dead collector must not stop future collections.
mkdir "${TRAFFIC_DIR}/collect.lock"
printf '%s\n' '999999' >"${TRAFFIC_DIR}/collect.lock/pid"
run_monitor collect
assert_no_file "${TRAFFIC_DIR}/collect.lock"

# Crossing the daily limit blocks every protocol identity for the user.
STATS_FILE=${TEST_ROOT}/stats-limit.json
write_stats "${STATS_FILE}" 525 525 525 525
NOW_EPOCH=1788134700
run_monitor collect

assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.daily.bytes == 2100' \
    'second delta was not accumulated'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.disabled == true' \
    'over-limit user was not disabled'
assert_jq "${XRAY_CONF_DIR}/09_routing.json" '
    .routing.rules[0].outboundTag == "traffic-block"
    and (.routing.rules[0].user | sort) == ["alice-VLESS_TCP/TLS_Vision", "alice-VMess_WS"]
' 'block rule does not cover all identities'
assert_jq "${XRAY_CONF_DIR}/09_routing.json" '
    [.routing.rules[] | select(.outboundTag == "blocked")] | length == 1
' 'existing routing rule was lost'
assert_file "${XRAY_CONF_DIR}/08_traffic_block_outbound.json"
assert_jq "${XRAY_CONF_DIR}/12_policy.json" '
    .policy.levels["0"].handshake == 2
    and .policy.levels["0"].statsUserUplink == true
    and .policy.levels["0"].statsUserDownlink == true
' 'policy settings were not safely merged'

# Daily and natural-month periods reset, lifetime remains cumulative.
STATS_FILE=${TEST_ROOT}/stats-zero-next.json
write_stats "${STATS_FILE}" 0 0 0 0
NOW_DATE=2026-09-01
NOW_EPOCH=1788220800
run_monitor collect

assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.daily.bytes == 0' \
    'daily period did not reset'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.monthly.bytes == 0' \
    'monthly period did not reset'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.billing.bytes == 2100' \
    'custom cycle reset too early'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.total == 2100' \
    'lifetime total was reset'
assert_jq "${TRAFFIC_DIR}/state.json" '.users.alice.disabled == false' \
    'user was not re-enabled after daily reset'
assert_no_file "${XRAY_CONF_DIR}/08_traffic_block_outbound.json"
assert_jq "${XRAY_CONF_DIR}/09_routing.json" '
    [.routing.rules[] | select(.outboundTag == "traffic-block")] | length == 0
' 'managed block rule was not removed'

# A custom billing quota resets only on its configured billing day.
config_tmp=${TEST_ROOT}/config-billing.json
jq '.users.alice.daily_limit = 0 | .users.alice.billing_limit = 2000' \
    "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"
NOW_DATE=2026-09-14
NOW_EPOCH=1789344000
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '
    .users.alice.billing.key == "2026-08-15"
    and .users.alice.disabled == true
' 'custom billing limit was not enforced'

NOW_DATE=2026-09-15
NOW_EPOCH=1789430400
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '
    .users.alice.billing.key == "2026-09-15"
    and .users.alice.billing.bytes == 0
    and .users.alice.disabled == false
' 'custom billing cycle did not reset and restore the user'

# Lifetime quota never resets automatically.
config_tmp=${TEST_ROOT}/config-total.json
jq '.users.alice.billing_limit = 0 | .users.alice.total_limit = 2000' \
    "${TRAFFIC_DIR}/config.json" >"${config_tmp}"
mv "${config_tmp}" "${TRAFFIC_DIR}/config.json"
NOW_DATE=2026-10-01
NOW_EPOCH=1790812800
run_monitor collect
assert_jq "${TRAFFIC_DIR}/state.json" '
    .users.alice.total == 2100
    and .users.alice.daily.bytes == 0
    and .users.alice.monthly.bytes == 0
    and .users.alice.disabled == true
' 'lifetime quota must remain enforced across resets'

# Reports preserve prior periods and quote CSV output.
report_path=$(run_monitor report daily previous false)
assert_file "${report_path}"
grep -q 'alice' "${report_path}" || {
    printf 'report path: %s\n' "${report_path}" >&2
    sed -n '1,20p' "${report_path}" >&2
    jq '.history.daily' "${TRAFFIC_DIR}/state.json" >&2
    fail 'previous daily report has no user data'
}
assert_file "${TRAFFIC_DIR}/reports/daily-2026-08-31.csv"

printf 'PASS: traffic monitor tests\n'
