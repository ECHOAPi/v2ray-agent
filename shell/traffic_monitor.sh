#!/usr/bin/env bash

# Per-port traffic accounting for v2ray-agent.
# Xray exposes exact inbound counters through its loopback-only StatsService.

set -u
umask 077

AGENT_DIR=${V2RAY_AGENT_BASE_DIR:-/etc/v2ray-agent}
TRAFFIC_DIR=${V2RAY_AGENT_TRAFFIC_DIR:-${AGENT_DIR}/traffic}
CONFIG_FILE=${V2RAY_AGENT_TRAFFIC_CONFIG:-${TRAFFIC_DIR}/config.json}
STATE_FILE=${V2RAY_AGENT_TRAFFIC_STATE:-${TRAFFIC_DIR}/state.json}
REPORT_DIR=${V2RAY_AGENT_TRAFFIC_REPORT_DIR:-${TRAFFIC_DIR}/reports}
ALERT_LOG=${V2RAY_AGENT_TRAFFIC_ALERT_LOG:-${TRAFFIC_DIR}/alerts.log}
COLLECT_LOG=${V2RAY_AGENT_TRAFFIC_COLLECT_LOG:-${TRAFFIC_DIR}/collect.log}
SCRIPT_PATH=${V2RAY_AGENT_TRAFFIC_SCRIPT:-${TRAFFIC_DIR}/traffic_monitor.sh}

XRAY_BIN=${V2RAY_AGENT_XRAY_BIN:-${AGENT_DIR}/xray/xray}
XRAY_CONF_DIR=${V2RAY_AGENT_XRAY_CONF_DIR:-${AGENT_DIR}/xray/conf}
SING_BOX_BIN=${V2RAY_AGENT_SING_BOX_BIN:-${AGENT_DIR}/sing-box/sing-box}
SING_BOX_CONF=${V2RAY_AGENT_SING_BOX_CONF:-${AGENT_DIR}/sing-box/conf/config.json}

XRAY_POLICY_FILE=${XRAY_CONF_DIR}/12_policy.json
XRAY_ROUTING_FILE=${XRAY_CONF_DIR}/09_routing.json
XRAY_STATS_FILE=${XRAY_CONF_DIR}/13_traffic_stats.json
XRAY_BLOCK_OUTBOUND_FILE=${XRAY_CONF_DIR}/08_traffic_block_outbound.json
MANAGED_BLOCK_TAG=v2ray-agent-traffic-block
LEGACY_BLOCK_TAG=traffic-block
DEFAULT_API=127.0.0.1:10085
TEST_MODE=${V2RAY_AGENT_TEST_MODE:-0}
COLLECT_LOCK_DIR=

red='\033[31m'
green='\033[32m'
yellow='\033[33m'
skyBlue='\033[36m'
plain='\033[0m'

say() {
    printf '%b\n' "$*"
}

die() {
    say "${red} ---> $*${plain}" >&2
    return 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "缺少依赖：$1"
}

atomic_json_write() {
    local target=$1
    local temp_file
    temp_file=$(mktemp "${target}.tmp.XXXXXX") || return 1
    if ! jq . >"${temp_file}"; then
        rm -f -- "${temp_file}"
        return 1
    fi
    chmod 600 "${temp_file}"
    mv -f -- "${temp_file}" "${target}"
}

atomic_json_write_if_changed() {
    local target=$1
    local temp_file
    temp_file=$(mktemp "${target}.tmp.XXXXXX") || return 1
    if ! jq . >"${temp_file}"; then
        rm -f -- "${temp_file}"
        return 1
    fi
    if [[ -f "${target}" ]] && cmp -s "${temp_file}" "${target}"; then
        rm -f -- "${temp_file}"
        return 0
    fi
    chmod 600 "${temp_file}"
    mv -f -- "${temp_file}" "${target}"
}

atomic_copy() {
    local source=$1
    local target=$2
    local mode=${3:-600}
    local temp_file
    temp_file=$(mktemp "${target}.tmp.XXXXXX") || return 1
    cp -- "${source}" "${temp_file}" || {
        rm -f -- "${temp_file}"
        return 1
    }
    chmod "${mode}" "${temp_file}"
    mv -f -- "${temp_file}" "${target}"
}

ensure_storage() {
    local normalized
    need_command jq || return 1
    mkdir -p "${TRAFFIC_DIR}" "${REPORT_DIR}"
    chmod 700 "${TRAFFIC_DIR}" "${REPORT_DIR}"

    if [[ ! -f "${CONFIG_FILE}" ]]; then
        jq -n --arg api "${DEFAULT_API}" '{
            version: 2,
            enabled: false,
            core: "xray",
            api: $api,
            alert_percent: 80,
            auto_disable: true,
            scheduled_report: true,
            retention_days: 100,
            coverage: "xray-ports",
            notify: {
                type: "local",
                telegram_bot_token: "",
                telegram_chat_id: "",
                webhook_url: ""
            },
            ports: {}
        }' | atomic_json_write "${CONFIG_FILE}" || return 1
    else
        normalized=$(jq '
            .version = 2
            | .coverage = "xray-ports"
            | .ports = (.ports // {})
            | del(.users)
        ' "${CONFIG_FILE}") || return 1
        printf '%s' "${normalized}" |
            atomic_json_write_if_changed "${CONFIG_FILE}" || return 1
    fi

    if [[ ! -f "${STATE_FILE}" ]]; then
        jq -n '{
            version: 2,
            last_collect_at: 0,
            core_counters: {},
            ports: {},
            history: {daily: {}, monthly: {}, billing: {}},
            alerts: {}
        }' | atomic_json_write "${STATE_FILE}" || return 1
    else
        normalized=$(jq '
            if (.version // 0) < 2 then
                {
                    version: 2,
                    last_collect_at: 0,
                    core_counters: {},
                    ports: {},
                    history: {daily: {}, monthly: {}, billing: {}},
                    alerts: {}
                }
            else
                .version = 2
                | .ports = (.ports // {})
                | .history = (.history // {daily: {}, monthly: {}, billing: {}})
                | .alerts = (.alerts // {})
                | .core_counters = (.core_counters // {})
                | del(.users)
            end
        ' "${STATE_FILE}") || return 1
        printf '%s' "${normalized}" |
            atomic_json_write_if_changed "${STATE_FILE}" || return 1
    fi

    touch "${ALERT_LOG}" "${COLLECT_LOG}"
    chmod 600 "${CONFIG_FILE}" "${STATE_FILE}" "${ALERT_LOG}" "${COLLECT_LOG}"
}

config_enabled() {
    [[ $(jq -r '.enabled // false' "${CONFIG_FILE}" 2>/dev/null) == true ]]
}

today_key() {
    if [[ -n ${V2RAY_AGENT_NOW_DATE:-} ]]; then
        printf '%s\n' "${V2RAY_AGENT_NOW_DATE}"
    else
        date +%F
    fi
}

now_epoch() {
    if [[ -n ${V2RAY_AGENT_NOW_EPOCH:-} ]]; then
        printf '%s\n' "${V2RAY_AGENT_NOW_EPOCH}"
    else
        date +%s
    fi
}

billing_key() {
    local date_key=$1
    local billing_day=$2
    local year month day previous_month

    year=${date_key:0:4}
    month=${date_key:5:2}
    day=${date_key:8:2}
    year=$((10#${year}))
    month=$((10#${month}))
    day=$((10#${day}))

    if ((billing_day < 1 || billing_day > 28)); then
        billing_day=1
    fi
    if ((day < billing_day)); then
        previous_month=$((month - 1))
        if ((previous_month == 0)); then
            previous_month=12
            year=$((year - 1))
        fi
        month=${previous_month}
    fi
    printf '%04d-%02d-%02d\n' "${year}" "${month}" "${billing_day}"
}

human_bytes() {
    awk -v bytes="${1:-0}" 'BEGIN {
        split("B KiB MiB GiB TiB PiB", unit, " ");
        value = bytes + 0; unit_index = 1;
        while (value >= 1024 && unit_index < 6) { value /= 1024; unit_index++ }
        if (unit_index == 1) printf "%.0f %s", value, unit[unit_index];
        else printf "%.2f %s", value, unit[unit_index];
    }'
}

bytes_to_gib() {
    awk -v bytes="${1:-0}" 'BEGIN { printf "%.2f", bytes / 1073741824 }'
}

gib_to_bytes() {
    local value=${1:-0}
    if [[ ! ${value} =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        return 1
    fi
    awk -v gib="${value}" 'BEGIN { printf "%.0f", gib * 1073741824 }'
}

valid_api_address() {
    local api=$1
    local port
    [[ ${api} =~ ^127[.]0[.]0[.]1:([0-9]{1,5})$ ]] || return 1
    port=${BASH_REMATCH[1]}
    ((10#${port} >= 1 && 10#${port} <= 65535))
}

discover_inbounds() {
    local file tag port inbound_lines
    [[ -d "${XRAY_CONF_DIR}" ]] || return 0
    for file in "${XRAY_CONF_DIR}"/*.json; do
        [[ -f "${file}" ]] || continue
        inbound_lines=$(jq -r '
            .inbounds[]?
            | select(
                .tag != null
                and (.tag | tostring | length) > 0
                and (
                    (.port | type) == "number"
                    or (
                        (.port | type) == "string"
                        and (.port | test("^[0-9]+$"))
                    )
                )
              )
            | (.port | tonumber) as $port
            | select($port >= 1 and $port <= 65535)
            | [(.tag | tostring), ($port | tostring)]
            | @tsv
        ' "${file}" 2>/dev/null || true)
        while IFS=$'\t' read -r tag port; do
            [[ -n ${tag} && -n ${port} ]] || continue
            printf '%s\t%s\n' "${tag}" "${port}"
        done <<<"${inbound_lines}"
    done | sort -u
}

inbound_json() {
    discover_inbounds | jq -R -s '
        split("\n")
        | map(select(length > 0) | split("\t") | {tag: .[0], port: .[1]})
        | unique_by(.tag)
    '
}

all_port_json() {
    local inbounds=$1
    local deltas
    deltas=${2-}
    [[ -n ${deltas} ]] || deltas='{}'
    jq -n \
        --argjson inbounds "${inbounds}" \
        --argjson deltas "${deltas}" \
        --slurpfile config "${CONFIG_FILE}" \
        --slurpfile state "${STATE_FILE}" '
        (([$inbounds[].port]
          + (($config[0].ports // {}) | keys)
          + (($state[0].ports // {}) | keys)
          + ($deltas | keys)) | unique | sort)
    '
}

query_xray_stats() {
    local api
    if [[ -n ${V2RAY_AGENT_STATS_FILE:-} ]]; then
        command cat -- "${V2RAY_AGENT_STATS_FILE}"
        return
    fi
    api=$(jq -r '.api // "127.0.0.1:10085"' "${CONFIG_FILE}")
    if ! valid_api_address "${api}"; then
        die "StatsService 地址必须是 127.0.0.1:1-65535"
        return 1
    fi
    "${XRAY_BIN}" api statsquery --server="${api}" -pattern 'inbound>>>'
}

aggregate_stats() {
    local raw_stats=$1
    local inbounds=$2
    local previous_counters
    previous_counters=$(jq '.core_counters // {}' "${STATE_FILE}")
    printf '%s' "${raw_stats}" | jq \
        --argjson inbounds "${inbounds}" \
        --argjson previous "${previous_counters}" '
        ($inbounds | reduce .[] as $item ({}; .[$item.tag] = $item.port)) as $tag_map
        | (reduce (
            .stat[]?
            | select(.name | test("^inbound>>>.*>>>traffic>>>(uplink|downlink)$"))
          ) as $stat ({}; .[$stat.name] = ($stat.value | tonumber))) as $counters
        | (reduce ($counters | to_entries[]) as $counter ({};
            ($counter.key
             | capture("^inbound>>>(?<tag>.*)>>>traffic>>>(?<direction>uplink|downlink)$").tag
            ) as $tag
            | ($tag_map[$tag] // "") as $port
            | ($previous[$counter.key] // 0) as $old_value
            | (if $counter.value >= $old_value
               then ($counter.value - $old_value)
               else $counter.value end) as $delta
            | if ($port | length) > 0 then
                .[$port] = ((.[$port] // 0) + $delta)
              else . end
          )) as $deltas
        | {counters: $counters, deltas: $deltas}
    '
}

build_billing_keys() {
    local ports=$1
    local day_key=$2
    local result='{}'
    local port billing_day key port_lines
    port_lines=$(jq -r '.[]' <<<"${ports}")
    while IFS= read -r port; do
        [[ -n ${port} ]] || continue
        billing_day=$(jq -r --arg port "${port}" '.ports[$port].billing_day // 1' "${CONFIG_FILE}")
        if [[ ! ${billing_day} =~ ^[0-9]+$ ]] || ((billing_day < 1 || billing_day > 28)); then
            billing_day=1
        fi
        key=$(billing_key "${day_key}" "${billing_day}")
        result=$(jq --arg port "${port}" --arg key "${key}" '.[$port] = $key' <<<"${result}")
    done <<<"${port_lines}"
    printf '%s\n' "${result}"
}

update_state() {
    local deltas=$1
    local inbounds=$2
    local counters=$3
    local day_key month_key epoch ports billing_keys config state retention

    day_key=$(today_key)
    month_key=${day_key:0:7}
    epoch=$(now_epoch)
    ports=$(all_port_json "${inbounds}" "${deltas}")
    billing_keys=$(build_billing_keys "${ports}" "${day_key}")
    config=$(command cat "${CONFIG_FILE}")
    state=$(command cat "${STATE_FILE}")
    retention=$(jq -r '.retention_days // 100' "${CONFIG_FILE}")
    if [[ ! ${retention} =~ ^[0-9]+$ ]] || ((retention < 7)); then
        retention=100
    fi

    jq -n \
        --argjson old "${state}" \
        --argjson config "${config}" \
        --argjson deltas "${deltas}" \
        --argjson counters "${counters}" \
        --argjson ports "${ports}" \
        --argjson billing_keys "${billing_keys}" \
        --arg day "${day_key}" \
        --arg month "${month_key}" \
        --argjson now "${epoch}" \
        --argjson retention "${retention}" '
        def blank_port($day; $month; $billing): {
            total: 0,
            daily: {key: $day, bytes: 0},
            monthly: {key: $month, bytes: 0},
            billing: {key: $billing, bytes: 0},
            disabled: false,
            disabled_reasons: []
        };
        def keep_last($count):
            to_entries | sort_by(.key)
            | if length > $count then .[-$count:] else . end
            | from_entries;
        def quota_rows($cfg; $usage): [
            {period: "daily", key: $usage.daily.key, used: $usage.daily.bytes,
             limit: ($cfg.daily_limit // 0)},
            {period: "monthly", key: $usage.monthly.key, used: $usage.monthly.bytes,
             limit: ($cfg.monthly_limit // 0)},
            {period: "billing", key: $usage.billing.key, used: $usage.billing.bytes,
             limit: ($cfg.billing_limit // 0)},
            {period: "total", key: "lifetime", used: $usage.total,
             limit: ($cfg.total_limit // 0)}
        ];

        ($old
         | .version = 2
         | .last_collect_at = $now
         | .core_counters = $counters
         | .ports = (.ports // {})
         | .history = (.history // {daily: {}, monthly: {}, billing: {}})
         | .history.daily = (.history.daily // {})
         | .history.monthly = (.history.monthly // {})
         | .history.billing = (.history.billing // {})
         | .alerts = (.alerts // {})
         | del(.users)
        ) as $initial
        | reduce $ports[] as $port ($initial;
            ($deltas[$port] // 0) as $delta
            | ($billing_keys[$port] // ($day + "-01")) as $billing
            | (.ports[$port] // blank_port($day; $month; $billing)) as $previous
            | .ports[$port] = (
                $previous
                | .total = ((.total // 0) + $delta)
                | .daily = if .daily.key == $day
                    then {key: $day, bytes: ((.daily.bytes // 0) + $delta)}
                    else {key: $day, bytes: $delta} end
                | .monthly = if .monthly.key == $month
                    then {key: $month, bytes: ((.monthly.bytes // 0) + $delta)}
                    else {key: $month, bytes: $delta} end
                | .billing = if .billing.key == $billing
                    then {key: $billing, bytes: ((.billing.bytes // 0) + $delta)}
                    else {key: $billing, bytes: $delta} end
            )
            | .history.daily[$day][$port] = .ports[$port].daily.bytes
            | .history.monthly[$month][$port] = .ports[$port].monthly.bytes
            | .history.billing[$billing][$port] = .ports[$port].billing.bytes
        )
        | .history.daily |= keep_last($retention)
        | .history.monthly |= keep_last(36)
        | .history.billing |= keep_last(36)
        | reduce $ports[] as $port (.;
            ($config.ports[$port] // {}) as $cfg
            | quota_rows($cfg; .ports[$port]) as $rows
            | .ports[$port].disabled_reasons = [
                $rows[] | select((.limit // 0) > 0 and .used >= .limit) | .period
              ]
            | .ports[$port].disabled = (
                ($config.auto_disable // true)
                and ((.ports[$port].disabled_reasons | length) > 0)
              )
        )
        | . as $next
        | [
            $ports[] as $port
            | ($config.ports[$port] // {}) as $cfg
            | quota_rows($cfg; $next.ports[$port])[]
            | select((.limit // 0) > 0)
            | (.used * 100 / .limit) as $percent
            | select($percent >= ($config.alert_percent // 80))
            | . + {
                type: "quota",
                port: $port,
                percent: $percent,
                stage: (if .used >= .limit then "limit" else "threshold" end)
              }
            | .id = ([.port, .period, .key, .stage] | join("|"))
            | select(($next.alerts[.id] // 0) == 0)
          ] as $quota_events
        | [
            $ports[] as $port
            | (($old.ports[$port].disabled // false) !=
               ($next.ports[$port].disabled // false)) as $changed
            | select($changed)
            | {
                id: (["status", $port, ($now | tostring)] | join("|")),
                type: "status",
                port: $port,
                disabled: ($next.ports[$port].disabled // false),
                reasons: ($next.ports[$port].disabled_reasons // [])
              }
          ] as $status_events
        | reduce $quota_events[] as $event ($next;
            .alerts[$event.id] = $now
          )
        | .alerts |= with_entries(select(.value >= ($now - 15552000)))
        | {state: ., events: ($quota_events + $status_events)}
    '
}

period_label() {
    case $1 in
    daily) printf '每日' ;;
    monthly) printf '自然月' ;;
    billing) printf '自定义结算周期' ;;
    total) printf '累计' ;;
    *) printf '%s' "$1" ;;
    esac
}

valid_webhook_url() {
    [[ $1 =~ ^https://[^[:space:]\"]+$ ]]
}

notify_message() {
    local kind=$1
    local message=$2
    local notify_type token chat_id url payload
    printf '%s [%s] %s\n' "$(date '+%F %T')" "${kind}" "${message}" >>"${ALERT_LOG}"

    notify_type=$(jq -r '.notify.type // "local"' "${CONFIG_FILE}")
    case ${notify_type} in
    telegram)
        token=$(jq -r '.notify.telegram_bot_token // ""' "${CONFIG_FILE}")
        chat_id=$(jq -r '.notify.telegram_chat_id // ""' "${CONFIG_FILE}")
        [[ ${token} =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || return 0
        [[ ${chat_id} =~ ^[-@A-Za-z0-9_]+$ ]] || return 0
        command -v curl >/dev/null 2>&1 || return 0
        printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "${token}" |
            curl --config - --fail --silent --show-error --max-time 10 \
                --data-urlencode "chat_id=${chat_id}" \
                --data-urlencode "text=${message}" \
                >/dev/null 2>>"${ALERT_LOG}" || true
        ;;
    webhook)
        url=$(jq -r '.notify.webhook_url // ""' "${CONFIG_FILE}")
        valid_webhook_url "${url}" || return 0
        command -v curl >/dev/null 2>&1 || return 0
        payload=$(jq -n --arg type "${kind}" --arg message "${message}" \
            --argjson timestamp "$(now_epoch)" \
            '{type: $type, message: $message, timestamp: $timestamp}')
        printf 'url = "%s"\n' "${url}" |
            curl --config - --fail --silent --show-error --max-time 10 \
                -H 'Content-Type: application/json' --data "${payload}" \
                >/dev/null 2>>"${ALERT_LOG}" || true
        ;;
    esac
}

dispatch_events() {
    local events=$1
    local event type port period key stage used limit percent reasons message event_lines
    event_lines=$(jq -c '.[]' <<<"${events}")
    while IFS= read -r event; do
        [[ -n ${event} ]] || continue
        type=$(jq -r '.type // "quota"' <<<"${event}")
        port=$(jq -r '.port' <<<"${event}")
        if [[ ${type} == status ]]; then
            if [[ $(jq -r '.disabled' <<<"${event}") == true ]]; then
                reasons=$(jq -r '.reasons | map(
                    if . == "daily" then "每日"
                    elif . == "monthly" then "自然月"
                    elif . == "billing" then "自定义结算周期"
                    elif . == "total" then "累计"
                    else . end
                ) | join("、")' <<<"${event}")
                message="[v2ray-agent] 端口 ${port} 已因流量超额自动停用（${reasons}）"
            else
                message="[v2ray-agent] 端口 ${port} 的结算周期已重置，端口已自动恢复"
            fi
            notify_message status "${message}"
            continue
        fi

        period=$(jq -r '.period' <<<"${event}")
        key=$(jq -r '.key' <<<"${event}")
        stage=$(jq -r '.stage' <<<"${event}")
        used=$(jq -r '.used' <<<"${event}")
        limit=$(jq -r '.limit' <<<"${event}")
        percent=$(jq -r '.percent | floor' <<<"${event}")
        if [[ ${stage} == limit ]]; then
            message="[v2ray-agent] 端口 ${port} 的$(period_label "${period}")流量已超额：$(human_bytes "${used}") / $(human_bytes "${limit}")（周期 ${key}）"
        else
            message="[v2ray-agent] 端口 ${port} 的$(period_label "${period}")流量已达到 ${percent}%：$(human_bytes "${used}") / $(human_bytes "${limit}")（周期 ${key}）"
        fi
        notify_message quota "${message}"
    done <<<"${event_lines}"
}

restart_xray() {
    if [[ ${TEST_MODE} == 1 || ${V2RAY_AGENT_NO_RESTART:-0} == 1 ]]; then
        return 0
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray.service; then
        systemctl restart xray.service
    elif command -v rc-service >/dev/null 2>&1 && rc-service xray status >/dev/null 2>&1; then
        rc-service xray restart
    else
        say "${yellow} ---> Xray 配置已更新；未检测到受支持的服务管理器，请手动重启 Xray${plain}"
    fi
}

sync_xray_config() {
    local temp_dir inbounds disabled_ports blocked_tags api changed=false
    local file relative

    ensure_storage || return 1
    [[ -d "${XRAY_CONF_DIR}" ]] || return 0
    inbounds=$(inbound_json)
    disabled_ports=$(jq '[.ports | to_entries[]? | select(.value.disabled == true) | .key]' "${STATE_FILE}")
    blocked_tags=$(jq -n --argjson inbounds "${inbounds}" --argjson ports "${disabled_ports}" '
        [$inbounds[]
         | . as $item
         | select($ports | index($item.port))
         | $item.tag]
        | unique
    ')
    api=$(jq -r '.api // "127.0.0.1:10085"' "${CONFIG_FILE}")
    if ! valid_api_address "${api}"; then
        die "StatsService 地址必须是 127.0.0.1:1-65535"
        return 1
    fi

    temp_dir=$(mktemp -d "${TRAFFIC_DIR}/xray-conf.XXXXXX") || return 1
    for file in "${XRAY_CONF_DIR}"/*.json; do
        [[ -f "${file}" ]] || continue
        cp -- "${file}" "${temp_dir}/"
    done

    if [[ ! -f "${temp_dir}/12_policy.json" ]]; then
        printf '%s\n' '{"policy":{"system":{}}}' >"${temp_dir}/12_policy.json"
    fi
    jq '
        .policy = (.policy // {})
        | .policy.system = (.policy.system // {})
        | .policy.system.statsInboundUplink = true
        | .policy.system.statsInboundDownlink = true
    ' "${temp_dir}/12_policy.json" >"${temp_dir}/12_policy.json.new" || {
        rm -rf -- "${temp_dir}"
        return 1
    }
    mv -f -- "${temp_dir}/12_policy.json.new" "${temp_dir}/12_policy.json"

    jq -n --arg api "${api}" '{
        stats: {},
        api: {tag: "traffic-api", listen: $api, services: ["StatsService"]}
    }' >"${temp_dir}/13_traffic_stats.json"

    if [[ ! -f "${temp_dir}/09_routing.json" ]]; then
        printf '%s\n' '{"routing":{"rules":[]}}' >"${temp_dir}/09_routing.json"
    fi
    jq --argjson tags "${blocked_tags}" \
        --arg tag "${MANAGED_BLOCK_TAG}" --arg legacy "${LEGACY_BLOCK_TAG}" '
        .routing = (.routing // {})
        | .routing.rules = ([
            .routing.rules[]?
            | select(.outboundTag != $tag and .outboundTag != $legacy)
          ])
        | if ($tags | length) > 0 then
            .routing.rules = ([{
                type: "field",
                inboundTag: $tags,
                outboundTag: $tag
            }] + .routing.rules)
          else . end
    ' "${temp_dir}/09_routing.json" >"${temp_dir}/09_routing.json.new" || {
        rm -rf -- "${temp_dir}"
        return 1
    }
    mv -f -- "${temp_dir}/09_routing.json.new" "${temp_dir}/09_routing.json"

    if [[ $(jq 'length' <<<"${blocked_tags}") -gt 0 ]]; then
        jq -n --arg tag "${MANAGED_BLOCK_TAG}" '{
            outbounds: [{tag: $tag, protocol: "blackhole", settings: {response: {type: "none"}}}]
        }' >"${temp_dir}/08_traffic_block_outbound.json"
    else
        rm -f -- "${temp_dir}/08_traffic_block_outbound.json"
    fi

    if [[ ${TEST_MODE} != 1 ]]; then
        if [[ ! -x "${XRAY_BIN}" ]]; then
            rm -rf -- "${temp_dir}"
            die "未找到可执行的 Xray 核心：${XRAY_BIN}"
            return 1
        fi
        if ! "${XRAY_BIN}" run -test -confdir "${temp_dir}" >/dev/null 2>&1; then
            rm -rf -- "${temp_dir}"
            die "端口流量监控配置未通过 Xray 校验，原配置未改动"
            return 1
        fi
    fi

    for relative in 12_policy.json 09_routing.json 13_traffic_stats.json; do
        if [[ ! -f "${XRAY_CONF_DIR}/${relative}" ]] ||
            ! cmp -s "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}"; then
            atomic_copy "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}" 644 || {
                rm -rf -- "${temp_dir}"
                return 1
            }
            changed=true
        fi
    done
    relative=08_traffic_block_outbound.json
    if [[ -f "${temp_dir}/${relative}" ]]; then
        if [[ ! -f "${XRAY_CONF_DIR}/${relative}" ]] ||
            ! cmp -s "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}"; then
            atomic_copy "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}" 644 || {
                rm -rf -- "${temp_dir}"
                return 1
            }
            changed=true
        fi
    elif [[ -f "${XRAY_CONF_DIR}/${relative}" ]]; then
        rm -f -- "${XRAY_CONF_DIR}/${relative}"
        changed=true
    fi
    rm -rf -- "${temp_dir}"

    if [[ ${changed} == true ]]; then
        restart_xray
    fi
}

remove_managed_xray_config() {
    local temp_file changed=false
    [[ -d "${XRAY_CONF_DIR}" ]] || return 0
    if [[ -f "${XRAY_ROUTING_FILE}" ]]; then
        temp_file=$(mktemp "${XRAY_ROUTING_FILE}.tmp.XXXXXX") || return 1
        jq --arg tag "${MANAGED_BLOCK_TAG}" --arg legacy "${LEGACY_BLOCK_TAG}" '
            .routing.rules = ([
                .routing.rules[]?
                | select(.outboundTag != $tag and .outboundTag != $legacy)
            ])
        ' "${XRAY_ROUTING_FILE}" >"${temp_file}" || {
            rm -f -- "${temp_file}"
            return 1
        }
        if ! cmp -s "${temp_file}" "${XRAY_ROUTING_FILE}"; then
            chmod 644 "${temp_file}"
            mv -f -- "${temp_file}" "${XRAY_ROUTING_FILE}"
            changed=true
        else
            rm -f -- "${temp_file}"
        fi
    fi
    if [[ -f "${XRAY_STATS_FILE}" ]]; then
        rm -f -- "${XRAY_STATS_FILE}"
        changed=true
    fi
    if [[ -f "${XRAY_BLOCK_OUTBOUND_FILE}" ]]; then
        rm -f -- "${XRAY_BLOCK_OUTBOUND_FILE}"
        changed=true
    fi
    if [[ ${changed} == true ]]; then
        restart_xray
    fi
}

cleanup_collect_lock() {
    if [[ -n ${COLLECT_LOCK_DIR} ]]; then
        rm -f -- "${COLLECT_LOCK_DIR}/pid"
        rmdir "${COLLECT_LOCK_DIR}" 2>/dev/null || true
        COLLECT_LOCK_DIR=
    fi
}

release_collect_lock() {
    cleanup_collect_lock
    trap - EXIT INT TERM
}

acquire_collect_lock() {
    local owner_pid=
    COLLECT_LOCK_DIR=${TRAFFIC_DIR}/collect.lock
    if mkdir "${COLLECT_LOCK_DIR}" 2>/dev/null; then
        printf '%s\n' "$$" >"${COLLECT_LOCK_DIR}/pid"
        return 0
    fi
    if [[ -f "${COLLECT_LOCK_DIR}/pid" ]]; then
        owner_pid=$(command cat "${COLLECT_LOCK_DIR}/pid" 2>/dev/null || true)
    fi
    if [[ ${owner_pid} =~ ^[0-9]+$ ]] && kill -0 "${owner_pid}" 2>/dev/null; then
        COLLECT_LOCK_DIR=
        return 1
    fi
    rm -f -- "${COLLECT_LOCK_DIR}/pid"
    rmdir "${COLLECT_LOCK_DIR}" 2>/dev/null || true
    if mkdir "${COLLECT_LOCK_DIR}" 2>/dev/null; then
        printf '%s\n' "$$" >"${COLLECT_LOCK_DIR}/pid"
        return 0
    fi
    COLLECT_LOCK_DIR=
    return 1
}

collect() {
    local raw_stats inbounds stats_result counters deltas result old_state new_state events
    ensure_storage || return 1
    config_enabled || return 0

    if ! acquire_collect_lock; then
        return 0
    fi
    trap cleanup_collect_lock EXIT
    trap 'cleanup_collect_lock; exit 130' INT
    trap 'cleanup_collect_lock; exit 143' TERM

    inbounds=$(inbound_json)
    if ! raw_stats=$(query_xray_stats 2>>"${COLLECT_LOG}"); then
        printf '%s stats query failed\n' "$(date '+%F %T')" >>"${COLLECT_LOG}"
        release_collect_lock
        return 1
    fi
    if ! stats_result=$(aggregate_stats "${raw_stats}" "${inbounds}" 2>>"${COLLECT_LOG}"); then
        printf '%s invalid stats response\n' "$(date '+%F %T')" >>"${COLLECT_LOG}"
        release_collect_lock
        return 1
    fi
    counters=$(jq '.counters' <<<"${stats_result}")
    deltas=$(jq '.deltas' <<<"${stats_result}")
    old_state=$(command cat "${STATE_FILE}")
    if ! result=$(update_state "${deltas}" "${inbounds}" "${counters}"); then
        release_collect_lock
        return 1
    fi
    new_state=$(jq '.state' <<<"${result}")
    events=$(jq '.events' <<<"${result}")
    if ! printf '%s' "${new_state}" | atomic_json_write "${STATE_FILE}"; then
        release_collect_lock
        return 1
    fi

    if ! sync_xray_config; then
        printf '%s' "${old_state}" | atomic_json_write "${STATE_FILE}"
        release_collect_lock
        return 1
    fi
    generate_report daily current false >/dev/null
    dispatch_events "${events}"
    release_collect_lock
}

report_usage_json() {
    local period=$1
    local selector=${2:-current}
    local current key
    current=$(today_key)
    case ${period} in
    daily)
        key=${current}
        if [[ ${selector} == previous ]]; then
            key=$(jq -r --arg current "${current}" '
                [.history.daily | keys[] | select(. != $current)] | sort | last // empty
            ' "${STATE_FILE}")
        fi
        [[ -n ${key} ]] || key=${current}
        jq -n --arg key "${key}" --slurpfile state "${STATE_FILE}" '{
            key: $key,
            usage: ($state[0].history.daily[$key] // {})
        }'
        ;;
    monthly)
        current=${current:0:7}
        key=${current}
        if [[ ${selector} == previous ]]; then
            key=$(jq -r --arg current "${current}" '
                [.history.monthly | keys[] | select(. != $current)] | sort | last // empty
            ' "${STATE_FILE}")
        fi
        [[ -n ${key} ]] || key=${current}
        jq -n --arg key "${key}" --slurpfile state "${STATE_FILE}" '{
            key: $key,
            usage: ($state[0].history.monthly[$key] // {})
        }'
        ;;
    billing)
        jq -n --slurpfile state "${STATE_FILE}" '{
            key: "current",
            usage: ($state[0].ports | with_entries(.value = {
                bytes: (.value.billing.bytes // 0),
                cycle: (.value.billing.key // "")
            }))
        }'
        ;;
    total)
        jq -n --slurpfile state "${STATE_FILE}" '{
            key: "lifetime",
            usage: ($state[0].ports | with_entries(.value = (.value.total // 0)))
        }'
        ;;
    *)
        die "未知报告类型：${period}"
        return 1
        ;;
    esac
}

generate_report() {
    local period=${1:-daily}
    local selector=${2:-current}
    local should_notify=${3:-false}
    local report_data key usage output summary
    ensure_storage || return 1
    report_data=$(report_usage_json "${period}" "${selector}") || return 1
    key=$(jq -r '.key' <<<"${report_data}")
    usage=$(jq '.usage' <<<"${report_data}")
    output=${REPORT_DIR}/${period}-${key}.csv

    if [[ ${period} == billing ]]; then
        jq -r -n --argjson usage "${usage}" --slurpfile state "${STATE_FILE}" '
            ["端口", "周期起始", "字节", "GiB", "状态"] | @csv,
            ($usage | to_entries | sort_by(.key)[]
             | [.key, .value.cycle, .value.bytes,
                ((.value.bytes / 1073741824 * 100 | round) / 100),
                (if ($state[0].ports[.key].disabled // false) then "已停用" else "正常" end)]
             | @csv)
        ' >"${output}"
    else
        jq -r -n --argjson usage "${usage}" --slurpfile state "${STATE_FILE}" '
            ["端口", "字节", "GiB", "状态"] | @csv,
            ($usage | to_entries | sort_by(-.value)[]
             | [.key, .value, ((.value / 1073741824 * 100 | round) / 100),
                (if ($state[0].ports[.key].disabled // false) then "已停用" else "正常" end)]
             | @csv)
        ' >"${output}"
    fi
    chmod 600 "${output}"

    if [[ ${should_notify} == true ]]; then
        summary=$(jq -r --arg period "$(period_label "${period}")" --arg key "${key}" '
            def amount: if (.value | type) == "object" then .value.bytes else .value end;
            to_entries | sort_by(-(amount)) | .[0:5]
            | map("端口 \(.key): \(((amount / 1073741824 * 100 | round) / 100)) GiB")
            | "[v2ray-agent] \($period)端口流量报告（\($key)）\n" + join("\n")
        ' <<<"${usage}")
        notify_message report "${summary}"
    fi
    printf '%s\n' "${output}"
}

install_cron() {
    local existing filtered
    if [[ ${TEST_MODE} == 1 ]]; then
        return 0
    fi
    if ! command -v crontab >/dev/null 2>&1; then
        say "${yellow} ---> 未找到 crontab；请手动每分钟执行 ${SCRIPT_PATH} collect${plain}"
        return 0
    fi
    existing=$(crontab -l 2>/dev/null || true)
    filtered=$(printf '%s\n' "${existing}" | sed '/# v2ray-agent-traffic/d')
    {
        printf '%s\n' "${filtered}"
        printf '%s\n' "* * * * * /bin/bash ${SCRIPT_PATH} collect >> ${COLLECT_LOG} 2>&1 # v2ray-agent-traffic"
        printf '%s\n' "5 0 * * * /bin/bash ${SCRIPT_PATH} report daily previous notify >> ${COLLECT_LOG} 2>&1 # v2ray-agent-traffic"
    } | crontab -
}

remove_cron() {
    local existing
    if [[ ${TEST_MODE} == 1 ]] || ! command -v crontab >/dev/null 2>&1; then
        return 0
    fi
    existing=$(crontab -l 2>/dev/null || true)
    printf '%s\n' "${existing}" | sed '/# v2ray-agent-traffic/d' | crontab -
}

enable_monitor() {
    local allow_partial=${1:-false}
    ensure_storage || return 1
    if [[ ! -x "${XRAY_BIN}" || ! -d "${XRAY_CONF_DIR}" ]]; then
        if [[ -x "${SING_BOX_BIN}" ]]; then
            die "sing-box 官方发布包未编入 with_v2ray_api，无法可靠统计入站端口流量；当前未启用此功能"
        else
            die "未检测到 Xray 安装"
        fi
        return 1
    fi
    if [[ -f "${SING_BOX_CONF}" && ${allow_partial} != true ]]; then
        die "检测到同时运行的 sing-box 协议；请显式选择“仅监控 Xray 端口”后继续"
        return 1
    fi

    jq '.enabled = true | .core = "xray"' "${CONFIG_FILE}" |
        atomic_json_write "${CONFIG_FILE}" || return 1
    sync_xray_config || {
        jq '.enabled = false' "${CONFIG_FILE}" | atomic_json_write "${CONFIG_FILE}"
        return 1
    }
    install_cron
    say "${green} ---> 端口流量监控已启用${plain}"
    if [[ -f "${SING_BOX_CONF}" ]]; then
        say "${yellow} ---> 当前只统计 Xray 入站端口，sing-box 端口不会计入额度${plain}"
    fi
    if ! collect; then
        say "${yellow} ---> 首次采集失败，定时任务将在下一分钟重试${plain}"
    fi
}

disable_monitor() {
    ensure_storage || return 1
    jq '.enabled = false' "${CONFIG_FILE}" | atomic_json_write "${CONFIG_FILE}" || return 1
    remove_cron
    if ! remove_managed_xray_config; then
        die "移除端口流量监控核心配置失败，请检查 Xray 配置"
        return 1
    fi
    say "${green} ---> 端口流量监控已停用，历史数据已保留，端口限制已解除${plain}"
}

display_usage() {
    local port daily monthly billing total status billing_cycle port_lines
    ensure_storage || return 1
    port_lines=$(jq -r '.ports | keys[]' "${STATE_FILE}")
    if [[ -z ${port_lines} ]]; then
        say "${yellow} ---> 暂无端口流量数据，请先启用并采集${plain}"
        return 0
    fi
    printf '\n%-12s %-12s %-12s %-12s %-12s %-8s\n' \
        "端口" "今日" "本月" "结算周期" "累计" "状态"
    printf '%s\n' '------------------------------------------------------------------------'
    while IFS= read -r port; do
        [[ -n ${port} ]] || continue
        daily=$(jq -r --arg port "${port}" '.ports[$port].daily.bytes // 0' "${STATE_FILE}")
        monthly=$(jq -r --arg port "${port}" '.ports[$port].monthly.bytes // 0' "${STATE_FILE}")
        billing=$(jq -r --arg port "${port}" '.ports[$port].billing.bytes // 0' "${STATE_FILE}")
        billing_cycle=$(jq -r --arg port "${port}" '.ports[$port].billing.key // "-"' "${STATE_FILE}")
        total=$(jq -r --arg port "${port}" '.ports[$port].total // 0' "${STATE_FILE}")
        if [[ $(jq -r --arg port "${port}" '.ports[$port].disabled // false' "${STATE_FILE}") == true ]]; then
            status=已停用
        else
            status=正常
        fi
        printf '%-12s %-12s %-12s %-12s %-12s %-8s\n' \
            "${port}" "$(human_bytes "${daily}")" "$(human_bytes "${monthly}")" \
            "$(human_bytes "${billing}")" "$(human_bytes "${total}")" "${status}"
        printf '  自定义周期起始：%s\n' "${billing_cycle}"
    done <<<"${port_lines}"
}

select_port() {
    local inbounds ports index i=1 port tag_list port_lines
    inbounds=$(inbound_json)
    ports=$(all_port_json "${inbounds}" '{}')
    if [[ $(jq 'length' <<<"${ports}") -eq 0 ]]; then
        die "未发现 Xray 入站端口"
        return 1
    fi
    port_lines=$(jq -r '.[]' <<<"${ports}")
    while IFS= read -r port; do
        tag_list=$(jq -r --arg port "${port}" '
            [.[] | select(.port == $port) | .tag] | unique | join(", ")
        ' <<<"${inbounds}")
        [[ -n ${tag_list} ]] || tag_list=仅存在于配置或历史
        printf '%d.%s（%s）\n' "${i}" "${port}" "${tag_list}" >&2
        i=$((i + 1))
    done <<<"${port_lines}"
    read -r -p '请选择端口编号：' index
    if [[ ! ${index} =~ ^[0-9]+$ ]] || ((index < 1 || index > i - 1)); then
        die "选择错误"
        return 1
    fi
    jq -r ".[$((index - 1))]" <<<"${ports}"
}

read_limit() {
    local label=$1 current=$2 input bytes
    read -r -p "${label} GiB（0 表示不限，回车保留 $(bytes_to_gib "${current}")）：" input
    if [[ -z ${input} ]]; then
        printf '%s\n' "${current}"
        return
    fi
    if ! bytes=$(gib_to_bytes "${input}"); then
        die "请输入非负数字"
        return 1
    fi
    printf '%s\n' "${bytes}"
}

configure_port() {
    local port current daily monthly billing total billing_day input temp
    ensure_storage || return 1
    port=$(select_port) || return 1
    current=$(jq -c --arg port "${port}" '.ports[$port] // {}' "${CONFIG_FILE}")
    daily=$(read_limit '每日额度' "$(jq -r '.daily_limit // 0' <<<"${current}")") || return 1
    monthly=$(read_limit '自然月额度' "$(jq -r '.monthly_limit // 0' <<<"${current}")") || return 1
    total=$(read_limit '累计额度' "$(jq -r '.total_limit // 0' <<<"${current}")") || return 1
    billing=$(read_limit '自定义结算周期额度' "$(jq -r '.billing_limit // 0' <<<"${current}")") || return 1
    billing_day=$(jq -r '.billing_day // 1' <<<"${current}")
    read -r -p "自定义结算日 1-28（回车保留 ${billing_day}）：" input
    if [[ -n ${input} ]]; then
        if [[ ! ${input} =~ ^[0-9]+$ ]] || ((input < 1 || input > 28)); then
            die "结算日必须为 1-28"
            return 1
        fi
        billing_day=${input}
    fi

    temp=$(jq --arg port "${port}" \
        --argjson daily "${daily}" --argjson monthly "${monthly}" \
        --argjson total "${total}" --argjson billing "${billing}" \
        --argjson billing_day "${billing_day}" '
        .ports[$port] = {
            daily_limit: $daily,
            monthly_limit: $monthly,
            total_limit: $total,
            billing_limit: $billing,
            billing_day: $billing_day
        }
    ' "${CONFIG_FILE}") || return 1
    printf '%s' "${temp}" | atomic_json_write "${CONFIG_FILE}" || return 1
    say "${green} ---> 端口 ${port} 的流量额度已保存${plain}"
    if config_enabled; then
        collect
    fi
}

configure_alerts() {
    local percent input auto_disable notify_type token chat_id url temp
    ensure_storage || return 1
    percent=$(jq -r '.alert_percent // 80' "${CONFIG_FILE}")
    read -r -p "告警阈值百分比（1-99，回车保留 ${percent}）：" input
    if [[ -n ${input} ]]; then
        if [[ ! ${input} =~ ^[0-9]+$ ]] || ((input < 1 || input > 99)); then
            die "阈值必须为 1-99"
            return 1
        fi
        percent=${input}
    fi
    read -r -p '超额后自动停用端口？[Y/n]：' input
    if [[ ${input} == n || ${input} == N ]]; then auto_disable=false; else auto_disable=true; fi
    say "1.仅本地日志（${ALERT_LOG}）"
    say '2.Telegram'
    say '3.Webhook（POST JSON）'
    read -r -p '请选择告警方式：' input
    notify_type=local
    token=''
    chat_id=''
    url=''
    case ${input} in
    2)
        notify_type=telegram
        read -r -s -p 'Telegram Bot Token：' token
        printf '\n'
        read -r -p 'Telegram Chat ID：' chat_id
        if [[ ! ${token} =~ ^[0-9]+:[A-Za-z0-9_-]+$ || ! ${chat_id} =~ ^[-@A-Za-z0-9_]+$ ]]; then
            die "Telegram Bot Token 或 Chat ID 格式错误"
            return 1
        fi
        ;;
    3)
        notify_type=webhook
        read -r -p 'Webhook URL（HTTPS）：' url
        if ! valid_webhook_url "${url}"; then
            die "Webhook URL 必须是有效的 HTTPS 地址"
            return 1
        fi
        ;;
    esac
    temp=$(jq --argjson percent "${percent}" --argjson auto "${auto_disable}" \
        --arg type "${notify_type}" --arg token "${token}" --arg chat "${chat_id}" --arg url "${url}" '
        .alert_percent = $percent
        | .auto_disable = $auto
        | .notify = {
            type: $type,
            telegram_bot_token: $token,
            telegram_chat_id: $chat,
            webhook_url: $url
          }
    ' "${CONFIG_FILE}") || return 1
    printf '%s' "${temp}" | atomic_json_write "${CONFIG_FILE}" || return 1
    say "${green} ---> 告警设置已保存${plain}"
    if config_enabled; then
        collect
    fi
}

report_menu() {
    local choice period output
    say '1.今日报告'
    say '2.本月报告'
    say '3.自定义结算周期报告'
    say '4.累计报告'
    read -r -p '请选择：' choice
    case ${choice} in
    1) period=daily ;;
    2) period=monthly ;;
    3) period=billing ;;
    4) period=total ;;
    *) die "选择错误"; return 1 ;;
    esac
    output=$(generate_report "${period}" current false) || return 1
    say "${green} ---> 报告已生成：${output}${plain}"
}

menu() {
    local choice input
    ensure_storage || return 1
    while true; do
        say "${skyBlue}\n==================== 端口流量监控 ====================${plain}"
        if config_enabled; then
            say "状态：${green}已启用${plain}"
        else
            say "状态：${yellow}未启用${plain}"
        fi
        say '1.启用监控'
        say '2.停用监控'
        say '3.查看端口流量'
        say '4.设置端口额度与结算日'
        say '5.设置告警与自动停用'
        say '6.立即采集'
        say '7.生成报告'
        say '0.返回'
        read -r -p '请选择：' choice
        case ${choice} in
        1)
            if [[ -f "${SING_BOX_CONF}" ]]; then
                say "${yellow}检测到 sing-box；当前组件只统计 Xray 入站端口。${plain}"
                read -r -p '是否明确仅监控 Xray 端口？[y/N]：' input
                [[ ${input} == y || ${input} == Y ]] && enable_monitor true
            else
                enable_monitor false
            fi
            ;;
        2) disable_monitor ;;
        3) display_usage ;;
        4) configure_port ;;
        5) configure_alerts ;;
        6) collect && say "${green} ---> 采集完成${plain}" ;;
        7) report_menu ;;
        0) return 0 ;;
        *) say "${red} ---> 选择错误${plain}" ;;
        esac
    done
}

main() {
    local command=${1:-menu}
    case ${command} in
    menu) menu ;;
    enable) enable_monitor "${2:-false}" ;;
    disable) disable_monitor ;;
    collect) collect ;;
    sync-config)
        ensure_storage || return 1
        if config_enabled; then sync_xray_config; else remove_managed_xray_config; fi
        ;;
    view) display_usage ;;
    report) generate_report "${2:-daily}" "${3:-current}" "${4:-false}" ;;
    discover-ports) ensure_storage && inbound_json ;;
    *) die "未知命令：${command}"; return 1 ;;
    esac
}

main "$@"
