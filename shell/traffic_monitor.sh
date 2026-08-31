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

XRAY_ROUTING_FILE=${XRAY_CONF_DIR}/09_routing.json
XRAY_STATS_FILE=${XRAY_CONF_DIR}/13_traffic_stats.json
XRAY_BLOCK_OUTBOUND_FILE=${XRAY_CONF_DIR}/08_traffic_block_outbound.json
MANAGED_BLOCK_TAG=v2ray-agent-traffic-block
LEGACY_BLOCK_TAG=traffic-block
DEFAULT_API=127.0.0.1:10085
TEST_MODE=${V2RAY_AGENT_TEST_MODE:-0}
COLLECT_LOCK_DIR=
COLLECT_LOCK_TOKEN=

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
            | .ports = (
                if (.ports | type) == "object" then .ports else {} end
              )
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

query_xray_stats_with_retry() {
    local attempt output
    for attempt in 1 2 3; do
        if output=$(query_xray_stats); then
            printf '%s\n' "${output}"
            return 0
        fi
        [[ -n ${V2RAY_AGENT_STATS_FILE:-} ]] && break
        ((attempt < 3)) && sleep 1
    done
    return 1
}

valid_stats_response() {
    local raw_stats=$1
    printf '%s' "${raw_stats}" | jq -e '
        (.stat | type) == "array"
        and all(.stat[]?;
            (.name | type) == "string"
            and (
                .value == null
                or (.value | type) == "number"
                or (
                    (.value | type) == "string"
                    and (.value | test("^[0-9]+$"))
                )
            )
            and (((.value // 0) | tonumber) >= 0)
        )
    ' >/dev/null 2>&1
}

aggregate_stats() {
    local raw_stats=$1
    local inbounds=$2
    local previous_counters
    valid_stats_response "${raw_stats}" || return 1
    previous_counters=$(jq '.core_counters // {}' "${STATE_FILE}")
    printf '%s' "${raw_stats}" | jq \
        --argjson inbounds "${inbounds}" \
        --argjson previous "${previous_counters}" '
        ($inbounds | reduce .[] as $item ({}; .[$item.tag] = $item.port)) as $tag_map
        | (reduce (
            .stat[]?
            | select(.name | test("^inbound>>>.*>>>traffic>>>(uplink|downlink)$"))
          ) as $stat ({}; .[$stat.name] = (($stat.value // 0) | tonumber))) as $counters
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
        | {
            counters: (
                ($previous | with_entries(
                    select(.key | test("^inbound>>>.*>>>traffic>>>(uplink|downlink)$"))
                )) + $counters
            ),
            deltas: $deltas
          }
    '
}

build_billing_keys() {
    local ports=$1
    local day_key=$2
    jq -n \
        --argjson ports "${ports}" \
        --arg day "${day_key}" \
        --slurpfile config "${CONFIG_FILE}" '
        def valid_billing_day:
            (if type == "number" then .
             elif type == "string" and test("^[0-9]+$") then tonumber
             else 1 end)
            | if . == floor and . >= 1 and . <= 28 then . else 1 end;
        def pad2:
            tostring | if length < 2 then "0" + . else . end;
        ($day[0:4] | tonumber) as $year
        | ($day[5:7] | tonumber) as $month
        | ($day[8:10] | tonumber) as $day_of_month
        | reduce $ports[] as $port ({};
            (($config[0].ports[$port].billing_day // 1) | valid_billing_day) as $billing_day
            | (if $day_of_month < $billing_day then
                   if $month == 1
                   then {year: ($year - 1), month: 12}
                   else {year: $year, month: ($month - 1)} end
               else {year: $year, month: $month} end) as $period
            | .[$port] = (
                ($period.year | tostring) + "-"
                + ($period.month | pad2) + "-"
                + ($billing_day | pad2)
              )
          )
    '
}

update_state() {
    local deltas=$1
    local inbounds=$2
    local counters=$3
    local day_key month_key epoch ports billing_keys retention

    day_key=$(today_key)
    month_key=${day_key:0:7}
    epoch=$(now_epoch)
    ports=$(all_port_json "${inbounds}" "${deltas}")
    billing_keys=$(build_billing_keys "${ports}" "${day_key}")
    retention=$(jq -r '.retention_days // 100' "${CONFIG_FILE}")
    if [[ ! ${retention} =~ ^[0-9]+$ ]] || ((retention < 7)); then
        retention=100
    fi

    jq -n \
        --slurpfile old_data "${STATE_FILE}" \
        --slurpfile config_data "${CONFIG_FILE}" \
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

        ($old_data[0]) as $old
        | ($config_data[0]) as $config
        | ($old
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
            | .id = ([
                .port,
                .period,
                .key,
                .stage,
                (.limit | tostring),
                (($config.alert_percent // 80) | tostring)
              ] | join("|"))
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
                message="[v2ray-agent] 端口 ${port} 已因流量超额启用黑洞停用（${reasons}）"
            else
                message="[v2ray-agent] 端口 ${port} 的额度状态已恢复，黑洞规则已自动移除"
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
    if [[ ${TEST_MODE} == 1 ]]; then
        [[ ${V2RAY_AGENT_TEST_RESTART_FAIL:-0} != 1 ]]
        return
    fi
    if [[ ${V2RAY_AGENT_NO_RESTART:-0} == 1 ]]; then
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

snapshot_xray_files() {
    local backup_dir=$1
    local relative
    mkdir -p "${backup_dir}" || return 1
    for relative in \
        12_policy.json \
        09_routing.json \
        13_traffic_stats.json \
        08_traffic_block_outbound.json; do
        if [[ -f "${XRAY_CONF_DIR}/${relative}" ]]; then
            cp -- "${XRAY_CONF_DIR}/${relative}" "${backup_dir}/${relative}" || return 1
        else
            : >"${backup_dir}/missing-${relative}" || return 1
        fi
    done
}

restore_xray_files() {
    local backup_dir=$1
    local relative failed=false
    for relative in \
        12_policy.json \
        09_routing.json \
        13_traffic_stats.json \
        08_traffic_block_outbound.json; do
        if [[ -f "${backup_dir}/${relative}" ]]; then
            atomic_copy "${backup_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}" 644 ||
                failed=true
        elif [[ -f "${backup_dir}/missing-${relative}" ]]; then
            rm -f -- "${XRAY_CONF_DIR}/${relative}" || failed=true
        else
            failed=true
        fi
    done
    [[ ${failed} == false ]]
}

blocked_tags_for_inbounds() {
    local inbounds=$1
    jq -n --argjson inbounds "${inbounds}" --slurpfile state "${STATE_FILE}" '
        (($state[0].ports // {})
         | to_entries
         | map(select((.value.disabled // false) == true) | .key)) as $ports
        | [$inbounds[]
           | . as $item
           | select($ports | index($item.port))
           | $item.tag]
        | unique
        | sort
    '
}

managed_xray_config_matches_state() {
    local inbounds=$1
    local api blocked_tags blocked_count

    api=$(jq -r '.api // "127.0.0.1:10085"' "${CONFIG_FILE}")
    valid_api_address "${api}" || return 1
    blocked_tags=$(blocked_tags_for_inbounds "${inbounds}") || return 1
    blocked_count=$(jq 'length' <<<"${blocked_tags}")

    [[ -f "${XRAY_CONF_DIR}/12_policy.json" ]] &&
        jq -e '
            .policy.system.statsInboundUplink == true
            and .policy.system.statsInboundDownlink == true
        ' "${XRAY_CONF_DIR}/12_policy.json" >/dev/null 2>&1 || return 1

    [[ -f "${XRAY_STATS_FILE}" ]] &&
        jq -e --arg api "${api}" '
            .stats == {}
            and .api == {
                tag: "traffic-api",
                listen: $api,
                services: ["StatsService"]
            }
        ' "${XRAY_STATS_FILE}" >/dev/null 2>&1 || return 1

    if [[ -f "${XRAY_ROUTING_FILE}" ]]; then
        jq -e --argjson expected "${blocked_tags}" \
            --arg tag "${MANAGED_BLOCK_TAG}" --arg legacy "${LEGACY_BLOCK_TAG}" '
            ([.routing.rules[]? | select(.outboundTag == $tag)]) as $managed
            | ([.routing.rules[]? | select(.outboundTag == $legacy)] | length) == 0
            and if ($expected | length) > 0 then
                ($managed | length) == 1
                and $managed[0].type == "field"
                and (($managed[0].inboundTag // [] | unique | sort) == ($expected | sort))
              else
                ($managed | length) == 0
              end
        ' "${XRAY_ROUTING_FILE}" >/dev/null 2>&1 || return 1
    elif ((blocked_count > 0)); then
        return 1
    fi

    if ((blocked_count > 0)); then
        [[ -f "${XRAY_BLOCK_OUTBOUND_FILE}" ]] &&
            jq -e --arg tag "${MANAGED_BLOCK_TAG}" '
                (.outbounds | type) == "array"
                and (.outbounds | length) == 1
                and .outbounds[0].tag == $tag
                and .outbounds[0].protocol == "blackhole"
            ' "${XRAY_BLOCK_OUTBOUND_FILE}" >/dev/null 2>&1 || return 1
    elif [[ -f "${XRAY_BLOCK_OUTBOUND_FILE}" ]]; then
        return 1
    fi
    return 0
}

sync_xray_config() {
    local temp_dir backup_dir inbounds blocked_tags api changed=false
    local file relative apply_failed=false

    ensure_storage || return 1
    [[ -d "${XRAY_CONF_DIR}" ]] || return 0
    inbounds=$(inbound_json)
    blocked_tags=$(blocked_tags_for_inbounds "${inbounds}") || return 1
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

    backup_dir=$(mktemp -d "${TRAFFIC_DIR}/xray-backup.XXXXXX") || {
        rm -rf -- "${temp_dir}"
        return 1
    }
    if ! snapshot_xray_files "${backup_dir}"; then
        rm -rf -- "${temp_dir}" "${backup_dir}"
        die "无法创建 Xray 配置快照，原配置未改动"
        return 1
    fi

    for relative in 12_policy.json 09_routing.json 13_traffic_stats.json; do
        if [[ ! -f "${XRAY_CONF_DIR}/${relative}" ]] ||
            ! cmp -s "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}"; then
            if ! atomic_copy "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}" 644; then
                apply_failed=true
                break
            fi
            changed=true
        fi
    done

    if [[ ${apply_failed} == false ]]; then
        relative=08_traffic_block_outbound.json
        if [[ -f "${temp_dir}/${relative}" ]]; then
            if [[ ! -f "${XRAY_CONF_DIR}/${relative}" ]] ||
                ! cmp -s "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}"; then
                if ! atomic_copy "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}" 644; then
                    apply_failed=true
                fi
                changed=true
            fi
        elif [[ -f "${XRAY_CONF_DIR}/${relative}" ]]; then
            rm -f -- "${XRAY_CONF_DIR}/${relative}" || apply_failed=true
            changed=true
        fi
    fi

    if [[ ${apply_failed} == true ]]; then
        restore_xray_files "${backup_dir}" || true
        rm -rf -- "${temp_dir}" "${backup_dir}"
        die "写入 Xray 配置失败，已尝试恢复原配置"
        return 1
    fi

    if [[ ${changed} == true ]] && ! restart_xray; then
        if restore_xray_files "${backup_dir}"; then
            restart_xray >/dev/null 2>&1 || true
            rm -rf -- "${temp_dir}" "${backup_dir}"
            die "Xray 重启失败，已恢复修改前的配置"
        else
            rm -rf -- "${temp_dir}" "${backup_dir}"
            die "Xray 重启失败，且自动恢复配置未完全成功"
        fi
        return 1
    fi

    rm -rf -- "${temp_dir}" "${backup_dir}"
}

remove_managed_xray_config() {
    local temp_dir backup_dir file relative changed=false apply_failed=false
    [[ -d "${XRAY_CONF_DIR}" ]] || return 0

    temp_dir=$(mktemp -d "${TRAFFIC_DIR}/xray-remove.XXXXXX") || return 1
    for file in "${XRAY_CONF_DIR}"/*.json; do
        [[ -f "${file}" ]] || continue
        cp -- "${file}" "${temp_dir}/" || {
            rm -rf -- "${temp_dir}"
            return 1
        }
    done

    if [[ -f "${temp_dir}/09_routing.json" ]]; then
        jq --arg tag "${MANAGED_BLOCK_TAG}" --arg legacy "${LEGACY_BLOCK_TAG}" '
            .routing.rules = ([
                .routing.rules[]?
                | select(.outboundTag != $tag and .outboundTag != $legacy)
            ])
        ' "${temp_dir}/09_routing.json" >"${temp_dir}/09_routing.json.new" || {
            rm -rf -- "${temp_dir}"
            return 1
        }
        mv -f -- "${temp_dir}/09_routing.json.new" "${temp_dir}/09_routing.json"
    fi
    rm -f -- "${temp_dir}/13_traffic_stats.json" \
        "${temp_dir}/08_traffic_block_outbound.json"

    if [[ ${TEST_MODE} != 1 && -x "${XRAY_BIN}" ]] &&
        ! "${XRAY_BIN}" run -test -confdir "${temp_dir}" >/dev/null 2>&1; then
        rm -rf -- "${temp_dir}"
        die "移除监控配置后的 Xray 校验失败，原配置未改动"
        return 1
    fi

    backup_dir=$(mktemp -d "${TRAFFIC_DIR}/xray-backup.XXXXXX") || {
        rm -rf -- "${temp_dir}"
        return 1
    }
    if ! snapshot_xray_files "${backup_dir}"; then
        rm -rf -- "${temp_dir}" "${backup_dir}"
        die "无法创建 Xray 配置快照，原配置未改动"
        return 1
    fi

    relative=09_routing.json
    if [[ -f "${temp_dir}/${relative}" ]] &&
        { [[ ! -f "${XRAY_CONF_DIR}/${relative}" ]] ||
          ! cmp -s "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}"; }; then
        if atomic_copy "${temp_dir}/${relative}" "${XRAY_CONF_DIR}/${relative}" 644; then
            changed=true
        else
            apply_failed=true
        fi
    fi

    if [[ ${apply_failed} == false ]]; then
        for relative in 13_traffic_stats.json 08_traffic_block_outbound.json; do
            if [[ -f "${XRAY_CONF_DIR}/${relative}" ]]; then
                if rm -f -- "${XRAY_CONF_DIR}/${relative}"; then
                    changed=true
                else
                    apply_failed=true
                    break
                fi
            fi
        done
    fi

    if [[ ${apply_failed} == true ]]; then
        restore_xray_files "${backup_dir}" || true
        rm -rf -- "${temp_dir}" "${backup_dir}"
        die "移除 Xray 监控配置失败，已尝试恢复原配置"
        return 1
    fi

    if [[ ${changed} == true ]] && ! restart_xray; then
        if restore_xray_files "${backup_dir}"; then
            restart_xray >/dev/null 2>&1 || true
            rm -rf -- "${temp_dir}" "${backup_dir}"
            die "Xray 重启失败，已恢复修改前的配置"
        else
            rm -rf -- "${temp_dir}" "${backup_dir}"
            die "Xray 重启失败，且自动恢复配置未完全成功"
        fi
        return 1
    fi

    rm -rf -- "${temp_dir}" "${backup_dir}"
}

process_start_id() {
    local pid=$1 start_id
    [[ ${pid} =~ ^[0-9]+$ && -r /proc/${pid}/stat ]] || return 1
    start_id=$(awk '{sub(/^.*[)] /, ""); print $20}' "/proc/${pid}/stat" 2>/dev/null) ||
        return 1
    [[ ${start_id} =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${start_id}"
}

write_collect_lock_owner() {
    local start_id=
    COLLECT_LOCK_TOKEN="$$:$(now_epoch):${RANDOM}${RANDOM}"
    printf '%s\n' "$$" >"${COLLECT_LOCK_DIR}/pid" || return 1
    printf '%s\n' "${COLLECT_LOCK_TOKEN}" >"${COLLECT_LOCK_DIR}/token" || return 1
    if start_id=$(process_start_id "$$"); then
        printf '%s\n' "${start_id}" >"${COLLECT_LOCK_DIR}/start_id" || return 1
    fi
}

cleanup_collect_lock() {
    local current_token=
    if [[ -n ${COLLECT_LOCK_DIR} ]]; then
        if [[ -f "${COLLECT_LOCK_DIR}/token" ]]; then
            current_token=$(command cat "${COLLECT_LOCK_DIR}/token" 2>/dev/null || true)
        fi
        if [[ -n ${COLLECT_LOCK_TOKEN} && ${current_token} == "${COLLECT_LOCK_TOKEN}" ]]; then
            rm -f -- "${COLLECT_LOCK_DIR}/pid" "${COLLECT_LOCK_DIR}/start_id" \
                "${COLLECT_LOCK_DIR}/token"
            rmdir "${COLLECT_LOCK_DIR}" 2>/dev/null || true
        fi
        COLLECT_LOCK_DIR=
        COLLECT_LOCK_TOKEN=
    fi
}

release_collect_lock() {
    cleanup_collect_lock
    trap - EXIT INT TERM
}

acquire_collect_lock() {
    local owner_pid='' owner_start_id='' current_start_id=''
    COLLECT_LOCK_DIR=${TRAFFIC_DIR}/collect.lock
    if mkdir "${COLLECT_LOCK_DIR}" 2>/dev/null; then
        if write_collect_lock_owner; then
            return 0
        fi
        rm -f -- "${COLLECT_LOCK_DIR}/pid" "${COLLECT_LOCK_DIR}/start_id" \
            "${COLLECT_LOCK_DIR}/token"
        rmdir "${COLLECT_LOCK_DIR}" 2>/dev/null || true
        COLLECT_LOCK_DIR=
        COLLECT_LOCK_TOKEN=
        return 1
    fi
    if [[ -f "${COLLECT_LOCK_DIR}/pid" ]]; then
        owner_pid=$(command cat "${COLLECT_LOCK_DIR}/pid" 2>/dev/null || true)
    fi
    if [[ ${owner_pid} =~ ^[0-9]+$ ]] && kill -0 "${owner_pid}" 2>/dev/null; then
        if [[ -f "${COLLECT_LOCK_DIR}/start_id" ]]; then
            owner_start_id=$(command cat "${COLLECT_LOCK_DIR}/start_id" 2>/dev/null || true)
            current_start_id=$(process_start_id "${owner_pid}" 2>/dev/null || true)
            if [[ -z ${owner_start_id} || -z ${current_start_id} ||
                ${owner_start_id} == "${current_start_id}" ]]; then
                COLLECT_LOCK_DIR=
                return 1
            fi
        else
            COLLECT_LOCK_DIR=
            return 1
        fi
    fi
    rm -f -- "${COLLECT_LOCK_DIR}/pid" "${COLLECT_LOCK_DIR}/start_id" \
        "${COLLECT_LOCK_DIR}/token"
    rmdir "${COLLECT_LOCK_DIR}" 2>/dev/null || true
    if mkdir "${COLLECT_LOCK_DIR}" 2>/dev/null; then
        if write_collect_lock_owner; then
            return 0
        fi
        rm -f -- "${COLLECT_LOCK_DIR}/pid" "${COLLECT_LOCK_DIR}/start_id" \
            "${COLLECT_LOCK_DIR}/token"
        rmdir "${COLLECT_LOCK_DIR}" 2>/dev/null || true
    fi
    COLLECT_LOCK_DIR=
    COLLECT_LOCK_TOKEN=
    return 1
}

collect() {
    local raw_stats inbounds stats_result counters deltas result old_state new_state events
    local status_changed
    ensure_storage || return 1
    config_enabled || return 0

    if ! acquire_collect_lock; then
        return 0
    fi
    trap cleanup_collect_lock EXIT
    trap 'cleanup_collect_lock; exit 130' INT
    trap 'cleanup_collect_lock; exit 143' TERM

    inbounds=$(inbound_json)
    if ! managed_xray_config_matches_state "${inbounds}"; then
        if ! sync_xray_config; then
            printf '%s managed config sync failed\n' "$(date '+%F %T')" >>"${COLLECT_LOG}"
            release_collect_lock
            return 1
        fi
    fi
    if ! raw_stats=$(query_xray_stats_with_retry 2>>"${COLLECT_LOG}"); then
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
    status_changed=$(jq -r 'any(.[]; .type == "status")' <<<"${events}")
    if ! printf '%s' "${new_state}" | atomic_json_write "${STATE_FILE}"; then
        release_collect_lock
        return 1
    fi

    if [[ ${status_changed} == true ]] && ! sync_xray_config; then
        printf '%s' "${old_state}" | atomic_json_write "${STATE_FILE}"
        release_collect_lock
        return 1
    fi
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
    local report_data key usage output temp_output summary
    ensure_storage || return 1
    report_data=$(report_usage_json "${period}" "${selector}") || return 1
    key=$(jq -r '.key' <<<"${report_data}")
    usage=$(jq '.usage' <<<"${report_data}")
    output=${REPORT_DIR}/${period}-${key}.csv
    temp_output=$(mktemp "${output}.tmp.XXXXXX") || return 1

    if [[ ${period} == billing ]]; then
        if ! jq -r -n --argjson usage "${usage}" --slurpfile state "${STATE_FILE}" '
            ["端口", "周期起始", "字节", "GiB", "状态"] | @csv,
            ($usage | to_entries | sort_by(.key)[]
             | [.key, .value.cycle, .value.bytes,
                ((.value.bytes / 1073741824 * 100 | round) / 100),
                (if ($state[0].ports[.key].disabled // false) then "已停用" else "正常" end)]
             | @csv)
        ' >"${temp_output}"; then
            rm -f -- "${temp_output}"
            return 1
        fi
    else
        if ! jq -r -n --argjson usage "${usage}" --slurpfile state "${STATE_FILE}" '
            ["端口", "字节", "GiB", "状态"] | @csv,
            ($usage | to_entries | sort_by(-.value)[]
             | [.key, .value, ((.value / 1073741824 * 100 | round) / 100),
                (if ($state[0].ports[.key].disabled // false) then "已停用" else "正常" end)]
             | @csv)
        ' >"${temp_output}"; then
            rm -f -- "${temp_output}"
            return 1
        fi
    fi
    if ! chmod 600 "${temp_output}" ||
        ! mv -f -- "${temp_output}" "${output}"; then
        rm -f -- "${temp_output}"
        return 1
    fi

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
    local allow_partial=${1:-false} previous_config previous_enabled rollback_failed=false
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
        die '检测到同时运行的 sing-box 协议；请显式选择“仅监控 Xray 端口”后继续'
        return 1
    fi

    if ! acquire_collect_lock; then
        die "已有采集或配置操作正在执行，请稍后重试"
        return 1
    fi
    trap cleanup_collect_lock EXIT
    trap 'cleanup_collect_lock; exit 130' INT
    trap 'cleanup_collect_lock; exit 143' TERM
    previous_config=$(command cat "${CONFIG_FILE}")
    previous_enabled=$(jq -r '.enabled // false' <<<"${previous_config}")
    jq '.enabled = true | .core = "xray"' "${CONFIG_FILE}" |
        atomic_json_write "${CONFIG_FILE}" || {
            release_collect_lock
            return 1
        }
    sync_xray_config || {
        printf '%s' "${previous_config}" | atomic_json_write "${CONFIG_FILE}" || true
        release_collect_lock
        return 1
    }
    if ! install_cron; then
        printf '%s' "${previous_config}" | atomic_json_write "${CONFIG_FILE}" ||
            rollback_failed=true
        if [[ ${previous_enabled} != true ]]; then
            remove_managed_xray_config || rollback_failed=true
        fi
        release_collect_lock
        if [[ ${rollback_failed} == true ]]; then
            die "安装定时任务失败，且启用状态未能完全回滚"
            return 1
        fi
        die "安装定时任务失败"
        return 1
    fi
    release_collect_lock
    say "${green} ---> 端口流量监控已启用${plain}"
    if [[ -f "${SING_BOX_CONF}" ]]; then
        say "${yellow} ---> 当前只统计 Xray 入站端口，sing-box 端口不会计入额度${plain}"
    fi
    if ! collect; then
        say "${yellow} ---> 首次采集失败，定时任务将在下一分钟重试${plain}"
    fi
}

disable_monitor() {
    local previous_config rollback_failed=false
    ensure_storage || return 1
    if ! acquire_collect_lock; then
        die "已有采集或配置操作正在执行，请稍后重试"
        return 1
    fi
    trap cleanup_collect_lock EXIT
    trap 'cleanup_collect_lock; exit 130' INT
    trap 'cleanup_collect_lock; exit 143' TERM
    previous_config=$(command cat "${CONFIG_FILE}")
    jq '.enabled = false' "${CONFIG_FILE}" | atomic_json_write "${CONFIG_FILE}" || {
        release_collect_lock
        return 1
    }
    if ! remove_cron; then
        printf '%s' "${previous_config}" | atomic_json_write "${CONFIG_FILE}" || true
        release_collect_lock
        die "移除定时任务失败"
        return 1
    fi
    if ! remove_managed_xray_config; then
        printf '%s' "${previous_config}" | atomic_json_write "${CONFIG_FILE}" ||
            rollback_failed=true
        if [[ $(jq -r '.enabled // false' <<<"${previous_config}") == true ]]; then
            install_cron || rollback_failed=true
        fi
        release_collect_lock
        if [[ ${rollback_failed} == true ]]; then
            die "移除核心配置失败，且监控状态未能完全恢复"
            return 1
        fi
        die "移除端口流量监控核心配置失败，请检查 Xray 配置"
        return 1
    fi
    release_collect_lock
    say "${green} ---> 端口流量监控已停用，历史数据已保留，端口限制已解除${plain}"
}

sync_config_command() {
    local result=0
    ensure_storage || return 1
    if ! acquire_collect_lock; then
        die "已有采集或配置操作正在执行，请稍后重试"
        return 1
    fi
    trap cleanup_collect_lock EXIT
    trap 'cleanup_collect_lock; exit 130' INT
    trap 'cleanup_collect_lock; exit 143' TERM
    if config_enabled; then
        sync_xray_config || result=$?
    else
        remove_managed_xray_config || result=$?
    fi
    release_collect_lock
    return "${result}"
}

display_usage() {
    local port daily monthly billing total status billing_cycle reasons port_lines last_collect
    ensure_storage || return 1
    last_collect=$(jq -r '.last_collect_at // 0' "${STATE_FILE}")
    say "最近采集时间戳：${last_collect}"
    say "停用方式：Xray inboundTag 黑洞路由（监听 socket 保持开启）"
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
        if [[ ${status} == 已停用 ]]; then
            reasons=$(jq -r --arg port "${port}" '
                .ports[$port].disabled_reasons
                | map(
                    if . == "daily" then "每日"
                    elif . == "monthly" then "自然月"
                    elif . == "billing" then "自定义结算周期"
                    elif . == "total" then "累计"
                    else . end
                )
                | join("、")
            ' "${STATE_FILE}")
            printf '  黑洞原因：%s\n' "${reasons}"
        fi
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
    temp=$(
        {
            printf '%s\n' "${token}"
            printf '%s\n' "${chat_id}"
            printf '%s\n' "${url}"
        } | jq -Rs \
            --slurpfile config "${CONFIG_FILE}" \
            --argjson percent "${percent}" \
            --argjson auto "${auto_disable}" \
            --arg type "${notify_type}" '
            split("\n") as $secret
            | $config[0]
            | .alert_percent = $percent
            | .auto_disable = $auto
            | .notify = {
                type: $type,
                telegram_bot_token: $secret[0],
                telegram_chat_id: $secret[1],
                webhook_url: $secret[2]
              }
        '
    ) || return 1
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

doctor() {
    local failures=0 warnings=0
    local api inbounds port_count raw_stats stat_count last_collect current_epoch collect_age
    local disabled_ports expected_tags actual_tags managed_rule_count legacy_rule_count
    local traffic_mode config_mode state_mode

    ensure_storage || return 1
    say "${skyBlue}\n==================== 端口流量监控自检 ====================${plain}"

    if jq -e '.version == 2 and (.ports | type) == "object"' "${CONFIG_FILE}" >/dev/null 2>&1 &&
        jq -e '.version == 2 and (.ports | type) == "object"' "${STATE_FILE}" >/dev/null 2>&1; then
        say "${green}[通过] 配置与状态 JSON${plain}"
    else
        say "${red}[失败] 配置或状态 JSON 结构错误${plain}"
        failures=$((failures + 1))
    fi

    api=$(jq -r '.api // ""' "${CONFIG_FILE}")
    if valid_api_address "${api}"; then
        say "${green}[通过] StatsService 仅监听 ${api}${plain}"
    else
        say "${red}[失败] StatsService 地址不是安全的 IPv4 回环地址${plain}"
        failures=$((failures + 1))
    fi

    if inbounds=$(inbound_json 2>/dev/null); then
        port_count=$(jq '[.[].port] | unique | length' <<<"${inbounds}")
        if ((port_count > 0)); then
            say "${green}[通过] 已发现 ${port_count} 个 Xray 入站端口${plain}"
        else
            say "${red}[失败] 未发现可统计的 Xray 入站端口${plain}"
            failures=$((failures + 1))
        fi
    else
        inbounds='[]'
        say "${red}[失败] 无法解析 Xray 入站配置${plain}"
        failures=$((failures + 1))
    fi

    if [[ ! -x "${XRAY_BIN}" ]]; then
        if [[ ${TEST_MODE} == 1 ]]; then
            say "${yellow}[跳过] 测试模式未提供 Xray 二进制${plain}"
            warnings=$((warnings + 1))
        else
            say "${red}[失败] Xray 二进制不存在或不可执行：${XRAY_BIN}${plain}"
            failures=$((failures + 1))
        fi
    elif [[ ${TEST_MODE} == 1 ]]; then
        say "${yellow}[跳过] 测试模式不执行 Xray 核心校验${plain}"
        warnings=$((warnings + 1))
    elif "${XRAY_BIN}" run -test -confdir "${XRAY_CONF_DIR}" >/dev/null 2>>"${COLLECT_LOG}"; then
        say "${green}[通过] Xray 完整配置校验${plain}"
    else
        say "${red}[失败] Xray 完整配置校验未通过${plain}"
        failures=$((failures + 1))
    fi

    if config_enabled; then
        if raw_stats=$(query_xray_stats 2>>"${COLLECT_LOG}") &&
            valid_stats_response "${raw_stats}"; then
            stat_count=$(jq '.stat | length' <<<"${raw_stats}")
            say "${green}[通过] StatsService 响应有效（${stat_count} 个计数器）${plain}"
        else
            say "${red}[失败] StatsService 查询失败或响应格式无效${plain}"
            failures=$((failures + 1))
        fi

        disabled_ports=$(jq '[.ports | to_entries[]? | select(.value.disabled == true) | .key]' "${STATE_FILE}")
        expected_tags=$(jq -n --argjson inbounds "${inbounds}" --argjson ports "${disabled_ports}" '
            [$inbounds[]
             | . as $item
             | select($ports | index($item.port))
             | $item.tag]
            | unique
            | sort
        ')
        if [[ -f "${XRAY_ROUTING_FILE}" ]]; then
            actual_tags=$(jq --arg tag "${MANAGED_BLOCK_TAG}" '
                [.routing.rules[]?
                 | select(.outboundTag == $tag)
                 | .inboundTag[]?]
                | unique
                | sort
            ' "${XRAY_ROUTING_FILE}" 2>/dev/null || printf 'null')
            managed_rule_count=$(jq --arg tag "${MANAGED_BLOCK_TAG}" '
                [.routing.rules[]? | select(.outboundTag == $tag)] | length
            ' "${XRAY_ROUTING_FILE}" 2>/dev/null || printf '0')
            legacy_rule_count=$(jq --arg tag "${LEGACY_BLOCK_TAG}" '
                [.routing.rules[]? | select(.outboundTag == $tag)] | length
            ' "${XRAY_ROUTING_FILE}" 2>/dev/null || printf '0')
        else
            actual_tags='[]'
            managed_rule_count=0
            legacy_rule_count=0
        fi

        if [[ ${actual_tags} == "${expected_tags}" ]] &&
            [[ ${legacy_rule_count} -eq 0 ]] &&
            { [[ $(jq 'length' <<<"${expected_tags}") -eq 0 && ${managed_rule_count} -eq 0 ]] ||
              [[ $(jq 'length' <<<"${expected_tags}") -gt 0 && ${managed_rule_count} -eq 1 ]]; }; then
            say "${green}[通过] 黑洞路由与端口停用状态一致${plain}"
        else
            say "${red}[失败] 黑洞路由与端口停用状态不一致，请执行 sync-config${plain}"
            failures=$((failures + 1))
        fi

        if [[ $(jq 'length' <<<"${expected_tags}") -gt 0 ]]; then
            if [[ -f "${XRAY_BLOCK_OUTBOUND_FILE}" ]] &&
                jq -e --arg tag "${MANAGED_BLOCK_TAG}" '
                    [.outbounds[]? | select(
                        .tag == $tag and .protocol == "blackhole"
                    )] | length == 1
                ' "${XRAY_BLOCK_OUTBOUND_FILE}" >/dev/null 2>&1; then
                say "${green}[通过] 黑洞 outbound 状态正确${plain}"
            else
                say "${red}[失败] 存在停用端口但黑洞 outbound 缺失或无效${plain}"
                failures=$((failures + 1))
            fi
        elif [[ -f "${XRAY_BLOCK_OUTBOUND_FILE}" ]]; then
            say "${red}[失败] 没有停用端口但仍残留黑洞 outbound${plain}"
            failures=$((failures + 1))
        else
            say "${green}[通过] 黑洞 outbound 状态正确${plain}"
        fi

        if [[ ${TEST_MODE} != 1 ]]; then
            if command -v crontab >/dev/null 2>&1 &&
                crontab -l 2>/dev/null | grep -q '# v2ray-agent-traffic'; then
                say "${green}[通过] 定时采集任务已安装${plain}"
            else
                say "${yellow}[警告] 未检测到定时采集任务${plain}"
                warnings=$((warnings + 1))
            fi
        fi
    else
        say "${yellow}[警告] 端口流量监控当前未启用${plain}"
        warnings=$((warnings + 1))
        managed_rule_count=0
        legacy_rule_count=0
        if [[ -f "${XRAY_ROUTING_FILE}" ]]; then
            managed_rule_count=$(jq --arg tag "${MANAGED_BLOCK_TAG}" '
                [.routing.rules[]? | select(.outboundTag == $tag)] | length
            ' "${XRAY_ROUTING_FILE}" 2>/dev/null || printf '1')
            legacy_rule_count=$(jq --arg tag "${LEGACY_BLOCK_TAG}" '
                [.routing.rules[]? | select(.outboundTag == $tag)] | length
            ' "${XRAY_ROUTING_FILE}" 2>/dev/null || printf '1')
        fi
        if [[ ${managed_rule_count} -eq 0 && ${legacy_rule_count} -eq 0 &&
            ! -f "${XRAY_STATS_FILE}" && ! -f "${XRAY_BLOCK_OUTBOUND_FILE}" ]]; then
            say "${green}[通过] 未启用状态没有残留托管配置${plain}"
        else
            say "${red}[失败] 未启用状态仍有托管配置残留，请执行 sync-config${plain}"
            failures=$((failures + 1))
        fi
    fi

    last_collect=$(jq -r '.last_collect_at // 0' "${STATE_FILE}")
    if [[ ${last_collect} =~ ^[0-9]+$ ]] && ((last_collect > 0)); then
        if config_enabled; then
            current_epoch=$(now_epoch)
            if [[ ${current_epoch} =~ ^[0-9]+$ ]] &&
                ((last_collect <= current_epoch + 60)); then
                collect_age=$((current_epoch - last_collect))
                ((collect_age < 0)) && collect_age=0
                if ((collect_age <= 300)); then
                    say "${green}[通过] 最近采集正常（${collect_age} 秒前）${plain}"
                else
                    say "${red}[失败] 最近采集已过期（${collect_age} 秒前）${plain}"
                    failures=$((failures + 1))
                fi
            else
                say "${red}[失败] 最近采集时间戳异常：${last_collect}${plain}"
                failures=$((failures + 1))
            fi
        else
            say "${green}[通过] 已保存采集状态（时间戳 ${last_collect}）${plain}"
        fi
    else
        if config_enabled; then
            say "${red}[失败] 监控已启用但尚无成功采集记录${plain}"
            failures=$((failures + 1))
        else
            say "${yellow}[警告] 尚无成功采集记录${plain}"
            warnings=$((warnings + 1))
        fi
    fi

    traffic_mode=$(stat -c '%a' "${TRAFFIC_DIR}" 2>/dev/null || printf '?')
    config_mode=$(stat -c '%a' "${CONFIG_FILE}" 2>/dev/null || printf '?')
    state_mode=$(stat -c '%a' "${STATE_FILE}" 2>/dev/null || printf '?')
    if [[ ${traffic_mode} == 700 && ${config_mode} == 600 && ${state_mode} == 600 ]]; then
        say "${green}[通过] 数据目录和状态文件权限正确${plain}"
    else
        say "${red}[失败] 权限异常：目录=${traffic_mode} config=${config_mode} state=${state_mode}${plain}"
        failures=$((failures + 1))
    fi

    if ((failures == 0)); then
        say "${green} ---> 自检通过，警告 ${warnings} 项${plain}"
        return 0
    fi
    say "${red} ---> 自检失败 ${failures} 项，警告 ${warnings} 项${plain}"
    return 1
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
        say '8.运行自检'
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
        8) doctor ;;
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
    sync-config) sync_config_command ;;
    view) display_usage ;;
    report) generate_report "${2:-daily}" "${3:-current}" "${4:-false}" ;;
    doctor) doctor ;;
    discover-ports) ensure_storage && inbound_json ;;
    *) die "未知命令：${command}"; return 1 ;;
    esac
}

main "$@"
