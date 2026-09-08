#!/usr/bin/env bash
# Retired: the former helper flushed unrelated IPv4 filter rules.
printf '%s\n' \
    'Automatic firewall removal is disabled; no firewall or service was changed.' \
    '自动清空防火墙功能已停用；未修改任何规则或服务。' \
    'Review SSH access, cloud rules and UFW policy before making manual firewall changes.' >&2
exit 1
