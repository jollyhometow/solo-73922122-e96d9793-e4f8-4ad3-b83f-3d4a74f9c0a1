#!/bin/sh
# 启动前把 TSIG 密钥渲染进 named 配置，并确保动态更新目录可写。
set -eu

: "${BIND_TSIG_SECRET:?BIND_TSIG_SECRET 未设置}"

# 仅替换占位符；密钥为 base64，不含 sed 特殊分隔符，用 | 作分隔更稳妥
sed -i "s|TSIG_SECRET_PLACEHOLDER|${BIND_TSIG_SECRET}|" /etc/bind/named.conf.local

# 动态更新会在区域目录写 .jnl，确保属主为 named 运行用户 bind
chown -R bind:bind /var/lib/bind/zones /var/cache/bind /var/run/named
chmod 755 /var/lib/bind/zones

# 配置自检（渲染后立即校验，失败则容器退出而非带病启动）
named-checkconf /etc/bind/named.conf.local
named-checkzone acme.test /var/lib/bind/zones/db.acme.test >/dev/null

# named -g 前台运行；-u bind 降权
exec named -g -u bind -c /etc/bind/named.conf.local
