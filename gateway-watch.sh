#!/bin/bash
# Шлюз для локальной сети: перенаправление устройств в Xray (TPROXY) есть, только пока контейнер
# запущен. Остановили контейнер — таблица nftables удаляется, и устройства ходят напрямую, а не
# упираются в закрытый порт. Работает от root (служба lan-vpn-proxy-gateway.service).
NAME=lan-vpn-proxy
TABLE="inet vpn"
RULES=${RULES:-/etc/lan-vpn-proxy/tproxy.nft}

sync() {
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ]; then
        nft list table $TABLE >/dev/null 2>&1 || { nft -f "$RULES" && echo "VPN для сети включён"; }
    else
        nft delete table $TABLE 2>/dev/null && echo "VPN для сети выключен: напрямую"
    fi
}

sync
# docker events --filter container=… совпадает по части имени — сверяем имя сами.
docker events --filter type=container --filter event=start --filter event=die \
        --format '{{.Actor.Attributes.name}}' |
    while read -r name; do
        [ "$name" = "$NAME" ] && sync
    done
