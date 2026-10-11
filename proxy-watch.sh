#!/usr/bin/env bash
# Держит системный прокси GNOME в соответствии с контейнером:
# контейнер запущен — прокси включён, остановлен — трафик идёт напрямую.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"

# .env не подключается через source: ссылки подписки с & и $ bash выполнил бы как команды.
env_value() {
    [ -f "$DIR/.env" ] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$DIR/.env" | tail -n 1 |
        sed -E "s/[[:space:]]+#.*$//; s/^(['\"])(.*)\1$/\2/"
}

CONTAINER="${CONTAINER:-lan-vpn-proxy}"
HTTP_PORT="${HTTP_PORT:-$(env_value HTTP_PORT)}"
HTTP_PORT="${HTTP_PORT:-3128}"
# Эти адреса всегда идут напрямую, минуя прокси.
IGNORE_HOSTS="['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '*.local']"

proxy_on() {
    gsettings set org.gnome.system.proxy.http host '127.0.0.1'
    gsettings set org.gnome.system.proxy.http port "$HTTP_PORT"
    gsettings set org.gnome.system.proxy.https host '127.0.0.1'
    gsettings set org.gnome.system.proxy.https port "$HTTP_PORT"
    gsettings set org.gnome.system.proxy.socks host ''
    gsettings set org.gnome.system.proxy.socks port 0
    gsettings set org.gnome.system.proxy ignore-hosts "$IGNORE_HOSTS"
    gsettings set org.gnome.system.proxy mode 'manual'
    echo "контейнер $CONTAINER запущен: прокси включён (127.0.0.1:$HTTP_PORT)"
}

proxy_off() {
    gsettings set org.gnome.system.proxy mode 'none'
    echo "контейнер $CONTAINER остановлен: трафик напрямую"
}

sync_state() {
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = true ]; then
        proxy_on
    else
        proxy_off
    fi
}

while true; do
    # --since повторяет события, случившиеся во время sync_state, чтобы их не пропустить.
    since=$(date +%s)
    sync_state
    docker events --since "$since" --filter type=container --filter "container=$CONTAINER" \
        --filter event=start --filter event=die --format '{{.Action}}' 2>/dev/null |
        while read -r action; do
            case "$action" in
                start) proxy_on ;;
                die) proxy_off ;;
            esac
        done
    # Сюда попадаем, если Docker недоступен или перезапускается.
    sleep 3
done
