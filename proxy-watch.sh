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
# Перезапуск и пересоздание контейнера (смена сервера) занимают пару секунд. Если на это время
# выключить прокси, программы успеют открыть прямые соединения и будут держать их часами.
RESTART_GRACE="${RESTART_GRACE:-5}"
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

# Прокси — по фактическому состоянию контейнера. Без "force" ничего не трогает, если уже так.
sync_state() {
    local mode
    mode=$(gsettings get org.gnome.system.proxy mode)
    if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = true ]; then
        [ "${1:-}" = force ] || [ "$mode" != "'manual'" ] && proxy_on
    else
        [ "${1:-}" = force ] || [ "$mode" != "'none'" ] && proxy_off
    fi
}

while true; do
    # --since повторяет события, случившиеся во время sync_state, чтобы их не пропустить.
    since=$(date +%s)
    sync_state force
    docker events --since "$since" --filter type=container --filter "container=$CONTAINER" \
        --filter event=start --filter event=die --format '{{.Actor.Attributes.name}} {{.Action}}' 2>/dev/null |
        while read -r name action; do
            # Фильтр container= совпадает и по части имени — например, с контейнером
            # проверки серверов lan-vpn-proxy-check. Нужны события только своего.
            [ "$name" = "$CONTAINER" ] || continue
            [ "$action" = die ] && sleep "$RESTART_GRACE"
            sync_state
        done
    # Сюда попадаем, если Docker недоступен или перезапускается.
    sleep 3
done
