#!/bin/bash
# Установка и переустановка шлюза для локальной сети (домашний сервер): sudo ./install-gateway.sh
# Можно запускать сколько угодно раз — раскладывает файлы заново и перезапускает то, что изменилось.
# Нужен заполненный .env (TPROXY_PORT, PUID=0, PGID=0, WEB_PASSWORD при WEB_BIND не 127.0.0.1).
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
USER_NAME=${SUDO_USER:-}
[ "$(id -u)" = 0 ] && [ -n "$USER_NAME" ] || { echo "запустите через sudo от своего пользователя: sudo $0" >&2; exit 1; }
[ -f "$DIR/.env" ] || { echo "нет $DIR/.env — скопируйте .env.example и заполните" >&2; exit 1; }

# .env не подключаем через source: bash выполнил бы & и $(…) из ссылок подписки.
env_get() {
    python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); from gen_config import load_env, setting
print(setting(load_env(sys.argv[1] + "/.env"), sys.argv[2], sys.argv[3]))' "$DIR" "$1" "${2:-}"
}
as_user() { sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" "$@"; }

PORT=$(env_get TPROXY_PORT 0)
[ "$PORT" != 0 ] || { echo "в .env не задан TPROXY_PORT" >&2; exit 1; }
[ "$(env_get PUID 1000)" = 0 ] && [ "$(env_get PGID 1000)" = 0 ] ||
    { echo "в .env нужны PUID=0 и PGID=0: сокету TPROXY нужен root" >&2; exit 1; }
WEB_BIND=$(env_get WEB_BIND 127.0.0.1)
case "$WEB_BIND" in 127.0.0.1|localhost|::1) ;; *)
    [ -n "$(env_get WEB_PASSWORD)" ] || { echo "WEB_BIND=$WEB_BIND без WEB_PASSWORD" >&2; exit 1; } ;;
esac
# Интерфейс и сеть устройств — по маршруту по умолчанию, если не заданы в .env.
IFACE=$(env_get GATEWAY_IFACE "$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1); exit}')")
LAN=$(env_get GATEWAY_LAN "$(ip -4 route show dev "$IFACE" scope link proto kernel | awk '{print $1; exit}')")
[ -n "$IFACE" ] && [ -n "$LAN" ] || { echo "не удалось определить интерфейс и сеть — задайте GATEWAY_IFACE и GATEWAY_LAN в .env" >&2; exit 1; }
echo "шлюз: устройства $LAN на $IFACE → Xray :$PORT"

changed=
# install_file ИСТОЧНИК ЦЕЛЬ ПРАВА — кладёт файл, только если он изменился
install_file() {
    if ! cmp -s "$1" "$2"; then
        install -D -m "$3" "$1" "$2" && echo "обновлён $2" && changed=1
    fi
}
tmp=$(mktemp -d)
chmod 755 "$tmp"  # часть файлов ставится от имени пользователя
trap 'rm -rf "$tmp"' EXIT

sed -e "s|@IFACE@|$IFACE|g" -e "s|@LAN@|$LAN|g" -e "s|@PORT@|$PORT|g" "$DIR/gateway/tproxy.nft.in" > "$tmp/tproxy.nft"
nft -c -f "$tmp/tproxy.nft"
install_file "$tmp/tproxy.nft" /etc/lan-vpn-proxy/tproxy.nft 644

cat > "$tmp/sysctl.conf" <<EOF
# Создан install-gateway.sh (lan-vpn-proxy): сервер — шлюз для устройств сети
net.ipv4.ip_forward=1
# шлюз в той же сети, что и устройства: не отправлять им ICMP redirect на роутер
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.$IFACE.send_redirects=0
EOF
if ! cmp -s "$tmp/sysctl.conf" /etc/sysctl.d/90-lan-vpn-proxy.conf; then
    install -m 644 "$tmp/sysctl.conf" /etc/sysctl.d/90-lan-vpn-proxy.conf
    sysctl -q -p /etc/sysctl.d/90-lan-vpn-proxy.conf && echo "обновлён /etc/sysctl.d/90-lan-vpn-proxy.conf"
fi

install_file "$DIR/gateway-watch.sh" /usr/local/sbin/lan-vpn-proxy-gateway 755
install_file "$DIR/lan-vpn-proxy-gateway.service" /etc/systemd/system/lan-vpn-proxy-gateway.service 644
systemctl daemon-reload
systemctl enable -q lan-vpn-proxy-gateway.service
if [ -n "$changed" ] || ! systemctl -q is-active lan-vpn-proxy-gateway.service; then
    systemctl restart lan-vpn-proxy-gateway.service && echo "перезапущен lan-vpn-proxy-gateway.service"
fi

# Веб-интерфейс — пользовательская служба; linger — чтобы работала без входа в систему.
loginctl enable-linger "$USER_NAME"
unit="$(getent passwd "$USER_NAME" | cut -d: -f6)/.config/systemd/user/lan-vpn-proxy-web.service"
sed "s|%h/projects/lan_vpn_proxy|$DIR|" "$DIR/lan-vpn-proxy-web.service" > "$tmp/web.service"
web_changed=
if ! cmp -s "$tmp/web.service" "$unit"; then
    as_user install -D -m 644 "$tmp/web.service" "$unit" && echo "обновлён $unit" && web_changed=1
    as_user systemctl --user daemon-reload
fi
as_user systemctl --user enable -q lan-vpn-proxy-web.service
if [ -n "$web_changed" ] || ! as_user systemctl --user -q is-active lan-vpn-proxy-web.service; then
    as_user systemctl --user restart lan-vpn-proxy-web.service && echo "перезапущен lan-vpn-proxy-web.service"
fi

# Xray: конфиг собираем только при первой установке — gen_config.py каждый раз заново скачивает
# подписку, а провайдер раздаёт адреса по очереди, и контейнер перезапускался бы без нужды.
cd "$DIR"
[ -f xray/config.json ] || as_user ./gen_config.py
as_user docker compose up -d

# Обновление пушем с ноутбука: git push green
if [ -d "$DIR/.git" ]; then
    as_user git -C "$DIR" config receive.denyCurrentBranch updateInstead
    as_user ln -sfn ../../gateway/post-receive "$DIR/.git/hooks/post-receive"
fi
echo "готово"
