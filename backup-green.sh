#!/bin/bash
# Резервная копия настроек домашнего сервера на этот компьютер: .env (подписка, пароль) и data/
# (имена устройств, статистика, сертификат). Код восстанавливается из git, а это — нет.
#   ./backup-green.sh [пользователь@сервер]
# Архивы — в ~/backups/lan_vpn_proxy (права 600), хранятся последние KEEP. Сервер недоступен
# (ноутбук не дома) — выходит без ошибки: так его можно запускать таймером.
# Заодно кладёт .env и data/ ноутбука на сервер, в ~/backups/laptop (тоже последние KEEP).
set -euo pipefail

HOST=${1:-dima@192.168.0.2}
REMOTE_DIR=lan_vpn_proxy
DEST=${BACKUP_DIR:-$HOME/backups/lan_vpn_proxy}
KEEP=${KEEP:-14}

# BatchMode: без вопросов о пароле; ключ хоста проверяется — в чужой сети с тем же адресом не подключимся.
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST")
if ! "${SSH[@]}" true 2>/dev/null; then
    echo "сервер $HOST недоступен — пропускаю"
    exit 0
fi

umask 077
mkdir -p "$DEST"
file="$DEST/green-$(date +%Y-%m-%d_%H%M).tar.gz"
"${SSH[@]}" "cd $REMOTE_DIR && tar -czf - .env data" > "$file.tmp"
tar -tzf "$file.tmp" .env >/dev/null  # архив целый и в нём есть .env
mv "$file.tmp" "$file"
echo "сохранено: $file ($(du -h "$file" | cut -f1))"

# Старые архивы — кроме последних KEEP. В имени дата и время, поэтому порядок glob — по возрасту.
archives=("$DEST"/green-*.tar.gz)
if [ "${#archives[@]}" -gt "$KEEP" ]; then
    rm -- "${archives[@]:0:${#archives[@]}-KEEP}"
fi

# И обратно: .env и data/ ноутбука (подписка, GREEN_PASSWORD) — на сервер, в ~/backups/laptop.
# Пропадёт ноутбук — настройки останутся на сервере.
cd "$(dirname "$0")"
remote="backups/laptop/laptop-$(date +%Y-%m-%d_%H%M).tar.gz"
tar -czf - .env data | "${SSH[@]}" "umask 077 && mkdir -p backups/laptop && cat > $remote.tmp &&
    tar -tzf $remote.tmp .env >/dev/null && mv $remote.tmp $remote &&
    ls -1 backups/laptop/laptop-*.tar.gz | head -n -$KEEP | xargs -r rm --"
echo "ноутбук сохранён на сервере: ~/$remote"
