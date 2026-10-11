# lan_vpn_proxy

VPN-прокси на Xray в Docker вместо клиента Happ.

Правило простое: **контейнер запущен — трафик идёт через VPN, остановлен — напрямую.**
На ноутбук ничего не ставится, меняются только системные настройки прокси GNOME.

## Как это работает

- `docker-compose.yml` — контейнер `lan-vpn-proxy` с Xray. Слушает `127.0.0.1:1080` (SOCKS5) и `127.0.0.1:3128` (HTTP), сам перезапускается после сбоя и перезагрузки.
- `.env` — все настройки: подписка, выбор сервера, порты. Шаблон — `.env.example`.
- `gen_config.py` — собирает `xray/config.json` из подписки, указанной в `.env`. Через VPN идёт всё, кроме локальных сетей.
- `proxy-watch.sh` — следит за контейнером через `docker events` и переключает системный прокси GNOME: контейнер запущен — режим «вручную» на `127.0.0.1:3128`, остановлен, упал или Docker недоступен — режим «отключено».
- `lan-vpn-proxy-watch.service` — пользовательская служба systemd, которая держит `proxy-watch.sh` запущенным. Если служба остановлена, прокси тоже выключается.
- `web.py` и `lan-vpn-proxy-web.service` — веб-интерфейс с кнопкой «Включить/Выключить» на `http://127.0.0.1:8765`.

Через VPN идут только программы, которые используют системный прокси: Chrome, Firefox (с настройкой «Использовать системные настройки прокси»), большинство GUI-приложений. Терминал, Docker-контейнеры и остальное ходят напрямую.

## Установка

1. Вписать в `.env` адрес подписки от провайдера (в одинарных кавычках):

   ```bash
   SUBSCRIPTION='https://провайдер/подписка'
   ```

   Если `.env` нет, создать его из шаблона: `install -m 600 .env.example .env`.

   Выбрать сервер и собрать конфиг:

   ```bash
   ./gen_config.py --list    # список серверов из подписки
   # номер или часть названия записать в SERVER в .env; пусто — первый сервер
   ./gen_config.py           # записывает xray/config.json
   ```

   Поддерживаются подписки в base64, списком ссылок и в JSON-формате Xray, а также одиночные ссылки `vless://…`, `vmess://…`, `trojan://…`, `ss://…`. Ссылки `happ://…` зашифрованы для Happ — нужна обычная подписка от провайдера.

2. Запустить контейнер и проверить:

   ```bash
   docker compose up -d
   curl -x http://127.0.0.1:3128 https://ifconfig.me   # должен показать IP VPN-сервера
   ```

3. Выключить Happ, иначе он будет сам менять настройки прокси и маршруты: закрыть приложение и выполнить

   ```bash
   sudo systemctl disable --now happd
   ```

4. Включить службу, которая переключает прокси:

   ```bash
   systemctl --user link ~/projects/lan_vpn_proxy/lan-vpn-proxy-watch.service
   systemctl --user enable --now lan-vpn-proxy-watch.service
   ```

## Использование

```bash
docker compose start    # VPN включён
docker compose stop     # напрямую
```

Отдельная команда в терминале через VPN:

```bash
https_proxy=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128 <команда>
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me
```

Сменить сервер или обновить подписку — поправить `SERVER` или `SUBSCRIPTION` в `.env`, пересобрать конфиг и пересоздать контейнер:

```bash
./gen_config.py
docker compose up -d --force-recreate
```

Для разовой проверки `.env` можно не трогать: аргументы важнее значений из него, например `./gen_config.py 'vless://…' -s 2`.

## Веб-интерфейс

Страница с кнопкой «Включить/Выключить», состоянием контейнера и системного прокси и проверкой внешнего IP (через VPN и напрямую). Кнопка делает то же, что `docker compose up -d` и `docker compose stop`; прокси GNOME вслед за контейнером переключает служба из шага 4 установки. Написан на стандартной библиотеке Python, ничего ставить не нужно.

Включить и открыть:

```bash
systemctl --user link ~/projects/lan_vpn_proxy/lan-vpn-proxy-web.service
systemctl --user enable --now lan-vpn-proxy-web.service
xdg-open http://127.0.0.1:8765
```

Разово, без службы: `./web.py`.

Интерфейс управляет Docker, поэтому слушает только `127.0.0.1` и отвечает лишь на адреса `127.0.0.1:WEB_PORT` и `localhost:WEB_PORT`. Действия принимаются только как JSON-запросы со своей страницы — сторонний сайт, открытый в браузере, нажать кнопку за вас не сможет.

## Настройки

Все настройки — в `.env`. Значения со спецсимволами (`&`, `#`, `$`) берите в одинарные кавычки. Переменная окружения с тем же именем важнее значения из `.env`, как в docker compose.

| Переменная                | По умолчанию    | Назначение                                                     |
|---------------------------|-----------------|----------------------------------------------------------------|
| `SUBSCRIPTION`            | —               | URL подписки или одна ссылка `vless://…` и т.п.                |
| `SERVER`                  | первый          | номер из `./gen_config.py --list` или часть названия           |
| `SUBSCRIPTION_USER_AGENT` | `v2rayN/7.13.8` | от него зависит формат, в котором провайдер отдаёт подписку    |
| `BIND_ADDR`               | `127.0.0.1`     | `0.0.0.0` откроет прокси для устройств в локальной сети        |
| `SOCKS_PORT`              | `1080`          | порт SOCKS5 на ноутбуке                                        |
| `HTTP_PORT`               | `3128`          | порт HTTP; его же `proxy-watch.sh` прописывает в прокси GNOME  |
| `WEB_PORT`                | `8765`          | порт веб-интерфейса                                            |
| `PUID`/`PGID`             | `1000`          | от чьего имени работает Xray (должен читать конфиг)            |

Что делать после изменения:

- `SUBSCRIPTION`, `SERVER`, `SUBSCRIPTION_USER_AGENT` — `./gen_config.py && docker compose up -d --force-recreate`;
- `BIND_ADDR`, порты, `PUID`/`PGID` — `docker compose up -d`, а для `HTTP_PORT` ещё и `systemctl --user restart lan-vpn-proxy-watch.service lan-vpn-proxy-web.service`;
- `WEB_PORT` — `systemctl --user restart lan-vpn-proxy-web.service`.

С `BIND_ADDR=0.0.0.0` прокси работает **без пароля**: им сможет пользоваться любой в той же Wi-Fi. В отелях и других чужих сетях не включайте.

Служба перезаписывает в GNOME список исключений прокси: localhost, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `*.local`. Список задан в `proxy-watch.sh`.

## Диагностика

```bash
docker compose logs -f                                  # логи Xray
journalctl --user -u lan-vpn-proxy-watch.service -f     # переключения прокси
gsettings get org.gnome.system.proxy mode               # manual — через VPN, none — напрямую
```

Для подробных логов Xray поменяйте `"loglevel": "warning"` на `"debug"` в `xray/config.json` и перезапустите контейнер.

## Удаление

```bash
systemctl --user disable --now lan-vpn-proxy-web.service
systemctl --user disable --now lan-vpn-proxy-watch.service   # прокси выключится сам
docker compose down
```

## Безопасность

`.env` и `xray/config.json` содержат ключи доступа к VPN. Держите их с правами `600` (конфиг создаётся так сам) и не публикуйте.
