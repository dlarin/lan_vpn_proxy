#!/usr/bin/env python3
"""Веб-интерфейс для включения и выключения lan-vpn-proxy: http://127.0.0.1:WEB_PORT.

Кнопка запускает и останавливает контейнер; системный прокси GNOME вслед за ним
переключает proxy-watch.sh. Ещё здесь обновление подписки, проверка серверов,
трафик по дням (замер раз в минуту в data/traffic.json) и рабочий VPN Cisco Secure Client.
Только стандартная библиотека Python.
"""
import base64
import collections
import datetime
import fcntl
import hmac
import http.client
import ipaddress
import json
import os
import re
import select
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree

from gen_config import (DEFAULT_OUTPUT, ENV_FILE, HEALTH_PORT, OUTBOUNDS_FILE, PROJECT_DIR, SERVERS_FILE, STATS_API,
                        build_check_config, build_config, config_settings, load_env, set_env_value, setting,
                        split_list, write_json)

CONTAINER = "lan-vpn-proxy"
WATCH_SERVICE = "lan-vpn-proxy-watch.service"
GATEWAY_SERVICE = "lan-vpn-proxy-gateway.service"  # шлюз: системная служба, правила nftables для сети
IP_URL = "https://ifconfig.me/ip"
SAMPLE_INTERVAL = 60  # секунд между замерами трафика и чтением журнала Xray
TRAFFIC_FILE = os.path.join(PROJECT_DIR, "data", "traffic.json")
TRAFFIC_DAYS_KEPT = 90
TRAFFIC_DAYS_SHOWN = 7
HOSTS_FILE = os.path.join(PROJECT_DIR, "data", "hosts.json")
HOSTS_DAYS_KEPT = 30
HOSTS_SHOWN = 100
# Устройства сети (шлюз): имена по MAC-адресу — IP по DHCP меняется, а MAC нет.
DEVICES_FILE = os.path.join(PROJECT_DIR, "data", "devices.json")
DEVICE_PREFIX = "устройство "
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# 2026/10/11 18:50:29.431418 from 127.0.0.1:43610 accepted //example.com:443 [http >> proxy]
ACCESS_LINE = re.compile(
    r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d+) from (\S+) accepted (\S+) \[\S+ (?:>>|->) (\S+)\]")
UNKNOWN_APP = "не определено"
SOCKETS_POLL = 2  # секунд между опросами ss: какое приложение держит соединение с прокси
SOCKETS_KEEP = 900  # сколько секунд помнить порт закрытого соединения
# Вторые уровни, под которыми регистрируют домены (example.co.uk); для группировки этого хватает.
SECOND_LEVELS = {"ac", "co", "com", "edu", "gov", "net", "org"}
CHECK_CONTAINER = "lan-vpn-proxy-check"
CHECK_FIRST_PORT = 20801  # проверка занимает 127.0.0.1:20801… — по порту на сервер
CHECK_URL = "https://www.gstatic.com/generate_204"
CHECK_TIMEOUT = 8
CISCO_VPN = "/opt/cisco/secureclient/bin/vpn"  # консольная утилита Cisco Secure Client
CISCO_PREFS = os.path.expanduser("~/.anyconnect")  # сервер и логин последнего подключения
CISCO_GUI = "vpnui"
CISCO_TIMEOUT = 120  # секунд на подключение: проверка ноутбука сервером и вход бывают долгими
CISCO_TUNNEL = "cscotun"  # сетевой интерфейс туннеля Cisco: есть, только пока VPN подключён
# Утилита переводит сообщения на язык системы; разбирать проще английские.
CISCO_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}
CISCO_GUI_HINT = ("Открыто окно Cisco Secure Client, а пока оно работает, Cisco не даёт подключаться "
                  "из других программ. Закройте его и нажмите ещё раз.")
# Значок вкладки — щит с туннелем. Цвет — как у точки состояния на странице, чтобы его было видно
# и по фоновой вкладке.
ICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<path d="M32 3 L57 11 V30 C57 46 46 56.5 32 61 C18 56.5 7 46 7 30 V11 Z" fill="{color}"/>'
        '<path d="M20 47 V33 A12 12 0 0 1 44 33 V47" fill="none" stroke="#fff" stroke-width="7" '
        'stroke-linecap="round"/></svg>')
ICON_COLORS = {"on": "#52c41a", "off": "#8c8c8c", "warn": "#faad14"}  # цвета Ant Design, как на странице

dotenv = load_env(ENV_FILE)
WEB_PORT = int(setting(dotenv, "WEB_PORT", "8765"))
# Адрес, на котором слушает интерфейс. Не 127.0.0.1 (например, 0.0.0.0 на домашнем сервере) —
# только с WEB_PASSWORD: страница управляет Docker.
WEB_BIND = setting(dotenv, "WEB_BIND", "127.0.0.1")
WEB_PASSWORD = setting(dotenv, "WEB_PASSWORD", "")
# HTTPS: без него пароль идёт по сети открытым текстом. auto — включён, если интерфейс открыт для сети.
WEB_TLS = setting(dotenv, "WEB_TLS", "auto")
WEB_TLS = WEB_TLS == "on" or (WEB_TLS == "auto" and WEB_BIND not in ("127.0.0.1", "localhost", "::1"))
# Самоподписанный сертификат: создаётся при первом запуске и заново, если поменялся WEB_HOSTS.
WEB_CERT = os.path.join(PROJECT_DIR, "data", "web.crt")
WEB_KEY = os.path.join(PROJECT_DIR, "data", "web.key")
# Подбор пароля: после LOGIN_MAX_FAILS неверных паролей за LOGIN_WINDOW секунд адрес ждёт до конца окна.
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 15 * 60
LOGIN_FAILS = collections.defaultdict(list)  # адрес -> время неверных попыток
LOGIN_LOCK = threading.Lock()
HTTP_PORT = setting(dotenv, "HTTP_PORT", "3128")
SOCKS_PORT = setting(dotenv, "SOCKS_PORT", "1080")
# Страница управляет Docker, поэтому отвечаем только на свои адреса: это защищает
# от DNS rebinding и от запросов, которые чужой сайт отправит из браузера.
# WEB_HOSTS — адреса и имена, по которым страницу открывают из сети (192.168.0.141 и т.п.).
ALLOWED_HOSTS = {f"{host}:{WEB_PORT}" for host in ["127.0.0.1", "localhost", *split_list(setting(dotenv, "WEB_HOSTS"))]}
ALLOWED_ORIGINS = {f"{'https' if WEB_TLS else 'http'}://{host}" for host in ALLOWED_HOSTS}
class ActionLock:
    """Одно действие с конфигом и контейнером за раз — и между потоками службы, и с `web.py rules-set`
    (его отдельным процессом запускает sync-rules.py): потоки ждут threading.Lock, процессы — flock."""

    def __init__(self, path):
        self.path = path
        self.threads = threading.Lock()
        self.file = None

    def __enter__(self):
        self.threads.acquire()
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self.file = open(self.path, "a")
            fcntl.flock(self.file, fcntl.LOCK_EX)
        except BaseException:
            if self.file:
                self.file.close()
                self.file = None
            self.threads.release()
            raise
        return self

    def __exit__(self, *_):
        self.file.close()  # закрытие снимает flock
        self.file = None
        self.threads.release()


ACTION_LOCK = ActionLock(os.path.join(PROJECT_DIR, "data", "action.lock"))
CHECK_LOCK = threading.Lock()
# Автопереключение: раз в AUTO_INTERVAL секунд запрос через текущий сервер; AUTO_FAILS неудач подряд —
# проверка всех серверов и переход на самый быстрый рабочий. SUBSCRIPTION_REFRESH — раз во сколько часов
# обновлять подписку (0 — не обновлять); работающий VPN при этом не перезапускается.
AUTO_SWITCH = setting(dotenv, "AUTO_SWITCH", "off") == "on"
SUBSCRIPTION_REFRESH = float(setting(dotenv, "SUBSCRIPTION_REFRESH", "0"))
AUTO_INTERVAL = 120
AUTO_FAILS = 3
# Результат последней проверки: задержка в мс по названию сервера, None — не работает.
last_check = {"time": None, "delays": {}}


def run(*cmd, timeout=60, env=None):
    """Возвращает (успех, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, "", str(e)
    return result.returncode == 0, result.stdout.strip(), result.stderr.strip()


def container_state():
    ok, out, _ = run("docker", "inspect", CONTAINER, timeout=10)
    if not ok:
        return {"exists": False, "running": False, "restarting": False, "status": "не создан"}
    state = json.loads(out)[0]["State"]
    return {
        "exists": True,
        "running": state["Running"] and not state["Restarting"],
        "restarting": state["Restarting"],
        "status": state["Status"],
    }


def read_vpn_bytes():
    """(отправлено, получено) через VPN с прошлого замера; счётчики Xray при этом обнуляются.

    Через VPN = всё, что пришло в прокси, минус ушедшее с него напрямую (локальные сети,
    а в режиме filter — всё не из списков).
    """
    ok, out, _ = run("docker", "exec", CONTAINER, "xray", "api", "statsquery",
                     f"--server={STATS_API}", "-reset", timeout=10)
    if not ok:
        return 0, 0  # контейнер выключен — через VPN ничего не прошло
    totals = collections.Counter()
    for stat in json.loads(out).get("stat", []):
        kind, tag, _, direction = stat["name"].split(">>>")
        if (kind == "inbound" and tag != "health") or (kind == "outbound" and tag == "direct"):
            # Нулевые значения Xray не выводит вовсе.
            totals[kind, direction] += int(stat.get("value", 0))
    return (max(totals["inbound", "uplink"] - totals["outbound", "uplink"], 0),
            max(totals["inbound", "downlink"] - totals["outbound", "downlink"], 0))


def read_nic_bytes():
    """Счётчики физических сетевых карт с момента загрузки системы."""
    ifaces = {}
    for name in os.listdir("/sys/class/net"):
        base = os.path.join("/sys/class/net", name)
        # lo, docker0, br-*, veth* виртуальные: их внешний трафик уже есть на физических картах.
        if not os.path.exists(os.path.join(base, "device")):
            continue
        with open(os.path.join(base, "statistics", "rx_bytes")) as rx, open(os.path.join(base, "statistics", "tx_bytes")) as tx:
            ifaces[name] = {"rx": int(rx.read()), "tx": int(tx.read())}
    with open("/proc/sys/kernel/random/boot_id") as f:
        return {"boot_id": f.read().strip(), "ifaces": ifaces}


class Traffic:
    """Трафик по дням: через VPN — по счётчикам Xray, всего — по счётчикам сетевых карт."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"nic": None, "days": {}}
        try:
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            pass
        except ValueError as e:
            print(f"трафик: {path} повреждён ({e}), начинаю заново", flush=True)

    def sample(self):
        vpn_up, vpn_down = read_vpn_bytes()
        nic = read_nic_bytes()
        with self.lock:
            last = self.data["nic"]
            self.data["nic"] = nic
            if last is None:
                return self.save()  # первый замер — только точка отсчёта
            same_boot = last["boot_id"] == nic["boot_id"]
            rx = tx = 0
            for name, cur in nic["ifaces"].items():
                prev = last["ifaces"].get(name) if same_boot else None
                # Новая карта, перезагрузка или переподключение адаптера — счётчик начался с нуля.
                rx += cur["rx"] - prev["rx"] if prev and cur["rx"] >= prev["rx"] else cur["rx"]
                tx += cur["tx"] - prev["tx"] if prev and cur["tx"] >= prev["tx"] else cur["tx"]
            day = self.data["days"].setdefault(
                datetime.date.today().isoformat(), {"vpn_up": 0, "vpn_down": 0, "nic_rx": 0, "nic_tx": 0})
            day["vpn_up"] += vpn_up
            day["vpn_down"] += vpn_down
            day["nic_rx"] += rx
            day["nic_tx"] += tx
            for old in sorted(self.data["days"])[:-TRAFFIC_DAYS_KEPT]:
                del self.data["days"][old]
            self.save()

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)

    def summary(self):
        with self.lock:
            days = sorted(self.data["days"].items(), reverse=True)[:TRAFFIC_DAYS_SHOWN]
        # «Напрямую» — всё на сетевых картах минус VPN; туда же попадают локальная сеть
        # и накладные расходы шифрования туннеля.
        return [{
            "date": date,
            "vpn_down": d["vpn_down"],
            "vpn_up": d["vpn_up"],
            "direct_down": max(d["nic_rx"] - d["vpn_down"], 0),
            "direct_up": max(d["nic_tx"] - d["vpn_up"], 0),
        } for date, d in days]

TRAFFIC = Traffic(TRAFFIC_FILE)


def host_of(destination):
    """Хост из адреса в журнале Xray: //host:443, http://host:80/path, tcp:host:443."""
    if "://" in destination:
        destination = destination.split("://", 1)[1]
    elif destination.startswith("//"):
        destination = destination[2:]
    elif destination[:4] in ("tcp:", "udp:"):
        destination = destination[4:]
    destination = destination.split("/", 1)[0].lower()
    if destination.startswith("["):
        return destination[1:destination.find("]")]
    return destination.rsplit(":", 1)[0]


def domain_of(host):
    """Домен, под которым группировать хост: mc.yandex.ru → yandex.ru. IP-адреса не трогаем."""
    labels = host.split(".")
    if ":" in host or host.replace(".", "").isdigit() or len(labels) <= 2:
        return host
    keep = 3 if labels[-2] in SECOND_LEVELS and len(labels[-1]) == 2 else 2
    return ".".join(labels[-keep:])


class ClientSockets:
    """Отладка: какое приложение держит какой порт соединения с прокси — опрос ss раз в SOCKETS_POLL секунд.

    Xray пишет в журнал порт программы-клиента; по нему HostLog находит приложение.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.ports = {}  # порт клиента → {"app", "first", "last"}
        self.names = {}  # pid → название приложения

    def app_name(self, pid):
        # Имя исполняемого файла — то же, с чем сравнивает правила VPN_APPS сам Xray.
        if pid not in self.names:
            try:
                name = os.path.basename(os.readlink(f"/proc/{pid}/exe")).removesuffix(" (deleted)")
            except OSError:
                name = ""
            self.names[pid] = name or f"pid {pid}"
        return self.names[pid]

    def poll(self):
        ok, out, _ = run("ss", "-tnpH", "state", "established",
                         f"( dport = :{HTTP_PORT} or dport = :{SOCKS_PORT} )", timeout=5)
        if not ok:
            return
        now = time.time()
        with self.lock:
            for line in out.splitlines():
                parts, pid = line.split(), re.search(r"pid=(\d+)", line)
                if len(parts) < 4 or not pid:
                    continue  # процесс другого пользователя: без root ss его не показывает
                port, app = int(parts[2].rsplit(":", 1)[1]), self.app_name(int(pid[1]))
                entry = self.ports.get(port)
                if entry and entry["app"] == app and now - entry["last"] <= SOCKETS_POLL * 3:
                    entry["last"] = now
                else:
                    self.ports[port] = {"app": app, "first": now, "last": now}
            for port in [p for p, e in self.ports.items() if now - e["last"] > SOCKETS_KEEP]:
                del self.ports[port]
            if len(self.names) > 1000:
                self.names.clear()

    def app_for(self, port, at):
        with self.lock:
            entry = self.ports.get(port)
        # Соединение могло открыться до опроса, в котором мы его увидели.
        if entry and entry["first"] - SOCKETS_POLL * 2 <= at <= entry["last"] + SOCKETS_POLL:
            return entry["app"]
        return None

    def run_forever(self):
        while True:
            try:
                self.poll()
            except Exception as e:  # сбой опроса не должен останавливать веб-интерфейс
                print(f"ss: {e}", flush=True)
            time.sleep(SOCKETS_POLL)


SOCKETS = ClientSockets()


class Devices:
    """Устройства сети, которые ходят через шлюз: MAC → последний IP и имя, которое дал пользователь."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        try:
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
        except (FileNotFoundError, ValueError):
            self.data = {}

    @staticmethod
    def neighbours():
        """IP → MAC из таблицы соседей: устройство, которое только что подключалось, в ней есть."""
        _, out, _ = run("ip", "neigh", "show", timeout=5)
        table = {}
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                table[parts[0]] = parts[parts.index("lladdr") + 1].lower()
        return table

    def key_for(self, ip, neighbours):
        """Ключ для статистики: «устройство <MAC>», а если MAC не узнать — «устройство <IP>»."""
        mac = neighbours.get(ip)
        if not mac:
            return DEVICE_PREFIX + ip
        with self.lock:
            self.data.setdefault(mac, {})["ip"] = ip
        return DEVICE_PREFIX + mac

    def save(self):
        with self.lock:
            write_json(self.path, self.data)

    def resolve(self, app):
        """(подпись, MAC или None) для строки статистики."""
        if not app.startswith(DEVICE_PREFIX):
            return app, None
        ident = app[len(DEVICE_PREFIX):]
        with self.lock:
            if not MAC.match(ident):  # старая запись по IP — ищем устройство с этим адресом
                ident = next((mac for mac, d in self.data.items() if d.get("ip") == ident), ident)
            device = self.data.get(ident)
        if not device:
            return app, None
        return device.get("name") or DEVICE_PREFIX + device.get("ip", ident), ident

    def rename(self, body):
        mac = str((body or {}).get("device", "")).lower() if isinstance(body, dict) else ""
        name = str(body.get("name", "")).strip() if isinstance(body, dict) else ""
        if not MAC.match(mac) or mac not in self.data:
            return False, "Нет такого устройства"
        if len(name) > 40 or any(not c.isprintable() for c in name):
            return False, "Имя — до 40 обычных символов"
        with self.lock:
            if name:
                self.data[mac]["name"] = name
            else:
                self.data[mac].pop("name", None)
            write_json(self.path, self.data)
        return True, f"Устройство {self.data[mac].get('ip', mac)}: " + (f"«{name}»" if name else "имя убрано")


DEVICES = Devices(DEVICES_FILE)


class HostLog:
    """Отладка: подключения через VPN по приложениям, хостам и дням — из журнала доступа Xray (docker logs)."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"since": None, "last": "", "days": {}}  # days: {день: {приложение: {хост: n}}}
        try:
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            pass
        except ValueError as e:
            print(f"хосты: {path} повреждён ({e}), начинаю заново", flush=True)
        # Первая версия не знала приложений: {день: {хост: n}}.
        for day, by_app in self.data["days"].items():
            if by_app and isinstance(next(iter(by_app.values())), int):
                self.data["days"][day] = {UNKNOWN_APP: by_app}

    def sample(self):
        with self.lock:
            started = time.time()
            since = ["--since", str(self.data["since"])] if self.data["since"] else []
            ok, out, err = run("docker", "logs", *since, CONTAINER, timeout=30)
            if not ok:
                return
            last = self.data["last"]
            neighbours = None  # таблицу соседей читаем, только если есть подключения из сети
            for line in (out + "\n" + err).splitlines():
                match = ACCESS_LINE.match(line)
                # --since берём с запасом, а уже учтённые строки отсекаем по их времени.
                if not match or match[4] != "proxy" or match[1] <= self.data["last"]:
                    continue
                # Xray в контейнере пишет время в UTC.
                at = datetime.datetime.strptime(match[1], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
                # HTTP-вход пишет «127.0.0.1:43610», SOCKS — «tcp:127.0.0.1:43610».
                source = match[2].removeprefix("tcp:").removeprefix("udp:")
                source_ip, _, source_port = source.rpartition(":")
                source_ip = source_ip.strip("[]")
                if source_ip in ("127.0.0.1", "::1"):
                    app = SOCKETS.app_for(int(source_port), at.timestamp()) or UNKNOWN_APP
                else:  # шлюз или BIND_ADDR=0.0.0.0: устройство из локальной сети
                    if neighbours is None:
                        neighbours = DEVICES.neighbours()
                    app = DEVICES.key_for(source_ip, neighbours)
                hosts = self.data["days"].setdefault(at.astimezone().date().isoformat(), {}).setdefault(app, {})
                host = host_of(match[3])
                hosts[host] = hosts.get(host, 0) + 1
                last = max(last, match[1])
            self.data["since"] = round(started - 5, 3)
            self.data["last"] = last
            for old in sorted(self.data["days"])[:-HOSTS_DAYS_KEPT]:
                del self.data["days"][old]
            write_json(self.path, self.data)  # это история посещений — права 600
            if neighbours:
                DEVICES.save()

    def reset(self):
        """Стирает статистику; считать начинаем с этого момента, а не с начала журнала контейнера."""
        with self.lock:
            self.data["days"] = {}
            self.data["since"] = round(time.time() - 5, 3)
            # Строки журнала не позже этого времени sample() считает уже учтёнными.
            self.data["last"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y/%m/%d %H:%M:%S.%f")
            write_json(self.path, self.data)
        return True, "Статистика по хостам сброшена"

    def summary(self, days, group, app=None):
        """Приложения — за весь период; хосты — только выбранного приложения (app=None — всех)."""
        cutoff = (datetime.date.today() - datetime.timedelta(days=days - 1)).isoformat()
        apps, hosts = collections.Counter(), collections.Counter()
        host_apps = collections.defaultdict(collections.Counter)
        labels = {}  # ключ статистики → (подпись, MAC); старые записи по IP и новые по MAC — одно устройство
        with self.lock:
            for day, by_app in self.data["days"].items():
                if day < cutoff:
                    continue
                for name, by_host in by_app.items():
                    label, mac = DEVICES.resolve(name)
                    name = DEVICE_PREFIX + mac if mac else name
                    labels[name] = (label, mac)
                    for host, n in by_host.items():
                        apps[name] += n
                        if app in (None, name):
                            key = domain_of(host) if group else host
                            hosts[key] += n
                            host_apps[key][name] += n
        top = hosts.most_common(HOSTS_SHOWN)
        total = sum(hosts.values())
        return {
            "apps": [{"app": name, "label": labels[name][0], "device": labels[name][1], "count": n}
                     for name, n in apps.most_common()],
            "apps_total": sum(apps.values()),
            "total": total,
            "hosts_total": len(hosts),
            "hosts": [{"host": host, "count": n, "apps": [labels[a][0] for a, _ in host_apps[host].most_common(3)]}
                      for host, n in top],
            "other_hosts": len(hosts) - len(top),
            "other_count": total - sum(n for _, n in top),
        }


HOSTS = HostLog(HOSTS_FILE)


def collect_forever():
    """Раз в минуту: трафик по дням и подключения по хостам."""
    while True:
        for job in (TRAFFIC.sample, HOSTS.sample):
            try:
                job()
            except Exception as e:  # сбой замера не должен останавливать сбор и веб-интерфейс
                print(f"{job.__qualname__}: {e}", flush=True)
        time.sleep(SAMPLE_INTERVAL)


def load_servers():
    """Список серверов, который сохранил gen_config.py; None — конфиг ещё не собирали."""
    try:
        with open(SERVERS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return None


def load_chains():
    """Outbound-ы всех серверов с ключами; [] — нет данных или они не совпадают со списком."""
    try:
        with open(OUTBOUNDS_FILE, encoding="utf-8") as f:
            chains = json.load(f)
    except (FileNotFoundError, ValueError):
        return []
    return chains if len(chains) == len((load_servers() or {}).get("servers", [])) else []


def servers_info():
    """Список серверов для страницы — вместе с результатом последней проверки."""
    return {**(load_servers() or {"servers": []}), "check": last_check}


def test_config(config):
    """Ошибка Xray для этого конфига или None — чтобы неверная запись в списках не уронила VPN."""
    tmp = tempfile.mkdtemp(prefix="lvp-test-")
    try:
        write_json(os.path.join(tmp, "config.json"), config)
        _, image, _ = run("docker", "compose", "config", "--images")
        ok, out, err = run("docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                           "-v", f"{tmp}:/c:ro", image, "run", "-test", "-c", "/c/config.json", timeout=30)
        if ok:
            return None
        failed = [line for line in (out + "\n" + err).splitlines() if "ailed" in line]
        return (failed[-1] if failed else err or out)[-400:]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def write_server_config(index, settings):
    """Собирает и проверяет конфиг для сервера index; (ошибка или None)."""
    servers, chains = load_servers(), load_chains()
    if not chains:
        return "Нет данных о серверах — нажмите «Обновить подписку»"
    if not isinstance(index, int) or not 0 <= index < len(chains):
        return "Нет такого сервера"
    config = build_config({"outbounds": chains[index]}, **settings)
    error = test_config(config)
    if error:
        return f"Xray не принял конфиг: {error}"
    write_json(DEFAULT_OUTPUT, config)
    write_json(SERVERS_FILE, {**servers, "current": index})
    return None


def restart_if_running():
    """(успех, перезапущен ли контейнер): новый конфиг Xray читает только при старте."""
    if not container_state()["running"]:
        return True, False
    ok, _, err = run("docker", "compose", "up", "-d", "--force-recreate")
    return (True, True) if ok else (False, err)


def select_server(index):
    with ACTION_LOCK:
        error = write_server_config(index, config_settings(load_env(ENV_FILE)))
        if error:
            return False, error
        name = load_servers()["servers"][index]["name"]
        # Иначе «Обновить подписку» и ./gen_config.py вернули бы прежний сервер.
        set_env_value(ENV_FILE, "SERVER", name)
        ok, restarted = restart_if_running()
    if not ok:
        return False, restarted
    return True, f"VPN переключён на {name}." if restarted else \
        f"Выбран сервер {name}. VPN выключен — включите его на главной вкладке."


def rules_info():
    dotenv = load_env(ENV_FILE)
    settings = config_settings(dotenv)
    # Шлюз (TPROXY_PORT): трафик приходит с других устройств, их программ Xray не видит.
    return {**settings["routing"], "gateway": settings["tproxy_port"] > 0,
            "updated": int(setting(dotenv, "RULES_UPDATED", "0") or 0)}


def save_rules(body, updated=None):
    """updated — время изменения правил (unix): sync-rules.py переносит его с другой машины как есть."""
    if not isinstance(body, dict) or body.get("mode") not in ("all", "filter"):
        return False, "Неверный режим"
    lists = {}
    for key in ("apps", "hosts", "direct"):
        items = body.get(key)
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            return False, "Неверный список"
        lists[key] = list(dict.fromkeys(item.strip() for item in items if item.strip()))
        # В .env список хранится через запятую в кавычках.
        bad = next((item for item in lists[key] if any(c in item for c in ",'\"") or any(c.isspace() for c in item)), None)
        if bad:
            return False, f"Недопустимые символы в записи «{bad}»: запятые, кавычки и пробелы нельзя"
    if body["mode"] == "filter" and not lists["apps"] and not lists["hosts"]:
        return False, "Списки пусты — в режиме «по списку» через VPN не пойдёт ничего"
    settings = config_settings(load_env(ENV_FILE))
    settings["routing"] = {"mode": body["mode"], **lists}
    with ACTION_LOCK:
        before = comparable_config()
        error = write_server_config((load_servers() or {}).get("current"), settings)
        if error:
            return False, error
        set_env_value(ENV_FILE, "ROUTING_MODE", body["mode"])
        set_env_value(ENV_FILE, "VPN_APPS", ", ".join(lists["apps"]))
        set_env_value(ENV_FILE, "VPN_HOSTS", ", ".join(lists["hosts"]))
        set_env_value(ENV_FILE, "DIRECT_HOSTS", ", ".join(lists["direct"]))
        # По нему sync-rules.py решает, чьи правила новее — ноутбука или green.
        set_env_value(ENV_FILE, "RULES_UPDATED", str(updated if isinstance(updated, int) and updated > 0 else int(time.time())))
        # Конфиг тот же (например, на шлюзе поменяли только VPN_APPS) — не рвём соединения перезапуском.
        # Исключения прокси GNOME из DIRECT_HOSTS proxy-watch.sh берёт при перезапуске, но DIRECT_HOSTS
        # есть и в конфиге — его правка конфиг меняет.
        ok, restarted = restart_if_running() if comparable_config() != before else (True, False)
    if not ok:
        return False, restarted
    mode = "всё через VPN" if body["mode"] == "all" else \
        f"по списку: приложений {len(lists['apps'])}, хостов {len(lists['hosts'])}"
    direct = f", всегда напрямую: {len(lists['direct'])}" if lists["direct"] else ""
    return True, f"Сохранено, режим — {mode}{direct}." + (" Контейнер перезапущен." if restarted else "")


def comparable_config():
    """Конфиг без shortId: подписка каждый раз выдаёт другой, а работают все."""
    try:
        with open(DEFAULT_OUTPUT, encoding="utf-8") as f:
            config = json.load(f)
    except (FileNotFoundError, ValueError):
        return None
    for outbound in config.get("outbounds", []):
        outbound.get("streamSettings", {}).get("realitySettings", {}).pop("shortId", None)
    return config


def update_subscription():
    before = comparable_config()
    with ACTION_LOCK:
        ok, _, err = run(sys.executable, os.path.join(PROJECT_DIR, "gen_config.py"), timeout=90)
        if not ok:
            return False, err
        message = f"Подписка обновлена, серверов: {len(servers_info()['servers'])}."
        if comparable_config() != before and container_state()["running"]:
            ok, _, err = run("docker", "compose", "up", "-d", "--force-recreate")
            if not ok:
                return False, err
            message += " Настройки сервера изменились — контейнер перезапущен."
    return True, message


def probe(port):
    """Задержка запроса через прокси на этом порту, мс; None — сервер не работает."""
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    start = time.monotonic()
    try:
        with opener.open(CHECK_URL, timeout=CHECK_TIMEOUT) as response:
            response.read()
    except (OSError, http.client.HTTPException):
        return None
    return round((time.monotonic() - start) * 1000)


def wait_started(container, timeout=10):
    # Порт на хосте Docker открывает раньше, чем Xray начнёт слушать, поэтому ждём строку в журнале.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, out, err = run("docker", "logs", container, timeout=5)
        if " started" in out + err:
            return True
        time.sleep(0.3)
    return False


def check_servers():
    """Настоящая проверка: временный Xray, где каждый сервер — HTTP-прокси на своём порту, и запрос через каждый."""
    if not CHECK_LOCK.acquire(blocking=False):
        return False, "Проверка уже идёт"
    tmp = tempfile.mkdtemp(prefix="lvp-check-")
    try:
        servers, chains = servers_info()["servers"], load_chains()
        if not chains:
            return False, "Нет данных для проверки — нажмите «Обновить подписку»"
        write_json(os.path.join(tmp, "config.json"), build_check_config(chains, CHECK_FIRST_PORT))
        ports = range(CHECK_FIRST_PORT, CHECK_FIRST_PORT + len(chains))
        _, image, _ = run("docker", "compose", "config", "--images")
        run("docker", "rm", "-fv", CHECK_CONTAINER)  # остаток прерванной проверки
        # Сеть хоста, как у основного контейнера: на шлюзе Docker не управляет iptables
        # ("iptables": false), и в сети bridge у Xray нет ни выхода в интернет, ни проброса портов.
        ok, _, err = run("docker", "run", "-d", "--rm", "--name", CHECK_CONTAINER,
                         "--user", f"{os.getuid()}:{os.getgid()}", "--network", "host",
                         "-v", f"{tmp}:/config:ro", image, "run", "-c", "/config/config.json")  # как в compose
        if not ok:
            return False, err
        try:
            if not wait_started(CHECK_CONTAINER):
                return False, "Xray для проверки не запустился"
            with ThreadPoolExecutor(max_workers=len(chains)) as pool:
                delays = list(pool.map(probe, ports))
        finally:
            # -v: иначе остаются анонимные тома образа (VOLUME), по два на каждую проверку
            run("docker", "rm", "-fv", CHECK_CONTAINER)
        last_check.update(time=datetime.datetime.now().isoformat(timespec="minutes"),
                          delays={s["name"]: d for s, d in zip(servers, delays)})
        return True, f"Работают {sum(d is not None for d in delays)} из {len(delays)}."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        CHECK_LOCK.release()


class AutoSwitch:
    """Автопереключение на рабочий сервер и обновление подписки по расписанию (AUTO_SWITCH, SUBSCRIPTION_REFRESH)."""

    def __init__(self):
        self.fails = 0
        self.probe = None  # {"time", "delay"} последней проверки текущего сервера
        self.event = None  # {"time", "text"} последнего переключения или неудачи
        self.refreshed = None

    def info(self):
        return {"enabled": AUTO_SWITCH, "refresh_hours": SUBSCRIPTION_REFRESH, "probe": self.probe,
                "fails": self.fails, "event": self.event, "refreshed": self.refreshed}

    def note(self, text):
        self.event = {"time": now_minutes(), "text": text}
        print(f"автопереключение: {text}", flush=True)

    def run_forever(self):
        next_refresh = time.monotonic() + SUBSCRIPTION_REFRESH * 3600
        while True:
            time.sleep(AUTO_INTERVAL)
            for enabled, job in ((AUTO_SWITCH, self.check),
                                 (SUBSCRIPTION_REFRESH and time.monotonic() >= next_refresh, self.refresh)):
                if not enabled:
                    continue
                try:
                    job()
                except Exception as e:  # сбой не должен останавливать задачу и веб-интерфейс
                    print(f"{job.__qualname__}: {e}", flush=True)
            if SUBSCRIPTION_REFRESH and time.monotonic() >= next_refresh:
                next_refresh = time.monotonic() + SUBSCRIPTION_REFRESH * 3600

    def check(self):
        # VPN выключен — трафик и так напрямую, проверять нечего.
        if not container_state()["running"]:
            self.fails = 0
            return
        # Конфиг, собранный до появления входа health, проверить нельзя — не считаем это сбоем сервера.
        try:
            with open(DEFAULT_OUTPUT, encoding="utf-8") as f:
                if not any(i.get("tag") == "health" for i in json.load(f).get("inbounds", [])):
                    return
        except (OSError, ValueError):
            return
        delay = probe(HEALTH_PORT)
        self.probe = {"time": now_minutes(), "delay": delay}
        if delay is not None:
            self.fails = 0
            return
        self.fails += 1
        if self.fails >= AUTO_FAILS:
            self.switch()

    def switch(self):
        self.fails = 0  # следующая полная проверка — не раньше чем через AUTO_FAILS неудач
        info = load_servers()
        old = info["servers"][info["current"]]["name"] if info else "?"
        ok, message = check_servers()
        if not ok:
            return self.note(f"{old} не отвечает, проверить серверы не вышло: {message}")
        servers = load_servers()["servers"]
        delays = [last_check["delays"].get(s["name"]) for s in servers]
        if delays[info["current"]] is not None:
            return  # при полной проверке текущий сервер ответил — сбой был временным
        working = sorted((d, i) for i, d in enumerate(delays) if d is not None)
        if not working:
            return self.note(f"{old} не отвечает, рабочих серверов нет — возможно, нет интернета")
        new = servers[working[0][1]]["name"]
        ok, message = select_server(working[0][1])
        self.note(f"переключён с {old} на {new}: {old} не отвечал" if ok else f"переключиться на {new} не вышло: {message}")

    def refresh(self):
        """Свежий список серверов и ключи. Рабочий конфиг не трогаем: смена адреса у провайдера
        (rucash/rucash2) иначе перезапускала бы VPN каждый раз; если текущий сервер умрёт,
        check переключит на сервер уже из свежего списка."""
        tmp = tempfile.mkdtemp(prefix="lvp-refresh-")
        try:
            with ACTION_LOCK:
                ok, _, err = run(sys.executable, os.path.join(PROJECT_DIR, "gen_config.py"),
                                 "-o", os.path.join(tmp, "config.json"), timeout=90)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if ok:
            self.refreshed = now_minutes()
        else:
            self.note(f"обновить подписку не вышло: {err[-200:]}")


def now_minutes():
    return datetime.datetime.now().isoformat(timespec="minutes")


AUTO = AutoSwitch()


class XrayRelease:
    """Новые версии Xray: раз в день сверяет тег образа в docker-compose.yml с релизами на GitHub.

    latest — последний релиз, который разработчики пометили основным (так они выпускают и срочные
    обновления безопасности); withdrawn — нашего тега на GitHub больше нет, версию отозвали.
    Без доступа к GitHub (green) просто молчит.
    """
    API = "https://api.github.com/repos/XTLS/Xray-core/releases"
    INTERVAL = 24 * 3600
    RETRY = 3600

    def __init__(self):
        self.latest = self.withdrawn = self.checked = None

    @staticmethod
    def current():
        try:
            with open(os.path.join(PROJECT_DIR, "docker-compose.yml"), encoding="utf-8") as f:
                match = re.search(r"image:\s*\S*xray-core:(\S+)", f.read())
        except OSError:
            return None
        return match and match.group(1)

    @staticmethod
    def newer(a, b):
        """a новее b; теги вида 26.10.21 (бывает v впереди)."""
        def key(tag):
            return [int(part) for part in re.findall(r"\d+", tag)]
        return key(a) > key(b)

    def get(self, path):
        request = urllib.request.Request(self.API + path, headers={"User-Agent": "lan-vpn-proxy",
                                                                   "Accept": "application/vnd.github+json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=15) as response:
            return json.load(response)

    def check(self):
        current = self.current()
        if not current:
            return
        self.latest = self.get("/latest")["tag_name"].lstrip("v")
        try:
            self.get(f"/tags/v{current}")
            self.withdrawn = False
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            self.withdrawn = True
        self.checked = now_minutes()

    def info(self):
        current = self.current()
        return {"current": current, "latest": self.latest, "checked": self.checked, "withdrawn": bool(self.withdrawn),
                "update": bool(current and self.latest and self.newer(self.latest, current))}

    def run_forever(self):
        while True:
            try:
                self.check()
                time.sleep(self.INTERVAL)
            except (OSError, ValueError, KeyError, http.client.HTTPException):
                time.sleep(self.RETRY)


XRAY = XrayRelease()


def status():
    _, mode, _ = run("gsettings", "get", "org.gnome.system.proxy", "mode", timeout=5)
    _, port, _ = run("gsettings", "get", "org.gnome.system.proxy.http", "port", timeout=5)
    routing = rules_info()
    # На шлюзе GNOME нет — вместо наблюдателя за прокси важна служба, которая включает VPN для сети.
    _, watcher, _ = run("systemctl", *([] if routing["gateway"] else ["--user"]), "is-active",
                        GATEWAY_SERVICE if routing["gateway"] else WATCH_SERVICE, timeout=5)
    servers = load_servers()
    return {
        **container_state(),
        "config": os.path.isfile(DEFAULT_OUTPUT),
        "proxy_mode": mode.strip("'"),
        "proxy_port": port,
        "http_port": HTTP_PORT,
        "watcher": watcher == "active",
        "traffic": TRAFFIC.summary(),
        "server": servers["servers"][servers["current"]] if servers else None,
        "routing": routing,
        "servers_updated": servers["updated"] if servers else None,
        "cisco": CISCO.info(),
        "auto": AUTO.info(),
        "xray": XRAY.info(),
    }


def turn_on():
    if not os.path.isfile(DEFAULT_OUTPUT):
        return False, "Нет xray/config.json: заполните SUBSCRIPTION в .env и запустите ./gen_config.py"
    with ACTION_LOCK:
        ok, _, err = run("docker", "compose", "up", "-d")
    return ok, "" if ok else err


def turn_off():
    with ACTION_LOCK:
        ok, _, err = run("docker", "compose", "stop")
    return ok, "" if ok else err


def fetch_ip(proxy=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}))
    request = urllib.request.Request(IP_URL, headers={"User-Agent": "curl/8"})
    try:
        with opener.open(request, timeout=8) as response:
            return response.read().decode("utf-8", "replace").strip()[:64]
    except (OSError, http.client.HTTPException) as e:
        return f"ошибка: {e}"


def check_ip():
    vpn = fetch_ip(f"http://127.0.0.1:{HTTP_PORT}") if container_state()["running"] else None
    return {"vpn": vpn, "direct": fetch_ip()}


def cisco_prefs():
    """Сервер и логин, с которыми Cisco Secure Client подключался последний раз."""
    try:
        root = ElementTree.parse(CISCO_PREFS).getroot()
    except (OSError, ElementTree.ParseError):
        return {"host": "", "user": ""}
    return {"host": root.findtext("DefaultHostName") or "", "user": root.findtext("DefaultUser") or ""}


def cisco_host():
    # CISCO_HOST из .env важнее сервера последнего подключения.
    return setting(load_env(ENV_FILE), "CISCO_HOST") or cisco_prefs()["host"]


def cisco_gui_running():
    return run("pgrep", "-x", CISCO_GUI, timeout=5)[0]


def cisco_error(output, default):
    """Понятное сообщение из вывода утилиты vpn."""
    if "capability is unavailable" in output:
        return CISCO_GUI_HINT
    if "Login failed" in output:
        return "Сервер не принял логин, пароль или код."
    errors = re.findall(r">> ((?:error|warning): [^\n]*)", output)
    return "; ".join(dict.fromkeys(errors)) or default


class Cisco:
    """Рабочий VPN: подключение через консольную утилиту Cisco Secure Client.

    Пароль и код никуда не записываются: они сразу уходят в утилиту.
    """

    def __init__(self):
        self.action = threading.Lock()  # одно подключение или отключение за раз

    def installed(self):
        return os.access(CISCO_VPN, os.X_OK)

    def connected(self):
        # По интерфейсу туннеля, а не через vpn state: тот идёт пару секунд и при каждом
        # запуске пишет в журнал службы десяток строк, а страница спрашивает раз в 3 секунды.
        return any(name.startswith(CISCO_TUNNEL) for name in os.listdir("/sys/class/net"))

    def info(self):
        if not self.installed():
            return None
        return {"state": "Connected" if self.connected() else "Disconnected", "busy": self.action.locked(),
                "host": cisco_host(), "user": cisco_prefs()["user"], "gui": cisco_gui_running()}

    def connect(self, body):
        fields = [body.get(key) if isinstance(body, dict) else None for key in ("user", "password", "otp")]
        if not all(isinstance(value, str) for value in fields):
            return False, "Неверный запрос"
        user, password, otp = fields[0].strip(), fields[1], fields[2].strip()
        if not user or not password:
            return False, "Введите логин и пароль"
        # Перевод строки утилита приняла бы за ответ на следующий вопрос.
        if any(c in value for value in (user, password, otp) for c in "\r\n"):
            return False, "Недопустимые символы в логине, пароле или коде"
        host = cisco_host()
        if not host:
            return False, "Не задан сервер Cisco: впишите CISCO_HOST в .env"
        if cisco_gui_running():
            return False, CISCO_GUI_HINT
        if not self.action.acquire(blocking=False):
            return False, "Cisco уже подключается или отключается"
        try:
            return self.login(host, user, password, otp)
        finally:
            self.action.release()

    def login(self, host, user, password, otp):
        """Проходит вход vpn connect, отвечая на вопросы утилиты по мере их появления.

        Что спросить, решает сервер (группа, логин, пароль, код, согласие с баннером), поэтому
        отвечаем по тексту вопроса. Вопросы утилита задаёт только в терминале — setsid -c даёт
        ей псевдотерминал.
        """
        master, slave = os.openpty()
        try:
            proc = subprocess.Popen(["setsid", "-wc", CISCO_VPN, "connect", host], stdin=slave, stdout=slave,
                                    stderr=slave, cwd=PROJECT_DIR, env=CISCO_ENV)
        except OSError as e:
            os.close(master)
            return False, str(e)
        finally:
            os.close(slave)
        output, answered, asked = "", 0, set()
        deadline = time.monotonic() + CISCO_TIMEOUT
        try:
            while ">> state: Connected" not in output:
                if time.monotonic() > deadline:
                    return False, f"Cisco не подключился за {CISCO_TIMEOUT // 60} мин."
                if select.select([master], [], [], 0.5)[0]:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:  # EIO: утилита завершилась и закрыла терминал
                        break
                    if not chunk:
                        break
                    output += chunk.decode("utf-8", "replace").replace("\r", "")
                    continue  # отвечаем, только когда утилита замолчала на вопросе
                if proc.poll() is not None:
                    break
                # Вопрос — недописанная строка после нашего прошлого ответа: «Username: [dima]», «Password:».
                prompt = output[answered:].rpartition("\n")[2].strip()
                if not prompt or prompt.startswith("VPN>"):
                    continue
                label = prompt.split(":", 1)[0].strip().lower()
                if "[y/n]" in prompt:
                    answer = "y"  # баннер сервера — то же, что «Принять» в окне Cisco
                elif label == "group":
                    answer = ""  # группа по умолчанию: её задаёт адрес сервера
                elif "Login failed" in output or (label == "username" and "username" in asked):
                    # После неудачного входа утилита спрашивает логин заново.
                    return False, cisco_error(output, "Сервер не принял логин, пароль или код.")
                elif label == "username":
                    asked.add("username")
                    answer = user
                elif label == "password" and "password" not in asked:
                    asked.add("password")
                    answer = password
                elif "password" in asked and "otp" not in asked:
                    # Следующий вопрос после пароля — код: Second Password, Answer, Response — как назовёт сервер.
                    if not otp:
                        return False, "Сервер просит одноразовый код"
                    asked.add("otp")
                    answer = otp
                else:
                    return False, f"Cisco спрашивает «{prompt}», а веб-интерфейс не знает ответа — подключитесь в окне Cisco"
                os.write(master, (answer + "\n").encode())
                answered = len(output)
        finally:
            try:
                # Подключившись, утилита выходит сама; в остальных случаях прерываем её.
                proc.wait(10 if ">> state: Connected" in output else 0.1)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            os.close(master)
        if ">> state: Connected" in output:
            return True, f"Cisco подключён к {host}."
        return False, cisco_error(output, "Подключиться не удалось")

    def disconnect(self):
        if not self.action.acquire(blocking=False):
            return False, "Cisco уже подключается или отключается"
        try:
            _, out, err = run(CISCO_VPN, "disconnect", timeout=60, env=CISCO_ENV)
        finally:
            self.action.release()
        # Сначала утилита печатает состояние на момент запуска, итог — последнее.
        if re.findall(r">> state: (\w+)", out)[-1:] == ["Disconnected"] or not self.connected():
            return True, "Cisco отключён."
        return False, cisco_error(out + "\n" + err, "Отключить Cisco не удалось")


CISCO = Cisco()


class Handler(BaseHTTPRequestHandler):
    server_version = "lan-vpn-proxy"

    def respond(self, code, body, content_type="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def handle(self):
        try:
            super().handle()
        except ssl.SSLError:
            pass  # открыли http:// вместо https:// или браузер не принял сертификат — не засоряем журнал

    def authorized(self):
        """Пароль (HTTP Basic, имя любое) — если задан WEB_PASSWORD. Без него — 401, браузер спросит пароль."""
        if not WEB_PASSWORD:
            return True
        client, now = self.client_address[0], time.time()
        with LOGIN_LOCK:
            fails = LOGIN_FAILS[client] = [t for t in LOGIN_FAILS[client] if now - t < LOGIN_WINDOW]
            if len(fails) >= LOGIN_MAX_FAILS:
                self.respond(429, {"error": "слишком много неверных паролей, попробуйте позже"})
                return False
        header = self.headers.get("Authorization")
        scheme, _, encoded = (header or "").partition(" ")
        try:
            password = base64.b64decode(encoded, validate=True).decode().partition(":")[2]
        except (ValueError, UnicodeDecodeError):
            password = ""
        if scheme.lower() == "basic" and hmac.compare_digest(password.encode(), WEB_PASSWORD.encode()):
            with LOGIN_LOCK:
                LOGIN_FAILS.pop(client, None)
            return True
        if header:  # первый запрос браузера идёт без пароля — это не попытка
            with LOGIN_LOCK:
                LOGIN_FAILS[client].append(now)
            print(f"неверный пароль веб-интерфейса с {client}", flush=True)
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="lan-vpn-proxy", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def allowed(self, action=False):
        if self.headers.get("Host") not in ALLOWED_HOSTS:
            return False
        if not action:
            return True
        # Браузер всегда шлёт Origin с POST; Content-Type: application/json с чужого
        # сайта требует CORS-preflight, на который мы не отвечаем.
        origin = self.headers.get("Origin")
        json_body = self.headers.get("Content-Type", "").startswith("application/json")
        return json_body and (origin is None or origin in ALLOWED_ORIGINS)

    def do_GET(self):
        if not self.allowed():
            return self.respond(403, {"error": "forbidden"})
        if not self.authorized():
            return
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/":
            return self.respond(200, PAGE.encode(), "text/html; charset=utf-8")
        if url.path == "/favicon.svg":
            state = (urllib.parse.parse_qs(url.query).get("s") or ["off"])[0]
            return self.respond(200, ICON.format(color=ICON_COLORS.get(state, ICON_COLORS["off"])).encode(),
                                "image/svg+xml")
        if url.path == "/api/status":
            return self.respond(200, status())
        if url.path == "/api/ip":
            return self.respond(200, check_ip())
        if url.path == "/api/rules":
            return self.respond(200, rules_info())
        if url.path == "/api/servers":
            return self.respond(200, servers_info())
        if url.path == "/api/hosts":  # отладочная вкладка «Хосты»
            query = urllib.parse.parse_qs(url.query)
            days = {"7": 7, "30": 30}.get((query.get("days") or ["1"])[0], 1)
            group = (query.get("group") or ["1"])[0] == "1"
            app = (query.get("app") or [""])[0] or None
            HOSTS.sample()  # дочитать журнал, чтобы список был свежим, а не минутной давности
            return self.respond(200, HOSTS.summary(days, group, app))
        self.respond(404, {"error": "not found"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if not self.allowed(action=True):
            return self.respond(403, {"error": "forbidden"})
        if not self.authorized():
            return
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return self.respond(400, {"error": "bad json"})
        action = {
            "/api/on": turn_on,
            "/api/off": turn_off,
            "/api/update": update_subscription,
            "/api/check": check_servers,
            "/api/select": lambda: select_server(body.get("index") if isinstance(body, dict) else None),
            "/api/rules": lambda: save_rules(body),
            "/api/hosts/reset": HOSTS.reset,
            "/api/devices/name": lambda: DEVICES.rename(body),
            "/api/cisco/connect": lambda: CISCO.connect(body),
            "/api/cisco/disconnect": CISCO.disconnect,
        }.get(self.path)
        if action is None:
            return self.respond(404, {"error": "not found"})
        ok, message = action()
        print(f"{self.path}: {'ok' if ok else message}", flush=True)
        self.respond(200 if ok else 500, {"ok": ok, "message": message, **status()})

    def log_message(self, format, *args):
        pass  # страница опрашивает статус каждые 3 секунды — это забило бы журнал


# Страница интерфейса — в static/index.html; читаем при запуске.
with open(os.path.join(PROJECT_DIR, "static", "index.html"), encoding="utf-8") as f:
    PAGE = f.read()


def ensure_cert():
    """Самоподписанный сертификат на адреса из ALLOWED_HOSTS (openssl есть в Ubuntu из коробки)."""
    names = sorted({host.rsplit(":", 1)[0] for host in ALLOWED_HOSTS})
    san = ",".join(f"{'IP' if is_ip(name) else 'DNS'}:{name}" for name in names)
    try:
        with open(WEB_CERT + ".san") as f:
            if f.read() == san and os.path.exists(WEB_KEY):
                return
    except OSError:
        pass
    os.makedirs(os.path.dirname(WEB_CERT), exist_ok=True)
    old = os.umask(0o077)  # ключ — только владельцу
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "3650", "-subj", "/CN=lan-vpn-proxy", "-addext", f"subjectAltName={san}",
                        "-keyout", WEB_KEY, "-out", WEB_CERT], check=True, capture_output=True)
        with open(WEB_CERT + ".san", "w") as f:
            f.write(san)
    finally:
        os.umask(old)
    print(f"создан сертификат веб-интерфейса: {san}", flush=True)


def is_ip(name):
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def main():
    threading.Thread(target=collect_forever, daemon=True).start()
    threading.Thread(target=SOCKETS.run_forever, daemon=True).start()
    threading.Thread(target=AUTO.run_forever, daemon=True).start()
    threading.Thread(target=XRAY.run_forever, daemon=True).start()
    if WEB_BIND not in ("127.0.0.1", "localhost", "::1") and not WEB_PASSWORD:
        sys.exit(f"WEB_BIND={WEB_BIND} без WEB_PASSWORD: страницу без пароля откроет любой в сети")
    server = ThreadingHTTPServer((WEB_BIND, WEB_PORT), Handler)
    if WEB_TLS:
        ensure_cert()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(WEB_CERT, WEB_KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    print(f"веб-интерфейс: {'https' if WEB_TLS else 'http'}://{WEB_BIND}:{WEB_PORT}", flush=True)
    server.serve_forever()


def rules_cli(args):
    """Для sync-rules.py: `web.py rules` — правила в JSON, `web.py rules-set` — применить JSON из stdin."""
    if args == ["rules"]:
        print(json.dumps(rules_info(), ensure_ascii=False))
        return
    body = json.load(sys.stdin)
    ok, message = save_rules(body, body.get("updated") if isinstance(body, dict) else None)
    print(message)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    if sys.argv[1:] in (["rules"], ["rules-set"]):
        rules_cli(sys.argv[1:])
    else:
        main()
