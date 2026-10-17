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
import hmac
import http.client
import json
import os
import re
import select
import shutil
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

from gen_config import (DEFAULT_OUTPUT, ENV_FILE, OUTBOUNDS_FILE, PROJECT_DIR, SERVERS_FILE, STATS_API,
                        build_check_config, build_config, config_settings, load_env, set_env_value, setting,
                        split_list, write_json)

CONTAINER = "lan-vpn-proxy"
WATCH_SERVICE = "lan-vpn-proxy-watch.service"
IP_URL = "https://ifconfig.me/ip"
SAMPLE_INTERVAL = 60  # секунд между замерами трафика и чтением журнала Xray
TRAFFIC_FILE = os.path.join(PROJECT_DIR, "data", "traffic.json")
TRAFFIC_DAYS_KEPT = 90
TRAFFIC_DAYS_SHOWN = 7
HOSTS_FILE = os.path.join(PROJECT_DIR, "data", "hosts.json")
HOSTS_DAYS_KEPT = 30
HOSTS_SHOWN = 100
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
HTTP_PORT = setting(dotenv, "HTTP_PORT", "3128")
SOCKS_PORT = setting(dotenv, "SOCKS_PORT", "1080")
# Страница управляет Docker, поэтому отвечаем только на свои адреса: это защищает
# от DNS rebinding и от запросов, которые чужой сайт отправит из браузера.
# WEB_HOSTS — адреса и имена, по которым страницу открывают из сети (192.168.0.141 и т.п.).
ALLOWED_HOSTS = {f"{host}:{WEB_PORT}" for host in ["127.0.0.1", "localhost", *split_list(setting(dotenv, "WEB_HOSTS"))]}
ALLOWED_ORIGINS = {f"http://{host}" for host in ALLOWED_HOSTS}
ACTION_LOCK = threading.Lock()
CHECK_LOCK = threading.Lock()
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
        if kind == "inbound" or (kind == "outbound" and tag == "direct"):
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
                else:
                    app = f"устройство {source_ip}"  # BIND_ADDR=0.0.0.0: клиент из локальной сети
                hosts = self.data["days"].setdefault(at.astimezone().date().isoformat(), {}).setdefault(app, {})
                host = host_of(match[3])
                hosts[host] = hosts.get(host, 0) + 1
                last = max(last, match[1])
            self.data["since"] = round(started - 5, 3)
            self.data["last"] = last
            for old in sorted(self.data["days"])[:-HOSTS_DAYS_KEPT]:
                del self.data["days"][old]
            write_json(self.path, self.data)  # это история посещений — права 600

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
        with self.lock:
            for day, by_app in self.data["days"].items():
                if day < cutoff:
                    continue
                for name, by_host in by_app.items():
                    for host, n in by_host.items():
                        apps[name] += n
                        if app in (None, name):
                            key = domain_of(host) if group else host
                            hosts[key] += n
                            host_apps[key][name] += n
        top = hosts.most_common(HOSTS_SHOWN)
        total = sum(hosts.values())
        return {
            "apps": [{"app": name, "count": n} for name, n in apps.most_common()],
            "apps_total": sum(apps.values()),
            "total": total,
            "hosts_total": len(hosts),
            "hosts": [{"host": host, "count": n, "apps": [a for a, _ in host_apps[host].most_common(3)]}
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
    return config_settings(load_env(ENV_FILE))["routing"]


def save_rules(body):
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
        error = write_server_config((load_servers() or {}).get("current"), settings)
        if error:
            return False, error
        set_env_value(ENV_FILE, "ROUTING_MODE", body["mode"])
        set_env_value(ENV_FILE, "VPN_APPS", ", ".join(lists["apps"]))
        set_env_value(ENV_FILE, "VPN_HOSTS", ", ".join(lists["hosts"]))
        set_env_value(ENV_FILE, "DIRECT_HOSTS", ", ".join(lists["direct"]))
        ok, restarted = restart_if_running()
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
        run("docker", "rm", "-f", CHECK_CONTAINER)  # остаток прерванной проверки
        ok, _, err = run("docker", "run", "-d", "--rm", "--name", CHECK_CONTAINER,
                         "--user", f"{os.getuid()}:{os.getgid()}",
                         "-p", f"127.0.0.1:{ports[0]}-{ports[-1]}:{ports[0]}-{ports[-1]}",
                         "-v", f"{tmp}:/usr/local/etc/xray:ro", image)
        if not ok:
            return False, err
        try:
            if not wait_started(CHECK_CONTAINER):
                return False, "Xray для проверки не запустился"
            with ThreadPoolExecutor(max_workers=len(chains)) as pool:
                delays = list(pool.map(probe, ports))
        finally:
            run("docker", "rm", "-f", CHECK_CONTAINER)
        last_check.update(time=datetime.datetime.now().isoformat(timespec="minutes"),
                          delays={s["name"]: d for s, d in zip(servers, delays)})
        return True, f"Работают {sum(d is not None for d in delays)} из {len(delays)}."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        CHECK_LOCK.release()


def status():
    _, mode, _ = run("gsettings", "get", "org.gnome.system.proxy", "mode", timeout=5)
    _, port, _ = run("gsettings", "get", "org.gnome.system.proxy.http", "port", timeout=5)
    _, watcher, _ = run("systemctl", "--user", "is-active", WATCH_SERVICE, timeout=5)
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
        "routing": rules_info(),
        "servers_updated": servers["updated"] if servers else None,
        "cisco": CISCO.info(),
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

    def authorized(self):
        """Пароль (HTTP Basic, имя любое) — если задан WEB_PASSWORD. Без него — 401, браузер спросит пароль."""
        if not WEB_PASSWORD:
            return True
        scheme, _, encoded = self.headers.get("Authorization", "").partition(" ")
        try:
            password = base64.b64decode(encoded, validate=True).decode().partition(":")[2]
        except (ValueError, UnicodeDecodeError):
            password = ""
        if scheme.lower() == "basic" and hmac.compare_digest(password.encode(), WEB_PASSWORD.encode()):
            return True
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


PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN-прокси</title>
<link rel="icon" id="favicon" href="/favicon.svg" type="image/svg+xml">
<style>
  /* Оформление по Ant Design 5: его цвета, размеры и компоненты на чистом CSS, без библиотеки и CDN. */
  :root {
    color-scheme: light dark;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif;
    --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
    --primary: #1677ff; --primary-hover: #4096ff; --primary-active: #0958d9; --primary-bg: #e6f4ff;
    --primary-shadow: rgba(5, 145, 255, .1);
    --success: #52c41a; --warning: #faad14; --error: #ff4d4f; --error-hover: #ff7875; --off: #bfbfbf;
    --text: rgba(0, 0, 0, .88); --text-3: rgba(0, 0, 0, .45); --text-disabled: rgba(0, 0, 0, .25);
    --border: #d9d9d9; --border-2: #f0f0f0; --bg-layout: #f5f5f5; --bg-container: #fff;
    --fill-disabled: rgba(0, 0, 0, .04); --table-head: #fafafa; --row-hover: #fafafa;
    --success-bg: #f6ffed; --success-border: #b7eb8f; --success-text: #389e0d;
    --warning-bg: #fffbe6; --warning-border: #ffe58f;
    --error-bg: #fff2f0; --error-border: #ffccc7;
    --info-bg: #e6f4ff; --info-border: #91caff;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --primary: #1668dc; --primary-hover: #3c89e8; --primary-active: #1554ad; --primary-bg: #111a2c;
      --primary-shadow: rgba(0, 60, 180, .15);
      --success: #49aa19; --warning: #d89614; --error: #dc4446; --error-hover: #e86e6b; --off: #595959;
      --text: rgba(255, 255, 255, .85); --text-3: rgba(255, 255, 255, .45); --text-disabled: rgba(255, 255, 255, .25);
      --border: #424242; --border-2: #303030; --bg-layout: #000; --bg-container: #141414;
      --fill-disabled: rgba(255, 255, 255, .08); --table-head: #1d1d1d; --row-hover: #262626;
      --success-bg: #162312; --success-border: #274916; --success-text: #49aa19;
      --warning-bg: #2b2111; --warning-border: #594214;
      --error-bg: #2c1618; --error-border: #5b2526;
      --info-bg: #111a2c; --info-border: #15325b;
    }
  }
  body { margin: 0; background: var(--bg-layout); color: var(--text); font: 14px/1.5714 var(--font); }
  main { max-width: 760px; margin: 0 auto; padding: 32px 16px; }
  header { display: flex; align-items: center; gap: 12px; margin: 0 0 8px; }
  h1 { margin: 0; font-size: 20px; font-weight: 600; }
  a { color: var(--primary); text-decoration: none; transition: color .2s; }
  a:hover { color: var(--primary-hover); }
  code { margin: 0 .2em; padding: .2em .4em .1em; font: 85% var(--mono); background: rgba(150, 150, 150, .1);
         border: 1px solid rgba(100, 100, 100, .2); border-radius: 3px; }
  [hidden] { display: none !important; }

  /* Tabs */
  nav { display: flex; gap: 32px; margin: 0 0 16px; border-bottom: 1px solid var(--border-2); }
  nav a { padding: 12px 0; margin-bottom: -1px; color: var(--text); border-bottom: 2px solid transparent; }
  nav a:hover { color: var(--primary-hover); }
  nav a[aria-current] { color: var(--primary); border-bottom-color: var(--primary); }

  /* Card */
  .card { margin: 0 0 16px; padding: 20px 24px; background: var(--bg-container); border: 1px solid var(--border-2);
          border-radius: 8px; }
  .card-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px 12px;
               min-height: 56px; margin: -20px -24px 20px; padding: 8px 24px; box-sizing: border-box;
               border-bottom: 1px solid var(--border-2); }
  .card-head h2 { margin: 0; font-size: 16px; font-weight: 600; }
  .extra { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
  .extra .foot { margin: 0; }
  h3 { margin: 24px 0 8px; font-size: 14px; font-weight: 600; }
  .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; margin: 0 0 16px; }
  .toolbar .end { margin-left: auto; }

  /* Button */
  button { height: 32px; padding: 4px 15px; font: inherit; color: var(--text); background: var(--bg-container);
           border: 1px solid var(--border); border-radius: 6px; box-shadow: 0 2px 0 rgba(0, 0, 0, .02);
           cursor: pointer; transition: all .2s cubic-bezier(.645, .045, .355, 1); }
  button:hover { color: var(--primary-hover); border-color: var(--primary-hover); }
  button:active { color: var(--primary-active); border-color: var(--primary-active); }
  button.primary { color: #fff; background: var(--primary); border-color: var(--primary);
                   box-shadow: 0 2px 0 var(--primary-shadow); }
  button.primary:hover { color: #fff; background: var(--primary-hover); border-color: var(--primary-hover); }
  button.primary:active { background: var(--primary-active); border-color: var(--primary-active); }
  button.danger { color: var(--error); border-color: var(--error); }
  button.danger:hover { color: var(--error-hover); border-color: var(--error-hover); }
  button.large { height: 40px; padding: 6px 15px; font-size: 16px; border-radius: 8px; }
  button:disabled, button:disabled:hover { color: var(--text-disabled); background: var(--fill-disabled);
                                           border-color: var(--border); box-shadow: none; cursor: progress; }
  td button { height: 24px; padding: 0 7px; border-radius: 4px; }
  #toggle { display: block; width: 100%; margin: 16px 0; }

  /* Input, Select, Radio, Checkbox */
  input:not([type=radio]):not([type=checkbox]), textarea, select {
    box-sizing: border-box; padding: 4px 11px; font: inherit; color: var(--text); background: var(--bg-container);
    border: 1px solid var(--border); border-radius: 6px; transition: border-color .2s, box-shadow .2s; }
  input:not([type=radio]):not([type=checkbox]), select { height: 32px; }
  input:hover, textarea:hover, select:hover { border-color: var(--primary-hover); }
  input:focus, textarea:focus, select:focus { outline: none; border-color: var(--primary);
                                              box-shadow: 0 0 0 2px var(--primary-shadow); }
  input::placeholder { color: var(--text-disabled); }
  textarea { display: block; width: 100%; font: 13px/1.5714 var(--mono); resize: vertical; }
  select { appearance: none; padding-right: 30px; cursor: pointer;
           background: var(--bg-container) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M3 4.5 6 7.5 9 4.5' fill='none' stroke='%238c8c8c' stroke-width='1.4'/%3E%3C/svg%3E") right 10px center / 12px no-repeat; }
  input[type=radio], input[type=checkbox] { appearance: none; flex: none; width: 16px; height: 16px; margin: 0 8px 0 0;
    vertical-align: -3px; background: var(--bg-container); border: 1px solid var(--border); cursor: pointer;
    transition: all .2s; }
  input[type=radio] { border-radius: 50%; }
  input[type=checkbox] { border-radius: 4px; }
  input[type=radio]:hover, input[type=checkbox]:hover { border-color: var(--primary); }
  input[type=radio]:checked { border-color: var(--primary); background: radial-gradient(circle, #fff 0 3px, var(--primary) 3.5px); }
  input[type=checkbox]:checked { border-color: var(--primary);
    background: var(--primary) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M2.5 6.2 5 8.5 9.5 3.5' fill='none' stroke='white' stroke-width='1.8'/%3E%3C/svg%3E") center / 12px no-repeat; }
  label { cursor: pointer; }
  label.mode { display: flex; align-items: baseline; margin: 0 0 8px; }
  label.mode input { position: relative; top: 3px; }
  .login { display: grid; grid-template-columns: 1fr 1fr 7rem auto; gap: 8px; margin: 16px 0; }
  .login input { min-width: 0; }

  /* Alert, Tag, Badge */
  .note { margin: 0 0 16px; padding: 8px 12px; background: var(--info-bg); border: 1px solid var(--info-border);
          border-radius: 8px; }
  .note.ok { background: var(--success-bg); border-color: var(--success-border); }
  .note.err { background: var(--error-bg); border-color: var(--error-border); }
  .note.warn { background: var(--warning-bg); border-color: var(--warning-border); }
  .tag { display: inline-block; padding: 0 7px; font-size: 12px; line-height: 20px; font-weight: 400; white-space: nowrap;
         color: var(--text); background: var(--table-head); border: 1px solid var(--border); border-radius: 4px; }
  .tag.blue { color: var(--primary); background: var(--info-bg); border-color: var(--info-border); }
  .tag.green { color: var(--success-text); background: var(--success-bg); border-color: var(--success-border); }
  nav .tag { margin-left: 4px; vertical-align: 1px; }
  .state { display: flex; align-items: center; gap: 10px; font-size: 20px; font-weight: 600; line-height: 1.4; }
  .dot { flex: none; width: 10px; height: 10px; border-radius: 50%; background: var(--off); }
  .on .dot { background: var(--success); }
  .warn .dot { background: var(--warning); }

  /* Descriptions */
  dl { display: grid; grid-template-columns: auto 1fr; gap: 8px 24px; margin: 0; }
  dt { color: var(--text-3); }
  dd { margin: 0; }

  /* Table */
  table { width: 100%; border-collapse: separate; border-spacing: 0; }
  th, td { padding: 12px 8px; text-align: left; border-bottom: 1px solid var(--border-2); }
  th { font-weight: 600; background: var(--table-head); }
  th:first-child { border-top-left-radius: 8px; }
  th:last-child { border-top-right-radius: 8px; }
  td { font-variant-numeric: tabular-nums; transition: background .2s; }
  tbody tr:hover td { background: var(--row-hover); }
  tr.current td, tr.current:hover td { background: var(--primary-bg); }
  tr.muted td { color: var(--text-3); }
  .addr { display: block; font-size: 12px; color: var(--text-3); }
  .foot { margin: 12px 0 0; color: var(--text-3); }
</style>
</head>
<body>
<main>
<header><img id="logo" src="/favicon.svg" alt="" width="32" height="32"><h1>lan-vpn-proxy</h1></header>
<nav><a href="#" id="nav-main">Главная</a><a href="#servers" id="nav-servers">Серверы</a><a href="#rules" id="nav-rules">Правила</a><a href="#hosts" id="nav-hosts">Хосты<span class="tag">отладка</span></a></nav>
<section id="tab-main">
<div class="card">
<div id="state" class="state"><span class="dot"></span><span id="state-text">Загрузка…</span></div>
<button id="toggle" class="large primary" disabled>…</button>
<p id="error" class="note err" hidden></p>
<p id="hint" class="note warn" hidden></p>
<dl>
  <dt>Сервер</dt><dd><span id="server">—</span> <a href="#servers">сменить</a></dd>
  <dt>Через VPN</dt><dd><span id="routing">—</span> <a href="#rules">изменить</a></dd>
  <dt>Контейнер</dt><dd id="container">—</dd>
  <dt>Прокси GNOME</dt><dd id="proxy">—</dd>
  <dt>Внешний IP</dt><dd><span id="ip"></span> <button id="check">Проверить</button></dd>
</dl>
</div>
<div id="cisco" class="card" hidden>
<div class="card-head"><h2>Рабочий VPN (Cisco)</h2><span id="cisco-state" class="tag">—</span></div>
<dl>
  <dt>Сервер</dt><dd id="cisco-host">—</dd>
</dl>
<form id="cisco-form" class="login" hidden>
  <input id="cisco-user" name="username" autocomplete="username" placeholder="Логин" required>
  <input id="cisco-password" name="password" type="password" autocomplete="current-password" placeholder="Пароль" required>
  <input id="cisco-otp" name="otp" autocomplete="one-time-code" inputmode="numeric" placeholder="Код">
  <button id="cisco-connect" class="primary">Подключить</button>
</form>
<p id="cisco-actions" hidden><button id="cisco-disconnect" class="danger">Отключить</button></p>
<p id="cisco-hint" class="note warn" hidden></p>
<p id="cisco-msg" class="note" hidden></p>
<p class="foot">Через Cisco идут только рабочие сети — их задаёт сервер Cisco, остальное он не трогает.
Рабочие сайты из списка «Всегда напрямую» (вкладка «Правила») идут мимо VPN-прокси и попадают в Cisco
в любом режиме. Пароль и код никуда не сохраняются.</p>
</div>
<div class="card">
<div class="card-head"><h2>Трафик по дням</h2></div>
<table>
  <thead><tr><th>День</th><th>Через VPN</th><th>Напрямую</th></tr></thead>
  <tbody id="traffic"></tbody>
</table>
<p class="foot">↓ получено, ↑ отправлено. «Напрямую» — приблизительно: сюда же попадают
локальная сеть и накладные расходы шифрования VPN. Замер раз в минуту.</p>
</div>
</section>
<section id="tab-servers" hidden>
<div class="card">
<div class="card-head"><h2>Серверы</h2>
  <span class="extra"><button id="update">Обновить подписку</button> <button id="test" class="primary">Проверить серверы</button></span></div>
<p id="servers-msg" class="note" hidden></p>
<table>
  <thead><tr><th>№</th><th>Сервер</th><th>Подключение</th><th>Задержка</th><th></th></tr></thead>
  <tbody id="servers"></tbody>
</table>
<p class="foot"><span id="servers-updated"></span> «Выбрать» переключает VPN на сервер и записывает его
в <code>SERVER</code> в .env; если VPN включён, связь пропадёт на пару секунд. Проверка делает настоящий
запрос через каждый сервер, задержка — время до ответа; сверху самые быстрые. № — номер в подписке.</p>
</div>
</section>
<section id="tab-rules" hidden>
<div class="card">
<div class="card-head"><h2>Что идёт через VPN</h2></div>
<label class="mode"><input type="radio" name="mode" value="all"><span><b>Всё через VPN</b> — всё, что приходит в прокси</span></label>
<label class="mode"><input type="radio" name="mode" value="filter"><span><b>По списку</b> — через VPN только
приложения и хосты ниже, остальное напрямую</span></label>
<h3>Приложения</h3>
<textarea id="rules-apps" rows="4" spellcheck="false"></textarea>
<p class="foot">По одному в строке: имя исполняемого файла (как на вкладке «Хосты»), полный путь
или папка с / на конце. Через VPN пойдут все подключения этого приложения.</p>
<h3>Хосты</h3>
<textarea id="rules-hosts" rows="14" spellcheck="false"></textarea>
<p class="foot">По одному в строке: домен (youtube.com — вместе с поддоменами), IP или сеть
(91.108.4.0/22). Можно и правила Xray: full:, keyword:, regexp:.</p>
<h3>Всегда напрямую</h3>
<textarea id="rules-direct" rows="3" spellcheck="false"></textarea>
<p class="foot">Мимо VPN в любом режиме, даже для приложений из списка: например, рабочие сайты — они
пойдут через Cisco, если он подключён. Формат тот же, что у хостов. Эти адреса попадают и в исключения
системного прокси GNOME (кроме keyword: и regexp: — их GNOME не понимает).</p>
</div>
<p><button id="rules-save" class="primary">Сохранить и применить</button></p>
<p id="rules-msg" class="note" hidden></p>
<p class="foot">Хранится в .env (ROUTING_MODE, VPN_APPS, VPN_HOSTS, DIRECT_HOSTS); списки приложений
и хостов действуют только в режиме «по списку». Перед применением Xray проверяет конфиг; если VPN включён, контейнер перезапускается —
открытые соединения оборвутся, и программы переподключатся. Локальные сети всегда идут напрямую,
а программы, которые не используют системный прокси (терминал, Claude Code), — напрямую в любом режиме.</p>
</section>
<section id="tab-hosts" hidden>
<p class="note">Отладочная функция: помогает понять, что идёт через VPN. Цифры приблизительные —
считаются подключения из журнала Xray, а не трафик.</p>
<div class="toolbar">
  <select id="hosts-days">
    <option value="1">Сегодня</option><option value="7">7 дней</option><option value="30">30 дней</option>
  </select>
  <label><input type="checkbox" id="hosts-group" checked>по доменам</label>
  <button id="hosts-reset" class="danger end">Сбросить статистику</button>
</div>
<div class="card">
<div class="card-head"><h2>Приложения</h2></div>
<table>
  <thead><tr><th>Приложение</th><th>Подключений</th><th>Доля</th></tr></thead>
  <tbody id="apps"></tbody>
</table>
</div>
<div class="card">
<div class="card-head"><h2>Хосты</h2>
  <span class="extra"><span id="hosts-total" class="foot"></span><select id="hosts-app"><option value="">Все приложения</option></select></span></div>
<table>
  <thead><tr><th>Хост</th><th>Приложения</th><th>Подключений</th><th>Доля</th></tr></thead>
  <tbody id="hosts"></tbody>
</table>
<p class="foot">Хосты, к которым программы подключались через VPN, по журналу Xray. Доля — от числа
подключений, а не от объёма: сколько байт ушло каждому хосту, Xray не считает. Приложение
определяется по открытым соединениям с прокси (опрос раз в 2 секунды), поэтому совсем короткие
подключения и программы других пользователей попадают в «не определено». «По доменам»
объединяет поддомены: mc.yandex.ru и yandex.ru → yandex.ru. Хранится 30 дней.</p>
</div>
</section>
</main>
<script>
const $ = id => document.getElementById(id);
let busy = false, last = null, servers = [], current = -1, check = {delays: {}}, serversKey = null;

function note(id, text) { $(id).textContent = text; $(id).hidden = !text; }

function post(action, body = {}) {
  return fetch('/api/' + action, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json());
}

function size(bytes) {
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return bytes.toLocaleString('ru', {maximumFractionDigits: i && bytes < 10 ? 1 : 0}) + ' ' + units[i];
}

function row(cells, className) {
  const tr = document.createElement('tr');
  tr.className = className || '';
  for (const cell of cells) {
    const td = document.createElement('td');
    td.append(cell);
    tr.append(td);
  }
  return tr;
}

function emptyRow(text, columns) {
  const tr = row([text]);
  tr.firstChild.colSpan = columns;
  return tr;
}

function renderTraffic(days) {
  const today = new Date().toLocaleDateString('sv');  // ГГГГ-ММ-ДД в местном времени
  const rows = days.map(d => row([
    d.date === today ? 'сегодня' : d.date.slice(8) + '.' + d.date.slice(5, 7),
    size(d.vpn_down) + ' ↓ ' + size(d.vpn_up) + ' ↑',
    size(d.direct_down) + ' ↓ ' + size(d.direct_up) + ' ↑',
  ]));
  $('traffic').replaceChildren(...(rows.length ? rows : [emptyRow('Данных пока нет — первый замер через минуту', 3)]));
}

function kind(s) {
  return [s.protocol, s.network, s.security === 'none' ? '' : s.security].filter(Boolean).join(' · ').toUpperCase();
}

// undefined — не проверяли, null — не работает
function delayOf(i) { return check.delays[servers[i].name]; }

function renderServers() {
  const rank = d => d === undefined ? 1 : d === null ? 2 : 0;
  // Сверху рабочие по возрастанию задержки, затем непроверенные, внизу нерабочие.
  const order = servers.map((_, i) => i).sort((a, b) => {
    const da = delayOf(a), db = delayOf(b);
    return rank(da) - rank(db) || (rank(da) ? 0 : da - db) || a - b;
  });
  const rows = order.map(i => {
    const s = servers[i], d = delayOf(i);
    const name = document.createElement('span'), addr = document.createElement('span');
    name.textContent = s.name;
    addr.className = 'addr';
    addr.textContent = s.address + ':' + s.port;
    name.append(addr);
    const delay = d === undefined ? '—' : d === null ? 'не работает' : d + ' мс';
    let action = document.createElement('span');
    action.className = 'tag blue';
    action.textContent = 'текущий';
    if (i !== current) {
      action = document.createElement('button');
      action.textContent = 'Выбрать';
      action.onclick = () => serverAction('select', action, 'Переключаю…', {index: i});
    }
    return row([String(i + 1), name, kind(s), delay, action], i === current ? 'current' : '');
  });
  $('servers').replaceChildren(...(rows.length ? rows : [emptyRow('Список появится после «Обновить подписку»', 5)]));
}

async function loadServers() {
  const info = await (await fetch('/api/servers')).json();
  servers = info.servers;
  current = info.current;
  check = info.check;
  renderServers();
  const when = t => new Date(t).toLocaleString('ru', {dateStyle: 'short', timeStyle: 'short'});
  $('servers-updated').textContent =
    (info.updated ? 'Обновлено ' + when(info.updated) + ', серверов: ' + servers.length + '.' : '') +
    (check.time ? ' Проверено ' + when(check.time) + '.' : '');
}

async function serverAction(action, button, label, body) {
  const text = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try {
    const r = await post(action, body);
    $('servers-msg').className = 'note ' + (r.ok ? 'ok' : 'err');
    note('servers-msg', r.message || (r.ok ? '' : 'Не получилось'));
    await loadServers();
  } catch (e) {
    $('servers-msg').className = 'note err';
    note('servers-msg', 'Нет связи с веб-интерфейсом: ' + e);
  }
  button.disabled = false;
  button.textContent = text;
}

function render(s) {
  last = s;
  const active = s.running || s.restarting;
  $('state').className = 'state ' + (s.restarting ? 'warn' : s.running ? 'on' : '');
  $('state-text').textContent = s.restarting ? 'Контейнер перезапускается' : s.running ? 'VPN включён' : 'VPN выключен';
  const icon = '/favicon.svg?s=' + (s.restarting ? 'warn' : s.running ? 'on' : 'off');
  if ($('favicon').getAttribute('href') !== icon) $('favicon').href = $('logo').src = icon;
  $('toggle').textContent = active ? 'Выключить' : 'Включить';
  $('toggle').className = 'large ' + (active ? 'danger' : 'primary');
  $('toggle').disabled = busy;
  $('container').textContent = s.status;
  $('server').textContent = s.server ? s.server.name + ' · ' + kind(s.server) : 'не выбран';
  $('routing').textContent = s.routing.mode === 'filter'
    ? 'по списку: приложений ' + s.routing.apps.length + ', хостов ' + s.routing.hosts.length + ', остальное напрямую'
    : 'всё, что идёт через прокси' + (s.routing.direct.length ? ', кроме «всегда напрямую»: ' + s.routing.direct.length : '');
  // Список перечитываем, только когда gen_config.py собрал новый конфиг.
  const key = s.servers_updated + '|' + (s.server && s.server.name);
  if (key !== serversKey) { serversKey = key; loadServers(); }
  let proxy = 'выключен — трафик напрямую';
  if (s.proxy_mode === 'manual') {
    proxy = 'включён, 127.0.0.1:' + s.proxy_port;
    if (String(s.proxy_port) !== String(s.http_port)) proxy += ' — это не наш прокси (Happ?)';
  }
  $('proxy').textContent = proxy;
  let hint = '';
  if (!s.config) hint = 'Нет xray/config.json: заполните SUBSCRIPTION в .env и запустите ./gen_config.py';
  else if (s.restarting) hint = 'Xray падает при запуске — смотрите docker compose logs';
  else if (!s.watcher) hint = 'Служба lan-vpn-proxy-watch не запущена: системный прокси GNOME не будет переключаться';
  note('hint', hint);
  renderCisco(s.cisco);
  renderTraffic(s.traffic);
}

const CISCO_STATES = {Connected: 'подключён', Disconnected: 'отключён', Connecting: 'подключается…',
                      Reconnecting: 'переподключается…', Disconnecting: 'отключается…'};

function renderCisco(c) {
  $('cisco').hidden = !c;  // Cisco Secure Client не установлен
  if (!c) return;
  const connected = c.state === 'Connected' || c.state === 'Reconnecting';
  $('cisco-state').textContent = c.busy ? 'подключается…' : c.state ? CISCO_STATES[c.state] || c.state : 'узнаю…';
  $('cisco-state').className = 'tag' + (connected ? ' green' : c.busy || /ing$/.test(c.state) ? ' blue' : '');
  $('cisco-host').textContent = c.host || 'не задан — впишите CISCO_HOST в .env';
  $('cisco-form').hidden = connected;
  $('cisco-actions').hidden = !connected;
  // Логин подставляем, только пока поле пустое: опрос раз в 3 секунды не должен мешать вводу.
  if (!$('cisco-user').value && document.activeElement !== $('cisco-user')) $('cisco-user').value = c.user;
  note('cisco-hint', !connected && c.gui
    ? 'Открыто окно Cisco Secure Client — пока оно работает, подключиться отсюда не получится. Закройте его.' : '');
}

async function ciscoAction(action, button, label, body = {}) {
  const text = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try {
    const r = await post('cisco/' + action, body);
    $('cisco-msg').className = 'note ' + (r.ok ? 'ok' : 'err');
    note('cisco-msg', r.message || (r.ok ? '' : 'Не получилось'));
    render(r);
    return r.ok;
  } catch (e) {
    $('cisco-msg').className = 'note err';
    note('cisco-msg', 'Нет связи с веб-интерфейсом: ' + e);
  } finally {
    button.disabled = false;
    button.textContent = text;
  }
}

$('cisco-form').onsubmit = async e => {
  e.preventDefault();
  const ok = await ciscoAction('connect', $('cisco-connect'), 'Подключаю… до 2 мин',
    {user: $('cisco-user').value, password: $('cisco-password').value, otp: $('cisco-otp').value});
  // Код одноразовый, а пароль после входа больше не нужен.
  $('cisco-otp').value = '';
  if (ok) $('cisco-password').value = '';
};
$('cisco-disconnect').onclick = () => ciscoAction('disconnect', $('cisco-disconnect'), 'Отключаю…');

async function poll() {
  if (!busy) {
    try { render(await (await fetch('/api/status')).json()); }
    catch (e) { $('state').className = 'state warn'; $('state-text').textContent = 'Нет связи с веб-интерфейсом'; }
  }
  setTimeout(poll, 3000);
}

$('toggle').onclick = async () => {
  const action = last && (last.running || last.restarting) ? 'off' : 'on';
  busy = true;
  $('toggle').disabled = true;
  $('toggle').textContent = action === 'on' ? 'Включаю…' : 'Выключаю…';
  try {
    const s = await post(action);
    note('error', s.ok ? '' : s.message || 'Не получилось');
    busy = false;
    render(s);
  } catch (e) {
    busy = false;
    note('error', 'Нет связи с веб-интерфейсом: ' + e);
  }
  $('ip').textContent = '';
};

$('check').onclick = async () => {
  $('check').disabled = true;
  $('ip').textContent = 'проверяю…';
  try {
    const r = await (await fetch('/api/ip')).json();
    $('ip').textContent = (r.vpn ? 'через VPN ' + r.vpn + ', ' : '') + 'напрямую ' + r.direct;
  } catch (e) {
    $('ip').textContent = 'не удалось: ' + e;
  }
  $('check').disabled = false;
};

$('update').onclick = () => serverAction('update', $('update'), 'Обновляю…');
$('test').onclick = () => serverAction('check', $('test'), 'Проверяю… до 15 с');

function share(n, total) {
  const p = 100 * n / total;
  return p < 0.1 ? '<0,1 %' : p.toLocaleString('ru', {maximumFractionDigits: 1}) + ' %';
}

async function loadHosts() {
  const app = $('hosts-app').value, group = $('hosts-group').checked ? 1 : 0;
  const query = new URLSearchParams({days: $('hosts-days').value, group, app});
  let r;
  try { r = await (await fetch('/api/hosts?' + query)).json(); }
  catch (e) { $('hosts-total').textContent = 'Нет связи с веб-интерфейсом: ' + e; return; }
  const count = n => n.toLocaleString('ru');

  const apps = r.apps.map(a => row([a.app, count(a.count), share(a.count, r.apps_total)], a.app === app ? 'current' : ''));
  $('apps').replaceChildren(...(apps.length ? apps : [emptyRow('Подключений через VPN за этот период не было', 3)]));
  // Список приложений в фильтре берём из ответа, выбранное оставляем, даже если за период его нет.
  const options = [['', 'Все приложения'], ...r.apps.map(a => [a.app, a.app])];
  if (app && !r.apps.some(a => a.app === app)) options.push([app, app]);
  $('hosts-app').replaceChildren(...options.map(([value, text]) => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = text;
    return option;
  }));
  $('hosts-app').value = app;

  const hosts = r.hosts.map(h => row([h.host, h.apps.join(', '), count(h.count), share(h.count, r.total)]));
  if (r.other_hosts) hosts.push(row(['остальные: ' + r.other_hosts, '', count(r.other_count), share(r.other_count, r.total)], 'muted'));
  $('hosts').replaceChildren(...(hosts.length ? hosts : [emptyRow('Подключений через VPN за этот период не было', 4)]));
  $('hosts-total').textContent = 'подключений: ' + count(r.total) + ', ' + (group ? 'доменов' : 'хостов') + ': ' + count(r.hosts_total);
}

$('hosts-days').onchange = loadHosts;
$('hosts-group').onchange = loadHosts;
$('hosts-app').onchange = loadHosts;
$('hosts-reset').onclick = async () => {
  if (!confirm('Сбросить статистику по приложениям и хостам за все дни? Считать начнём заново с этого момента.')) return;
  try { await post('hosts/reset'); }
  catch (e) { $('hosts-total').textContent = 'Нет связи с веб-интерфейсом: ' + e; return; }
  $('hosts-app').value = '';
  loadHosts();
};
setInterval(() => { if (!$('tab-hosts').hidden) loadHosts(); }, 30000);

// Вкладка хранится в адресе (#servers, #hosts), поэтому переживает перезагрузку страницы.
async function loadRules() {
  const r = await (await fetch('/api/rules')).json();
  for (const input of document.querySelectorAll('input[name=mode]')) input.checked = input.value === r.mode;
  $('rules-apps').value = r.apps.join('\\n');
  $('rules-hosts').value = r.hosts.join('\\n');
  $('rules-direct').value = r.direct.join('\\n');
}

$('rules-save').onclick = async () => {
  const lines = id => $(id).value.split('\\n').map(s => s.trim()).filter(Boolean);
  const mode = (document.querySelector('input[name=mode]:checked') || {}).value;
  $('rules-save').disabled = true;
  $('rules-save').textContent = 'Применяю…';
  try {
    const r = await post('rules', {mode, apps: lines('rules-apps'), hosts: lines('rules-hosts'),
                                   direct: lines('rules-direct')});
    $('rules-msg').className = 'note ' + (r.ok ? 'ok' : 'err');
    note('rules-msg', r.message || (r.ok ? '' : 'Не получилось'));
    if (r.ok) await loadRules();
  } catch (e) {
    $('rules-msg').className = 'note err';
    note('rules-msg', 'Нет связи с веб-интерфейсом: ' + e);
  }
  $('rules-save').disabled = false;
  $('rules-save').textContent = 'Сохранить и применить';
};

const TABS = {'#servers': 'servers', '#rules': 'rules', '#hosts': 'hosts'};
function showTab() {
  const tab = TABS[location.hash] || 'main';
  if (tab === 'rules') loadRules();
  for (const name of ['main', 'servers', 'rules', 'hosts']) {
    $('tab-' + name).hidden = name !== tab;
    if (name === tab) $('nav-' + name).setAttribute('aria-current', 'page');
    else $('nav-' + name).removeAttribute('aria-current');
  }
  if (tab === 'hosts') loadHosts();
}
window.addEventListener('hashchange', showTab);
showTab();

poll();
</script>
</body>
</html>
"""


def main():
    threading.Thread(target=collect_forever, daemon=True).start()
    threading.Thread(target=SOCKETS.run_forever, daemon=True).start()
    if WEB_BIND not in ("127.0.0.1", "localhost", "::1") and not WEB_PASSWORD:
        sys.exit(f"WEB_BIND={WEB_BIND} без WEB_PASSWORD: страницу без пароля откроет любой в сети")
    server = ThreadingHTTPServer((WEB_BIND, WEB_PORT), Handler)
    print(f"веб-интерфейс: http://{WEB_BIND}:{WEB_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
