#!/usr/bin/env python3
"""Веб-интерфейс для включения и выключения lan-vpn-proxy: http://127.0.0.1:WEB_PORT.

Кнопка запускает и останавливает контейнер; системный прокси GNOME вслед за ним
переключает proxy-watch.sh. Ещё здесь обновление подписки, проверка серверов
и трафик по дням (замер раз в минуту в data/traffic.json). Только стандартная библиотека Python.
"""
import collections
import datetime
import http.client
import json
import os
import re
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

from gen_config import (DEFAULT_OUTPUT, ENV_FILE, OUTBOUNDS_FILE, PROJECT_DIR, SERVERS_FILE, STATS_API,
                        build_check_config, build_config, listen_settings, load_env, set_env_value, setting,
                        write_json)

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

dotenv = load_env(ENV_FILE)
WEB_PORT = int(setting(dotenv, "WEB_PORT", "8765"))
HTTP_PORT = setting(dotenv, "HTTP_PORT", "3128")
SOCKS_PORT = setting(dotenv, "SOCKS_PORT", "1080")
# Страница управляет Docker, поэтому отвечаем только на свои адреса: это защищает
# от DNS rebinding и от запросов, которые чужой сайт отправит из браузера.
ALLOWED_HOSTS = {f"127.0.0.1:{WEB_PORT}", f"localhost:{WEB_PORT}"}
ALLOWED_ORIGINS = {f"http://{host}" for host in ALLOWED_HOSTS}
ACTION_LOCK = threading.Lock()
CHECK_LOCK = threading.Lock()
# Результат последней проверки: задержка в мс по названию сервера, None — не работает.
last_check = {"time": None, "delays": {}}


def run(*cmd, timeout=60):
    """Возвращает (успех, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout)
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
    """(отправлено, получено) через прокси с прошлого замера; счётчики Xray при этом обнуляются."""
    ok, out, _ = run("docker", "exec", CONTAINER, "xray", "api", "statsquery",
                     f"--server={STATS_API}", "-pattern", "inbound>>>", "-reset", timeout=10)
    if not ok:
        return 0, 0  # контейнер выключен — через VPN ничего не прошло
    up = down = 0
    for stat in json.loads(out).get("stat", []):
        # Нулевые значения Xray не выводит вовсе.
        if stat["name"].endswith(">>>uplink"):
            up += int(stat.get("value", 0))
        elif stat["name"].endswith(">>>downlink"):
            down += int(stat.get("value", 0))
    return up, down


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
        if pid not in self.names:
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    argv0 = f.read().split(b"\0", 1)[0].decode("utf-8", "replace")
            except OSError:
                argv0 = ""
            # Chrome и Electron переписывают cmdline одной строкой с аргументами через пробел.
            self.names[pid] = os.path.basename(argv0.split(" ", 1)[0]) or f"pid {pid}"
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


def select_server(index):
    servers, chains = load_servers(), load_chains()
    if not chains:
        return False, "Нет данных о серверах — нажмите «Обновить подписку»"
    if not isinstance(index, int) or not 0 <= index < len(chains):
        return False, "Нет такого сервера"
    name = servers["servers"][index]["name"]
    with ACTION_LOCK:
        write_json(DEFAULT_OUTPUT, build_config({"outbounds": chains[index]}, **listen_settings(load_env(ENV_FILE))))
        write_json(SERVERS_FILE, {**servers, "current": index})
        # Иначе «Обновить подписку» и ./gen_config.py вернули бы прежний сервер.
        set_env_value(ENV_FILE, "SERVER", name)
        if not container_state()["running"]:
            return True, f"Выбран сервер {name}. VPN выключен — включите его на главной вкладке."
        ok, _, err = run("docker", "compose", "up", "-d", "--force-recreate")
    return (True, f"VPN переключён на {name}.") if ok else (False, err)


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
        "servers_updated": servers["updated"] if servers else None,
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
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/":
            return self.respond(200, PAGE.encode(), "text/html; charset=utf-8")
        if url.path == "/api/status":
            return self.respond(200, status())
        if url.path == "/api/ip":
            return self.respond(200, check_ip())
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
<style>
  :root { color-scheme: light dark; --on: #1a7f37; --off: #8c959f; --warn: #bf8700; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1rem; font-weight: 500; opacity: .7; margin: 0 0 1rem; }
  nav { display: flex; gap: 1.2rem; border-bottom: 1px solid #8884; margin: 0 0 1.5rem; }
  nav a { padding: .4rem 0; margin-bottom: -1px; color: inherit; text-decoration: none; opacity: .7;
          border-bottom: 2px solid transparent; }
  nav a[aria-current] { opacity: 1; font-weight: 600; border-bottom-color: currentColor; }
  td button { padding: .2rem .6rem; font-size: .9rem; }
  .badge { font-size: .7rem; font-weight: 400; padding: 0 .35rem; border: 1px solid currentColor;
           border-radius: .3rem; vertical-align: middle; }
  .debug { background: #8c959f22; }
  .state { display: flex; align-items: center; gap: .6rem; font-size: 1.6rem; font-weight: 600; }
  .dot { width: .9rem; height: .9rem; border-radius: 50%; background: var(--off); flex: none; }
  .on .dot { background: var(--on); }
  .warn .dot { background: var(--warn); }
  button { font: inherit; padding: .4rem .9rem; border-radius: .5rem; border: 1px solid #8888; cursor: pointer; }
  button:disabled { cursor: progress; opacity: .6; }
  #toggle { width: 100%; margin: 1.2rem 0; padding: .8rem; font-size: 1.1rem; font-weight: 600; }
  .note { padding: .6rem .8rem; border-radius: .4rem; margin: 0 0 1rem; }
  #error { background: #cf222e22; }
  #hint { background: #bf870022; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: .4rem 1rem; margin: 0; }
  dt { opacity: .7; }
  dd { margin: 0; }
  h2 { font-size: 1.1rem; margin: 2rem 0 .5rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .3rem .8rem .3rem 0; border-bottom: 1px solid #8884; }
  th { font-weight: 500; opacity: .7; }
  td { font-variant-numeric: tabular-nums; }
  .foot { font-size: .85rem; opacity: .7; }
  .addr { display: block; font-size: .8rem; opacity: .6; }
  tr.current td { font-weight: 600; }
  tr.muted td { opacity: .7; }
  .ok { background: #1a7f3722; }
  .err { background: #cf222e22; }
  code { font-size: .9em; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
<h1>lan-vpn-proxy</h1>
<nav><a href="#" id="nav-main">Главная</a><a href="#servers" id="nav-servers">Серверы</a><a href="#hosts" id="nav-hosts">Хосты <span class="badge">отладка</span></a></nav>
<section id="tab-main">
<div id="state" class="state"><span class="dot"></span><span id="state-text">Загрузка…</span></div>
<button id="toggle" disabled>…</button>
<p id="error" class="note" hidden></p>
<p id="hint" class="note" hidden></p>
<dl>
  <dt>Сервер</dt><dd><span id="server">—</span> <a href="#servers">сменить</a></dd>
  <dt>Контейнер</dt><dd id="container">—</dd>
  <dt>Прокси GNOME</dt><dd id="proxy">—</dd>
  <dt>Внешний IP</dt><dd><span id="ip"></span> <button id="check">Проверить</button></dd>
</dl>
<h2>Трафик по дням</h2>
<table>
  <thead><tr><th>День</th><th>Через VPN</th><th>Напрямую</th></tr></thead>
  <tbody id="traffic"></tbody>
</table>
<p class="foot">↓ получено, ↑ отправлено. «Напрямую» — приблизительно: сюда же попадают
локальная сеть и накладные расходы шифрования VPN. Замер раз в минуту.</p>
</section>
<section id="tab-servers" hidden>
<p><button id="update">Обновить подписку</button> <button id="test">Проверить серверы</button></p>
<p id="servers-msg" class="note" hidden></p>
<table>
  <thead><tr><th>№</th><th>Сервер</th><th>Подключение</th><th>Задержка</th><th></th></tr></thead>
  <tbody id="servers"></tbody>
</table>
<p class="foot"><span id="servers-updated"></span> «Выбрать» переключает VPN на сервер и записывает его
в <code>SERVER</code> в .env; если VPN включён, связь пропадёт на пару секунд. Проверка делает настоящий
запрос через каждый сервер, задержка — время до ответа; сверху самые быстрые. № — номер в подписке.</p>
</section>
<section id="tab-hosts" hidden>
<p class="note debug">Отладочная функция: помогает понять, что идёт через VPN. Цифры приблизительные —
считаются подключения из журнала Xray, а не трафик.</p>
<p>
  <select id="hosts-days">
    <option value="1">Сегодня</option><option value="7">7 дней</option><option value="30">30 дней</option>
  </select>
  <label><input type="checkbox" id="hosts-group" checked> по доменам</label>
</p>
<h2>Приложения</h2>
<table>
  <thead><tr><th>Приложение</th><th>Подключений</th><th>Доля</th></tr></thead>
  <tbody id="apps"></tbody>
</table>
<h2>Хосты</h2>
<p><select id="hosts-app"><option value="">Все приложения</option></select> <span id="hosts-total"></span></p>
<table>
  <thead><tr><th>Хост</th><th>Приложения</th><th>Подключений</th><th>Доля</th></tr></thead>
  <tbody id="hosts"></tbody>
</table>
<p class="foot">Хосты, к которым программы подключались через VPN, по журналу Xray. Доля — от числа
подключений, а не от объёма: сколько байт ушло каждому хосту, Xray не считает. Приложение
определяется по открытым соединениям с прокси (опрос раз в 2 секунды), поэтому совсем короткие
подключения и программы других пользователей попадают в «не определено». «По доменам»
объединяет поддомены: mc.yandex.ru и yandex.ru → yandex.ru. Хранится 30 дней.</p>
</section>
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
    let action = 'текущий';
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
  $('toggle').textContent = active ? 'Выключить' : 'Включить';
  $('toggle').disabled = busy;
  $('container').textContent = s.status;
  $('server').textContent = s.server ? s.server.name + ' · ' + kind(s.server) : 'не выбран';
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
  renderTraffic(s.traffic);
}

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
setInterval(() => { if (!$('tab-hosts').hidden) loadHosts(); }, 30000);

// Вкладка хранится в адресе (#servers, #hosts), поэтому переживает перезагрузку страницы.
const TABS = {'#servers': 'servers', '#hosts': 'hosts'};
function showTab() {
  const tab = TABS[location.hash] || 'main';
  for (const name of ['main', 'servers', 'hosts']) {
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
    server = ThreadingHTTPServer(("127.0.0.1", WEB_PORT), Handler)
    print(f"веб-интерфейс: http://127.0.0.1:{WEB_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
