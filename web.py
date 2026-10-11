#!/usr/bin/env python3
"""Веб-интерфейс для включения и выключения lan-vpn-proxy: http://127.0.0.1:WEB_PORT.

Кнопка запускает и останавливает контейнер; системный прокси GNOME вслед за ним
переключает proxy-watch.sh. Только стандартная библиотека Python.
"""
import http.client
import json
import os
import subprocess
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gen_config import DEFAULT_OUTPUT, ENV_FILE, PROJECT_DIR, load_env, setting

CONTAINER = "lan-vpn-proxy"
WATCH_SERVICE = "lan-vpn-proxy-watch.service"
IP_URL = "https://ifconfig.me/ip"

dotenv = load_env(ENV_FILE)
WEB_PORT = int(setting(dotenv, "WEB_PORT", "8765"))
HTTP_PORT = setting(dotenv, "HTTP_PORT", "3128")
# Страница управляет Docker, поэтому отвечаем только на свои адреса: это защищает
# от DNS rebinding и от запросов, которые чужой сайт отправит из браузера.
ALLOWED_HOSTS = {f"127.0.0.1:{WEB_PORT}", f"localhost:{WEB_PORT}"}
ALLOWED_ORIGINS = {f"http://{host}" for host in ALLOWED_HOSTS}
ACTION_LOCK = threading.Lock()


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


def status():
    _, mode, _ = run("gsettings", "get", "org.gnome.system.proxy", "mode", timeout=5)
    _, port, _ = run("gsettings", "get", "org.gnome.system.proxy.http", "port", timeout=5)
    _, watcher, _ = run("systemctl", "--user", "is-active", WATCH_SERVICE, timeout=5)
    return {
        **container_state(),
        "config": os.path.isfile(DEFAULT_OUTPUT),
        "proxy_mode": mode.strip("'"),
        "proxy_port": port,
        "http_port": HTTP_PORT,
        "watcher": watcher == "active",
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
        if self.path == "/":
            return self.respond(200, PAGE.encode(), "text/html; charset=utf-8")
        if self.path == "/api/status":
            return self.respond(200, status())
        if self.path == "/api/ip":
            return self.respond(200, check_ip())
        self.respond(404, {"error": "not found"})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if not self.allowed(action=True):
            return self.respond(403, {"error": "forbidden"})
        action = {"/api/on": turn_on, "/api/off": turn_off}.get(self.path)
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
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 30rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1rem; font-weight: 500; opacity: .7; margin: 0 0 1rem; }
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
  [hidden] { display: none !important; }
</style>
</head>
<body>
<h1>lan-vpn-proxy</h1>
<div id="state" class="state"><span class="dot"></span><span id="state-text">Загрузка…</span></div>
<button id="toggle" disabled>…</button>
<p id="error" class="note" hidden></p>
<p id="hint" class="note" hidden></p>
<dl>
  <dt>Контейнер</dt><dd id="container">—</dd>
  <dt>Прокси GNOME</dt><dd id="proxy">—</dd>
  <dt>Внешний IP</dt><dd><span id="ip"></span> <button id="check">Проверить</button></dd>
</dl>
<script>
const $ = id => document.getElementById(id);
let busy = false, last = null;

function note(id, text) { $(id).textContent = text; $(id).hidden = !text; }

function render(s) {
  last = s;
  const active = s.running || s.restarting;
  $('state').className = 'state ' + (s.restarting ? 'warn' : s.running ? 'on' : '');
  $('state-text').textContent = s.restarting ? 'Контейнер перезапускается' : s.running ? 'VPN включён' : 'VPN выключен';
  $('toggle').textContent = active ? 'Выключить' : 'Включить';
  $('toggle').disabled = busy;
  $('container').textContent = s.status;
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
    const r = await fetch('/api/' + action, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
    const s = await r.json();
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

poll();
</script>
</body>
</html>
"""


def main():
    server = ThreadingHTTPServer(("127.0.0.1", WEB_PORT), Handler)
    print(f"веб-интерфейс: http://127.0.0.1:{WEB_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
