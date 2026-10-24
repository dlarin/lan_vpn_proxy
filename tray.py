#!/usr/bin/python3
"""Значок в трее GNOME: состояние VPN ноутбука (http://127.0.0.1:8765) и green (GREEN_URL).

Запускается системным Python (/usr/bin/python3) — в нём есть gi, ставить ничего не нужно. Значок —
StatusNotifierItem по D-Bus, его показывает расширение Ubuntu AppIndicators (включено по умолчанию);
меню — com.canonical.dbusmenu. Опрос раз в POLL секунд, только чтение /api/status.

В .env: GREEN_URL (по умолчанию https://192.168.0.2:8765), GREEN_PASSWORD — пароль веб-интерфейса green.
Сертификат green проверяется по копии data/green-web.crt (самоподписанный) — без неё green не опрашивается.
"""
import base64
import json
import os
import ssl
import subprocess
import threading
import urllib.request

from gi.repository import Gio, GLib

from gen_config import ENV_FILE, PROJECT_DIR, load_env, setting

LAPTOP_URL = "http://127.0.0.1:{}".format(setting(load_env(ENV_FILE), "WEB_PORT", "8765"))
GREEN_CERT = os.path.join(PROJECT_DIR, "data", "green-web.crt")
POLL = 30
TIMEOUT = 5
ICONS = {"on": "network-vpn-symbolic", "off": "network-vpn-disabled-symbolic", "warn": "network-vpn-no-route-symbolic"}

SNI_XML = """<node><interface name="org.kde.StatusNotifierItem">
<property name="Category" type="s" access="read"/><property name="Id" type="s" access="read"/>
<property name="Title" type="s" access="read"/><property name="Status" type="s" access="read"/>
<property name="IconName" type="s" access="read"/><property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
<property name="Menu" type="o" access="read"/><property name="ItemIsMenu" type="b" access="read"/>
<method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
<method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
<method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
<method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
<signal name="NewIcon"/><signal name="NewToolTip"/><signal name="NewTitle"/>
</interface></node>"""

MENU_XML = """<node><interface name="com.canonical.dbusmenu">
<property name="Version" type="u" access="read"/><property name="Status" type="s" access="read"/>
<property name="TextDirection" type="s" access="read"/><property name="IconThemePath" type="as" access="read"/>
<method name="GetLayout"><arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/>
<arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/></method>
<method name="GetGroupProperties"><arg type="ai" direction="in"/><arg type="as" direction="in"/>
<arg type="a(ia{sv})" direction="out"/></method>
<method name="GetProperty"><arg type="i" direction="in"/><arg type="s" direction="in"/>
<arg type="v" direction="out"/></method>
<method name="Event"><arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/>
<arg type="u" direction="in"/></method>
<method name="EventGroup"><arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/></method>
<method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
<method name="AboutToShowGroup"><arg type="ai" direction="in"/><arg type="ai" direction="out"/>
<arg type="ai" direction="out"/></method>
<signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
</interface></node>"""


def fetch(url, password=None, cafile=None):
    """/api/status или None, если не ответил."""
    request = urllib.request.Request(url + "/api/status")
    if password:
        request.add_header("Authorization", "Basic " + base64.b64encode(f"tray:{password}".encode()).decode())
    context = ssl.create_default_context(cafile=cafile) if url.startswith("https") else None
    # Без прокси: системный прокси GNOME — это сам Xray, а адреса локальные.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            return json.load(response)
    except (OSError, ValueError):
        return None


def size(n):
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024


def describe(name, status, unreachable):
    """Строки меню и состояние стороны: on / off / warn / None (недоступна)."""
    if status is None:
        return [f"{name}: {unreachable}"], None
    server = (status.get("server") or {}).get("name", "сервер не выбран")
    if status.get("running"):
        state = "on"
        lines = [f"{name}: VPN включён — {server}"]
    else:
        state = "off"
        lines = [f"{name}: VPN выключен"]
    if not status.get("watcher"):
        state = "warn"
        lines.append("    не работает служба " + ("шлюза" if (status.get("routing") or {}).get("gateway") else "прокси"))
    elif status.get("running") and not (status.get("routing") or {}).get("gateway") \
            and status.get("proxy_mode") != "manual":
        state = "warn"
        lines.append("    контейнер запущен, а прокси GNOME выключен")
    routing = status.get("routing") or {}
    if routing:
        mode = "всё через VPN" if routing.get("mode") == "all" else f"по списку, хостов {len(routing.get('hosts', []))}"
        lines.append(f"    правила: {mode}")
    today = (status.get("traffic") or [None])[0]
    if today:
        lines.append(f"    сегодня через VPN: ↓ {size(today['vpn_down'])}  ↑ {size(today['vpn_up'])}")
    event = (status.get("auto") or {}).get("event")
    if event:
        lines.append(f"    автопереключение {event['time']}: {event['text']}")
    cisco = status.get("cisco")
    if cisco:
        lines.append("    Cisco: " + ("подключён" if cisco.get("state") == "Connected" else "отключён"))
    return lines, state


class Tray:
    def __init__(self):
        dotenv = load_env(ENV_FILE)
        self.green_url = setting(dotenv, "GREEN_URL", "https://192.168.0.2:8765")
        self.green_password = setting(dotenv, "GREEN_PASSWORD", "")
        self.icon, self.tooltip = ICONS["off"], "lan-vpn-proxy"
        self.lines = ["загрузка…"]
        self.revision = 1
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION)
        self.name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        sni = Gio.DBusNodeInfo.new_for_xml(SNI_XML).interfaces[0]
        menu = Gio.DBusNodeInfo.new_for_xml(MENU_XML).interfaces[0]
        self.bus.register_object("/StatusNotifierItem", sni, self.sni_call, self.sni_get, None)
        self.bus.register_object("/MenuBar", menu, self.menu_call, self.menu_get, None)
        Gio.bus_own_name_on_connection(self.bus, self.name, Gio.BusNameOwnerFlags.NONE, None, None)
        # Watcher появляется вместе с GNOME Shell — следим, чтобы зарегистрироваться и после его перезапуска.
        Gio.bus_watch_name_on_connection(self.bus, "org.kde.StatusNotifierWatcher", Gio.BusNameWatcherFlags.NONE,
                                         self.register, None)
        self.refresh()
        GLib.timeout_add_seconds(POLL, self.refresh)

    def register(self, *_):
        self.bus.call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher",
                      "RegisterStatusNotifierItem", GLib.Variant("(s)", (self.name,)), None,
                      Gio.DBusCallFlags.NONE, -1, None, None)

    # --- опрос ---
    def refresh(self):
        threading.Thread(target=self.poll, daemon=True).start()
        return True

    def poll(self):
        laptop = fetch(LAPTOP_URL)
        green = None
        if self.green_password and os.path.exists(GREEN_CERT):
            green = fetch(self.green_url, self.green_password, GREEN_CERT)
            green_note = "недоступен (не дома?)"
        else:
            green_note = "нет GREEN_PASSWORD или data/green-web.crt"
        laptop_lines, laptop_state = describe("Ноутбук", laptop, "веб-интерфейс не отвечает")
        green_lines, green_state = describe("green", green, green_note)
        if "warn" in (laptop_state, green_state) or laptop_state is None:
            state = "warn"
        elif "on" in (laptop_state, green_state):
            state = "on"
        else:
            state = "off"
        GLib.idle_add(self.update, laptop_lines + ["-"] + green_lines, state)

    def update(self, lines, state):
        tooltip = "\n".join(line.strip() for line in lines if line != "-")
        if lines != self.lines:
            self.lines = lines
            self.revision += 1
            self.emit("/MenuBar", "com.canonical.dbusmenu", "LayoutUpdated", GLib.Variant("(ui)", (self.revision, 0)))
        if ICONS[state] != self.icon:
            self.icon = ICONS[state]
            self.emit("/StatusNotifierItem", "org.kde.StatusNotifierItem", "NewIcon", None)
        if tooltip != self.tooltip:
            self.tooltip = tooltip
            self.emit("/StatusNotifierItem", "org.kde.StatusNotifierItem", "NewToolTip", None)
        return False

    def emit(self, path, interface, signal, args):
        self.bus.emit_signal(None, path, interface, signal, args)

    # --- StatusNotifierItem ---
    def sni_get(self, _bus, _sender, _path, _iface, prop):
        return {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", "lan-vpn-proxy"),
            "Title": GLib.Variant("s", "lan-vpn-proxy"),
            "Status": GLib.Variant("s", "Active"),
            "IconName": GLib.Variant("s", self.icon),
            "ToolTip": GLib.Variant("(sa(iiay)ss)", (self.icon, [], "lan-vpn-proxy", self.tooltip)),
            "Menu": GLib.Variant("o", "/MenuBar"),
            "ItemIsMenu": GLib.Variant("b", True),
        }.get(prop)

    def sni_call(self, _bus, _sender, _path, _iface, method, _params, invocation):
        if method == "Activate":
            self.open(LAPTOP_URL)
        invocation.return_value(None)

    # --- меню ---
    def items(self):
        """(id, свойства) пунктов: 1… — строки состояния, затем действия."""
        items = []
        for i, line in enumerate(self.lines):
            if line == "-":
                items.append((100 + i, {"type": GLib.Variant("s", "separator")}))
            else:
                items.append((100 + i, {"label": GLib.Variant("s", line.replace("_", "__")),
                                        "enabled": GLib.Variant("b", False)}))
        items.append((1, {"type": GLib.Variant("s", "separator")}))
        items.append((2, {"label": GLib.Variant("s", "Открыть ноутбук — " + LAPTOP_URL)}))
        items.append((3, {"label": GLib.Variant("s", "Открыть green — " + self.green_url)}))
        items.append((4, {"label": GLib.Variant("s", "Обновить")}))
        items.append((5, {"label": GLib.Variant("s", "Закрыть значок")}))
        return items

    def layout(self):
        children = [GLib.Variant("(ia{sv}av)", (item_id, props, [])) for item_id, props in self.items()]
        return (0, {"children-display": GLib.Variant("s", "submenu")}, children)

    def menu_get(self, _bus, _sender, _path, _iface, prop):
        return {"Version": GLib.Variant("u", 3), "Status": GLib.Variant("s", "normal"),
                "TextDirection": GLib.Variant("s", "ltr"), "IconThemePath": GLib.Variant("as", [])}.get(prop)

    def menu_call(self, _bus, _sender, _path, _iface, method, params, invocation):
        if method == "GetLayout":
            invocation.return_value(GLib.Variant("(u(ia{sv}av))", (self.revision, self.layout())))
        elif method == "GetGroupProperties":
            ids = set(params.unpack()[0])
            props = [(i, p) for i, p in self.items() if not ids or i in ids]
            invocation.return_value(GLib.Variant("(a(ia{sv}))", (props,)))
        elif method == "GetProperty":
            item_id, name = params.unpack()
            value = dict(self.items()).get(item_id, {}).get(name, GLib.Variant("s", ""))
            invocation.return_value(GLib.Variant("(v)", (value,)))
        elif method == "Event":
            item_id, event = params.unpack()[:2]
            if event == "clicked":
                self.click(item_id)
            invocation.return_value(None)
        elif method == "EventGroup":
            for item_id, event, _data, _time in params.unpack()[0]:
                if event == "clicked":
                    self.click(item_id)
            invocation.return_value(GLib.Variant("(ai)", ([],)))
        elif method == "AboutToShow":
            self.refresh()
            invocation.return_value(GLib.Variant("(b)", (False,)))
        elif method == "AboutToShowGroup":
            self.refresh()
            invocation.return_value(GLib.Variant("(aiai)", ([], [])))

    def click(self, item_id):
        if item_id == 2:
            self.open(LAPTOP_URL)
        elif item_id == 3:
            self.open(self.green_url)
        elif item_id == 4:
            self.refresh()
        elif item_id == 5:
            LOOP.quit()

    @staticmethod
    def open(url):
        subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    LOOP = GLib.MainLoop()
    TRAY = Tray()
    LOOP.run()
