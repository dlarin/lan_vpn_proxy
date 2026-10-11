#!/usr/bin/env python3
"""Собирает xray/config.json для контейнера lan-vpn-proxy.

Подписка и сервер берутся из .env (SUBSCRIPTION, SERVER, SUBSCRIPTION_USER_AGENT).
SOURCE, если указан, заменяет SUBSCRIPTION: URL подписки, ссылка
(vless://, vmess://, trojan://, ss://), путь к файлу с одним из них или "-" для stdin.
"""
import argparse
import base64
import binascii
import json
import os
import sys
import urllib.request
from urllib.parse import unquote, urlsplit

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(PROJECT_DIR, ".env")
DEFAULT_OUTPUT = os.path.join(PROJECT_DIR, "xray", "config.json")
DEFAULT_USER_AGENT = "v2rayN/7.13.8"
LINK_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
SERVICE_PROTOCOLS = {"freedom", "blackhole", "dns", "loopback"}
PRIVATE_NETS = [
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]
# Порты внутри контейнера; наружу пробрасываются в docker-compose.yml.
SOCKS_PORT = 1080
HTTP_PORT = 3128


def load_env(path):
    """Читает .env в формате docker compose: KEY=VALUE, значения можно брать в кавычки."""
    values = {}
    if not os.path.isfile(path):
        return values
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()
            values[key.strip()] = value
    return values


def setting(dotenv, key, default=None):
    # Как в docker compose: переменная окружения важнее значения из .env.
    return os.environ.get(key) or dotenv.get(key) or default


def b64decode(text):
    text = "".join(text.split()).replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text, validate=True).decode("utf-8")


def parse_query(query):
    # parse_qs превращает "+" в пробел, а в ссылках он бывает значимым.
    params = {}
    for part in query.split("&"):
        if part:
            key, _, value = part.partition("=")
            params[unquote(key)] = unquote(value)
    return params


def stream_settings(q, default_security="none"):
    network = q.get("type") or "tcp"
    network = {"raw": "tcp", "splithttp": "xhttp"}.get(network, network)
    security = q.get("security") or default_security
    host = q.get("host", "")
    path = q.get("path", "")
    stream = {"network": network, "security": security}

    if network == "ws":
        stream["wsSettings"] = {"path": path or "/", "host": host}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path or "/", "host": host}
    elif network == "grpc":
        grpc = {"serviceName": q.get("serviceName") or path, "multiMode": q.get("mode") == "multi"}
        if q.get("authority"):
            grpc["authority"] = q["authority"]
        stream["grpcSettings"] = grpc
    elif network == "xhttp":
        xhttp = {"path": path or "/", "host": host, "mode": q.get("mode") or "auto"}
        if q.get("extra"):
            xhttp["extra"] = json.loads(q["extra"])
        stream["xhttpSettings"] = xhttp
    elif network == "tcp" and q.get("headerType") == "http":
        request = {"path": path.split(",") if path else ["/"]}
        if host:
            request["headers"] = {"Host": host.split(",")}
        stream["tcpSettings"] = {"header": {"type": "http", "request": request}}

    if security == "tls":
        tls = {"fingerprint": q.get("fp") or "chrome"}
        if q.get("sni") or host:
            tls["serverName"] = q.get("sni") or host
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp") or "chrome",
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
        if q.get("pqv"):
            reality["mldsa65Verify"] = q["pqv"]
        stream["realitySettings"] = reality
    return stream


def parse_vmess(link):
    v = json.loads(b64decode(link[len("vmess://"):]))
    q = {
        "type": v.get("net"), "headerType": v.get("type"), "host": v.get("host", ""),
        "path": v.get("path", ""), "security": v.get("tls") or "none", "sni": v.get("sni", ""),
        "alpn": v.get("alpn", ""), "fp": v.get("fp", ""),
    }
    user = {"id": v["id"], "security": v.get("scy") or "auto"}
    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {"vnext": [{"address": v["add"], "port": int(v["port"]), "users": [user]}]},
        "streamSettings": stream_settings(q),
    }
    return {"name": v.get("ps") or v["add"], "outbounds": [outbound]}


def parse_ss(link):
    body, _, fragment = link[len("ss://"):].partition("#")
    body, _, query = body.partition("?")
    if "plugin" in parse_query(query):
        raise ValueError("ss с плагинами не поддерживается")
    body = body.rstrip("/")
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        userinfo = unquote(userinfo)
        try:
            decoded = b64decode(userinfo)
            if ":" in decoded:
                userinfo = decoded
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass  # SIP002 для 2022-методов: userinfo не в base64
    else:
        userinfo, _, hostport = b64decode(body).rpartition("@")
    method, _, password = userinfo.partition(":")
    u = urlsplit("//" + hostport)
    server = {"address": u.hostname, "port": u.port, "method": method, "password": password}
    outbound = {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [server]}}
    return {"name": unquote(fragment) or u.hostname, "outbounds": [outbound]}


def parse_link(link):
    scheme = link.split("://", 1)[0]
    if scheme == "vmess":
        return parse_vmess(link)
    if scheme == "ss":
        return parse_ss(link)

    u = urlsplit(link)
    q = parse_query(u.query)
    secret = unquote(u.netloc.rpartition("@")[0])
    if scheme == "vless":
        user = {"id": secret, "encryption": q.get("encryption") or "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
        settings = {"vnext": [{"address": u.hostname, "port": u.port, "users": [user]}]}
        stream = stream_settings(q)
    elif scheme == "trojan":
        settings = {"servers": [{"address": u.hostname, "port": u.port, "password": secret}]}
        stream = stream_settings(q, default_security="tls")
    else:
        raise ValueError(f"протокол {scheme} не поддерживается")
    outbound = {"tag": "proxy", "protocol": scheme, "settings": settings, "streamSettings": stream}
    return {"name": unquote(u.fragment) or u.hostname, "outbounds": [outbound]}


def parse_json_configs(data):
    servers = []
    for cfg in data if isinstance(data, list) else [data]:
        outbounds = cfg.get("outbounds") or []
        by_tag = {o["tag"]: o for o in outbounds if o.get("tag")}
        main = next((o for o in outbounds if o.get("protocol") not in SERVICE_PROTOCOLS), None)
        if main is None:
            continue
        chain = [dict(main, tag="proxy")]
        # Цепочки через dialerProxy (например, фрагментация) переносим вместе с основным outbound.
        ref = main.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy")
        while ref in by_tag and by_tag[ref] not in chain:
            chain.append(by_tag[ref])
            ref = by_tag[ref].get("streamSettings", {}).get("sockopt", {}).get("dialerProxy")
        servers.append({"name": cfg.get("remarks") or main.get("tag") or "?", "outbounds": chain})
    return servers


def parse_servers(text):
    if "://" not in text and not text.startswith(("{", "[")):
        try:
            text = b64decode(text).strip()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    if text.startswith(("{", "[")):
        return parse_json_configs(json.loads(text))

    servers = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("happ://"):
            sys.exit("ссылка зашифрована для Happ (happ://…): попросите у провайдера обычную подписку")
        if not line.startswith(LINK_SCHEMES):
            print(f"пропускаю строку: {line[:40]}", file=sys.stderr)
            continue
        try:
            servers.append(parse_link(line))
        except (KeyError, ValueError, json.JSONDecodeError, binascii.Error) as e:
            print(f"пропускаю ссылку {line[:20]}…: {e}", file=sys.stderr)
    return servers


def read_source(source, user_agent):
    if source == "-":
        text = sys.stdin.read()
    elif os.path.isfile(source):
        with open(source, encoding="utf-8") as f:
            text = f.read()
    else:
        text = source
    text = text.strip()
    if text.startswith(("http://", "https://")) and len(text.split()) == 1:
        request = urllib.request.Request(text, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8").strip()
    return text


def build_config(server):
    outbounds = list(server["outbounds"])
    if not any(o.get("tag") == "direct" for o in outbounds):
        outbounds.append({"tag": "direct", "protocol": "freedom"})
    sniffing = {"enabled": True, "destOverride": ["http", "tls"]}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "0.0.0.0", "port": SOCKS_PORT, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": False}, "sniffing": sniffing},
            {"tag": "http", "listen": "0.0.0.0", "port": HTTP_PORT, "protocol": "http",
             "settings": {}, "sniffing": sniffing},
        ],
        "outbounds": outbounds,
        # Всё, кроме локальных сетей, уходит в первый outbound — VPN.
        "routing": {"rules": [{"type": "field", "ip": PRIVATE_NETS, "outboundTag": "direct"}]},
    }


def pick(servers, choice):
    if not choice:
        return servers[0]
    if choice.isdigit() and 1 <= int(choice) <= len(servers):
        return servers[int(choice) - 1]
    matches = [s for s in servers if choice.lower() in s["name"].lower()]
    if len(matches) != 1:
        sys.exit(f"по «{choice}» найдено серверов: {len(matches)}; посмотрите список через --list")
    return matches[0]


def write_config(path, config):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def main():
    dotenv = load_env(ENV_FILE)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", nargs="?", default=setting(dotenv, "SUBSCRIPTION"),
                        help="URL подписки, ссылка, файл или - (по умолчанию SUBSCRIPTION из .env)")
    parser.add_argument("-l", "--list", action="store_true", help="показать серверы и выйти")
    parser.add_argument("-s", "--server", default=setting(dotenv, "SERVER"),
                        help="номер из --list или часть названия (по умолчанию SERVER из .env, иначе первый)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="куда записать конфиг")
    parser.add_argument("--user-agent", default=setting(dotenv, "SUBSCRIPTION_USER_AGENT", DEFAULT_USER_AGENT),
                        help="User-Agent для загрузки подписки (по умолчанию SUBSCRIPTION_USER_AGENT из .env)")
    args = parser.parse_args()
    if not args.source:
        sys.exit(f"подписка не задана: заполните SUBSCRIPTION в {ENV_FILE} или передайте её аргументом")

    servers = parse_servers(read_source(args.source, args.user_agent))
    if not servers:
        sys.exit("серверы не найдены; если это подписка, попробуйте другой --user-agent")
    if args.list:
        for i, server in enumerate(servers, 1):
            print(f"{i:3}  {server['name']}")
        return

    server = pick(servers, args.server)
    write_config(args.output, build_config(server))
    print(f"сервер: {server['name']}\nконфиг: {args.output}\nприменить: docker compose up -d --force-recreate")


if __name__ == "__main__":
    main()
