"""Тесты gen_config.py: разбор подписок и ссылок, .env, правила маршрутизации и сборка конфига.

Запуск: python3 -m unittest discover tests
Конфиг дополнительно проверяет сам Xray (docker run … run -test), если доступен Docker;
пропустить эту проверку — XRAY_TEST=0.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gen_config as g  # noqa: E402

# Ключи и UUID — выдуманные.
UUID = "11111111-2222-3333-4444-555555555555"
PUBKEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")  # формат ключа x25519
VLESS_REALITY = (f"vless://{UUID}@vpn.example.com:443?type=tcp&security=reality&sni=www.google.com"
                 f"&fp=chrome&pbk={PUBKEY}&sid=abcd&flow=xtls-rprx-vision#%F0%9F%A6%8B%20Fly")
VLESS_WS = f"vless://{UUID}@ws.example.com:8443?type=ws&security=tls&path=%2Fws&host=cdn.example.com#WS"
TROJAN = "trojan://p%40ss@tr.example.com:443?sni=tr.example.com#Trojan"
VMESS = "vmess://" + base64.b64encode(json.dumps({
    "ps": "VMess", "add": "vm.example.com", "port": "8080", "id": UUID, "net": "ws",
    "path": "/v", "host": "vm.example.com", "tls": "tls"}).encode()).decode()
SS_LEGACY = "ss://" + base64.b64encode(b"aes-256-gcm:secret@ss.example.com:8388").decode() + "#SS"
SS_SIP002 = "ss://" + base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:secret").decode().rstrip("=") \
    + "@ss2.example.com:8389#SS2"
SS_2022 = "ss://2022-blake3-aes-128-gcm:a2V5%3D@ss3.example.com:8390#SS2022"

ROUTING = {"mode": "filter", "apps": ["telegram-desktop"], "hosts": ["youtube.com", "91.108.4.0/22"],
           "direct": ["work.example.ru"]}


class ParseLinks(unittest.TestCase):
    def test_vless_reality(self):
        s = g.parse_link(VLESS_REALITY)
        self.assertEqual(s["name"], "🦋 Fly")
        o = s["outbounds"][0]
        user = o["settings"]["vnext"][0]["users"][0]
        self.assertEqual((o["settings"]["vnext"][0]["address"], o["settings"]["vnext"][0]["port"]),
                         ("vpn.example.com", 443))
        self.assertEqual(user, {"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"})
        reality = o["streamSettings"]["realitySettings"]
        self.assertEqual((reality["serverName"], reality["publicKey"], reality["shortId"]),
                         ("www.google.com", PUBKEY, "abcd"))

    def test_vless_ws_tls(self):
        stream = g.parse_link(VLESS_WS)["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["wsSettings"], {"path": "/ws", "host": "cdn.example.com"})
        self.assertEqual(stream["tlsSettings"]["serverName"], "cdn.example.com")

    def test_trojan_defaults_to_tls(self):
        o = g.parse_link(TROJAN)["outbounds"][0]
        self.assertEqual(o["settings"]["servers"][0]["password"], "p@ss")
        self.assertEqual(o["streamSettings"]["security"], "tls")

    def test_vmess(self):
        s = g.parse_link(VMESS)
        o = s["outbounds"][0]
        self.assertEqual(s["name"], "VMess")
        self.assertEqual(o["settings"]["vnext"][0]["port"], 8080)
        self.assertEqual(o["streamSettings"]["wsSettings"]["path"], "/v")

    def test_shadowsocks_variants(self):
        for link, address, method in [(SS_LEGACY, "ss.example.com", "aes-256-gcm"),
                                      (SS_SIP002, "ss2.example.com", "chacha20-ietf-poly1305"),
                                      (SS_2022, "ss3.example.com", "2022-blake3-aes-128-gcm")]:
            with self.subTest(link=link):
                server = g.parse_link(link)["outbounds"][0]["settings"]["servers"][0]
                self.assertEqual((server["address"], server["method"]), (address, method))
        self.assertEqual(g.parse_link(SS_2022)["outbounds"][0]["settings"]["servers"][0]["password"], "a2V5=")

    def test_plus_in_query_is_kept(self):
        # parse_qs сделал бы из «+» пробел
        self.assertEqual(g.parse_query("pbk=a+b%2Bc")["pbk"], "a+b+c")


class ParseSubscription(unittest.TestCase):
    def test_base64_list_skips_bad_lines(self):
        text = "\n".join([VLESS_REALITY, "# комментарий", "мусор", TROJAN, "vless://broken"])
        with mock.patch("sys.stderr"):
            servers = g.parse_servers(base64.b64encode(text.encode()).decode())
        self.assertEqual([s["name"] for s in servers][:2], ["🦋 Fly", "Trojan"])

    def test_happ_link_is_rejected(self):
        with self.assertRaises(SystemExit):
            g.parse_servers("happ://crypt/abc")

    def test_json_config_keeps_dialer_proxy_chain(self):
        data = [{"remarks": "Цепочка", "outbounds": [
            {"tag": "main", "protocol": "vless", "settings": {},
             "streamSettings": {"sockopt": {"dialerProxy": "frag"}}},
            {"tag": "frag", "protocol": "freedom", "settings": {"fragment": {}}},
            {"tag": "direct", "protocol": "freedom"},
        ]}]
        [server] = g.parse_servers(json.dumps(data))
        self.assertEqual(server["name"], "Цепочка")
        self.assertEqual([o["tag"] for o in server["outbounds"]], ["proxy", "frag"])


class Env(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".env")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_load_env_quotes_and_comments(self):
        with open(self.path, "w") as f:
            f.write("# комментарий\nA=1 # хвост\nB='x & $(y) # не комментарий'\nC=\"q\"\nBROKEN\n")
        self.assertEqual(g.load_env(self.path), {"A": "1", "B": "x & $(y) # не комментарий", "C": "q"})

    def test_set_env_value_keeps_other_lines(self):
        with open(self.path, "w") as f:
            f.write("# шапка\nROUTING_MODE=all\nOTHER=1")
        g.set_env_value(self.path, "ROUTING_MODE", "filter")
        g.set_env_value(self.path, "NEW", "it's")
        with open(self.path) as f:
            self.assertEqual(f.read(), "# шапка\nROUTING_MODE='filter'\nOTHER=1\nNEW=\"it's\"\n")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_environment_overrides_dotenv(self):
        with mock.patch.dict(os.environ, {"HTTP_PORT": "9999"}):
            self.assertEqual(g.setting({"HTTP_PORT": "3128"}, "HTTP_PORT"), "9999")
        self.assertEqual(g.setting({}, "MISSING", "def"), "def")

    def test_split_list(self):
        self.assertEqual(g.split_list(" a, b,,c ,"), ["a", "b", "c"])
        self.assertEqual(g.split_list(None), [])


class Routing(unittest.TestCase):
    def test_host_rules(self):
        domains, networks = g.host_rules(["YouTube.com", "full:t.me", "91.108.4.1/22", "2001:b28:f23c::/48"])
        self.assertEqual(domains, ["domain:youtube.com", "full:t.me"])
        self.assertEqual(networks, ["91.108.4.0/22", "2001:b28:f23c::/48"])

    def test_filter_order(self):
        rules = g.routing_rules(ROUTING)
        tags = [(next(k for k in ("ip", "domain", "process", "network") if k in r), r["outboundTag"]) for r in rules]
        # локальные сети и «всегда напрямую» — раньше правил VPN; приложения — после хостов; в конце — напрямую
        self.assertEqual(tags, [("ip", "direct"), ("domain", "direct"), ("domain", "proxy"), ("ip", "proxy"),
                                ("process", "proxy"), ("network", "direct")])

    def test_all_mode_has_no_catch_all_direct(self):
        rules = g.routing_rules(dict(ROUTING, mode="all"))
        self.assertTrue(all(r["outboundTag"] == "direct" for r in rules))
        self.assertFalse(any("network" in r for r in rules))


class BuildConfig(unittest.TestCase):
    def config(self, **kwargs):
        server = g.parse_link(VLESS_REALITY)
        return g.build_config(server, "127.0.0.1", 1080, 3128, ROUTING, **kwargs)

    def test_inbounds_and_direct_outbound(self):
        cfg = self.config()
        self.assertEqual([(i["tag"], i["port"]) for i in cfg["inbounds"]], [("socks", 1080), ("http", 3128)])
        self.assertEqual([o["tag"] for o in cfg["outbounds"]], ["proxy", "direct"])

    def test_tproxy_inbound(self):
        tproxy = self.config(tproxy_port=12345)["inbounds"][-1]
        self.assertEqual((tproxy["tag"], tproxy["port"], tproxy["protocol"]), ("tproxy", 12345, "dokodemo-door"))
        self.assertIn("quic", tproxy["sniffing"]["destOverride"])

    def test_config_settings_from_env(self):
        s = g.config_settings({"TPROXY_PORT": "12345", "ROUTING_MODE": "filter", "VPN_HOSTS": "a.com, b.com"})
        self.assertEqual((s["tproxy_port"], s["routing"]["mode"], s["routing"]["hosts"]), (12345, "filter", ["a.com", "b.com"]))

    def test_pick(self):
        servers = [{"name": "🦋 Fly"}, {"name": "✅Обновленный"}, {"name": "✅Обновленный 2"}]
        self.assertIs(g.pick(servers, ""), servers[0])
        self.assertIs(g.pick(servers, "2"), servers[1])
        self.assertIs(g.pick(servers, "✅Обновленный"), servers[1])  # полное название важнее части
        with self.assertRaises(SystemExit):
            g.pick(servers, "обновл")

    @unittest.skipIf(os.environ.get("XRAY_TEST") == "0" or not shutil.which("docker"), "нет Docker или XRAY_TEST=0")
    def test_xray_accepts_config(self):
        with open(os.path.join(g.PROJECT_DIR, "docker-compose.yml")) as f:
            image = next(line.split("image:")[1].strip() for line in f if "image:" in line)
        with tempfile.TemporaryDirectory() as d:
            # порты, которые не заняты прокси, — Xray с -test их не открывает, но пусть не путают
            cfg = g.build_config(g.parse_link(VLESS_REALITY), "127.0.0.1", 21080, 23128, ROUTING, tproxy_port=22345)
            path = os.path.join(d, "config.json")
            with open(path, "w") as f:
                json.dump(cfg, f)
            os.chmod(d, 0o755)
            os.chmod(path, 0o644)
            result = subprocess.run(["docker", "run", "--rm", "-v", f"{d}:/c:ro", image, "run", "-test", "-c", "/c/config.json"],
                                    capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
