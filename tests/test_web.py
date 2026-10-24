"""Тесты веб-интерфейса (web.py): защита запросов, пароль и блокировка подбора, сохранение правил.

Сервер поднимается на свободном порту 127.0.0.1; Docker и Xray подменены.
Запуск: /usr/bin/python3 -m unittest discover tests
"""
import base64
import http.client
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import web  # noqa: E402


class Server(unittest.TestCase):
    password = ""

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        self.host = f"127.0.0.1:{self.server.server_port}"
        self.patches = [
            mock.patch.object(web, "ALLOWED_HOSTS", {self.host}),
            mock.patch.object(web, "ALLOWED_ORIGINS", {f"http://{self.host}"}),
            mock.patch.object(web, "WEB_PASSWORD", self.password),
            mock.patch.object(web, "LOGIN_FAILS", web.collections.defaultdict(list)),
            mock.patch.object(web, "status", return_value={}),
            mock.patch.object(web, "turn_off", return_value=(True, "")),
            mock.patch("builtins.print"),
        ]
        for p in self.patches:
            p.start()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        for p in self.patches:
            p.stop()

    def request(self, method="GET", path="/favicon.svg", body=None, host=None, password=None, **headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Host": host or self.host, **{k.replace("_", "-"): v for k, v in headers.items()}}
        if password is not None:
            headers["Authorization"] = "Basic " + base64.b64encode(f"кто-угодно:{password}".encode()).decode()
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response.read()
        conn.close()
        return response

    def post(self, path="/api/off", body="{}", **headers):
        headers.setdefault("Content_Type", "application/json")
        headers.setdefault("Origin", f"http://{self.host}")
        return self.request("POST", path, body, **headers)


class RequestProtection(Server):
    def test_foreign_host_is_forbidden(self):
        # DNS rebinding: чужое имя, указывающее на 127.0.0.1
        self.assertEqual(self.request(host="evil.example:8765").status, 403)
        self.assertEqual(self.request().status, 200)

    def test_action_needs_json_and_own_origin(self):
        self.assertEqual(self.post(Content_Type="text/plain").status, 403)  # форма с чужого сайта
        self.assertEqual(self.post(Origin="https://evil.example").status, 403)
        self.assertEqual(self.post().status, 200)
        web.turn_off.assert_called_once()

    def test_bad_json_and_unknown_action(self):
        self.assertEqual(self.post(body="{").status, 400)
        self.assertEqual(self.post(path="/api/nope").status, 404)


class Password(Server):
    password = "secret"

    def test_password_required(self):
        response = self.request()
        self.assertEqual(response.status, 401)
        self.assertIn("Basic", response.getheader("WWW-Authenticate"))
        self.assertEqual(self.request(password="wrong").status, 401)
        self.assertEqual(self.request(password="secret").status, 200)

    def test_post_also_needs_password(self):
        self.assertEqual(self.post().status, 401)
        web.turn_off.assert_not_called()

    def test_brute_force_lockout(self):
        for _ in range(web.LOGIN_MAX_FAILS):
            self.assertEqual(self.request(password="wrong").status, 401)
        self.assertEqual(self.request(password="wrong").status, 429)
        self.assertEqual(self.request(password="secret").status, 429)  # до конца окна — даже с верным

    def test_request_without_password_is_not_an_attempt(self):
        # Браузер сначала всегда приходит без пароля — это не должно приближать блокировку.
        for _ in range(web.LOGIN_MAX_FAILS + 2):
            self.request()
        self.assertEqual(self.request(password="secret").status, 200)

    def test_success_resets_failures(self):
        for _ in range(web.LOGIN_MAX_FAILS - 1):
            self.request(password="wrong")
        self.request(password="secret")
        for _ in range(web.LOGIN_MAX_FAILS - 1):
            self.assertEqual(self.request(password="wrong").status, 401)


class SaveRules(unittest.TestCase):
    def setUp(self):
        self.env = {}
        self.patches = [
            mock.patch.object(web, "config_settings", return_value={"routing": {}}),
            mock.patch.object(web, "load_env", return_value={}),
            mock.patch.object(web, "load_servers", return_value={"current": 0}),
            mock.patch.object(web, "write_server_config", return_value=None),
            mock.patch.object(web, "restart_if_running", return_value=(True, True)),
            mock.patch.object(web, "set_env_value", side_effect=lambda path, k, v: self.env.update({k: v})),
            # По умолчанию конфиг после сохранения другой: каждый вызов — новый объект.
            mock.patch.object(web, "comparable_config", side_effect=lambda: object()),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def save(self, mode="filter", apps=(), hosts=("youtube.com",), direct=()):
        return web.save_rules({"mode": mode, "apps": list(apps), "hosts": list(hosts), "direct": list(direct)})

    def test_saves_lists_to_env(self):
        ok, message = self.save(hosts=[" youtube.com ", "t.me", "youtube.com", ""], direct=["work.ru"])
        self.assertTrue(ok, message)
        updated = self.env.pop("RULES_UPDATED")
        self.assertEqual(self.env, {"ROUTING_MODE": "filter", "VPN_APPS": "", "VPN_HOSTS": "youtube.com, t.me",
                                    "DIRECT_HOSTS": "work.ru"})
        self.assertAlmostEqual(int(updated), web.time.time(), delta=5)
        self.assertIn("перезапущен", message)

    def test_same_config_no_restart(self):
        # Например, на шлюзе поменяли только VPN_APPS — VPN всей сети перезапускать незачем.
        web.comparable_config.side_effect = lambda: {"same": True}
        ok, message = self.save()
        self.assertTrue(ok)
        web.restart_if_running.assert_not_called()
        self.assertNotIn("перезапущен", message)

    def test_keeps_given_update_time(self):
        # sync-rules.py переносит правила с другой машины вместе с их временем.
        web.save_rules({"mode": "all", "apps": [], "hosts": [], "direct": []}, 1700000000)
        self.assertEqual(self.env["RULES_UPDATED"], "1700000000")
        web.save_rules({"mode": "all", "apps": [], "hosts": [], "direct": []}, "мусор")
        self.assertNotEqual(self.env["RULES_UPDATED"], "1700000000")

    def test_rejects_bad_input(self):
        for kwargs in ({"mode": "nope"}, {"hosts": ["a.com, b.com"]}, {"hosts": ["a b"]}, {"direct": ["x'y"]},
                       {"hosts": []}):  # пустые списки в режиме filter — через VPN не пойдёт ничего
            with self.subTest(**kwargs):
                ok, _ = self.save(**kwargs)
                self.assertFalse(ok)
        self.assertEqual(self.env, {})
        self.assertFalse(web.save_rules({"mode": "all", "apps": "not a list", "hosts": [], "direct": []})[0])

    def test_config_rejected_by_xray_is_not_saved(self):
        web.write_server_config.return_value = "Xray не принял конфиг: …"
        ok, message = self.save()
        self.assertFalse(ok)
        self.assertEqual(self.env, {})
        web.restart_if_running.assert_not_called()


class RulesCli(unittest.TestCase):
    """`web.py rules` и `web.py rules-set` — их вызывает sync-rules.py."""

    def test_rules_set_passes_time_and_exit_code(self):
        body = {"mode": "all", "apps": [], "hosts": [], "direct": [], "updated": 1700000000}
        for ok, code in ((True, 0), (False, 1)):
            with self.subTest(ok=ok), mock.patch.object(web, "save_rules", return_value=(ok, "сообщение")) as save, \
                    mock.patch.object(web.sys, "stdin", io.StringIO(json.dumps(body))), \
                    mock.patch("builtins.print"), self.assertRaises(SystemExit) as exit_:
                web.rules_cli(["rules-set"])
            save.assert_called_once_with(body, 1700000000)
            self.assertEqual(exit_.exception.code, code)

    def test_rules_prints_json(self):
        with mock.patch.object(web, "rules_info", return_value={"mode": "all", "updated": 5}), \
                mock.patch("builtins.print") as out:
            web.rules_cli(["rules"])
        self.assertEqual(json.loads(out.call_args.args[0]), {"mode": "all", "updated": 5})


class ActionLockTest(unittest.TestCase):
    def test_blocks_other_process(self):
        # web.py rules-set (sync-rules.py) — отдельный процесс: ему должна мешать блокировка службы.
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "action.lock")
            try_lock = ("import fcntl, sys; f = open(sys.argv[1], 'a')\n"
                        "try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                        "except OSError: sys.exit(1)")
            with web.ActionLock(path):
                self.assertEqual(subprocess.run([sys.executable, "-c", try_lock, path]).returncode, 1)
            self.assertEqual(subprocess.run([sys.executable, "-c", try_lock, path]).returncode, 0)


class XrayReleaseTest(unittest.TestCase):
    def check(self, current, latest, ours_exists=True):
        release = web.XrayRelease()

        def get(path):
            if path == "/latest":
                return {"tag_name": "v" + latest}
            if not ours_exists:
                raise web.urllib.error.HTTPError(path, 404, "Not Found", {}, None)
            return {}
        with mock.patch.object(release, "current", return_value=current), mock.patch.object(release, "get", get):
            release.check()
            return release.info()

    def test_update_available(self):
        self.assertTrue(self.check("26.10.17", "26.10.21")["update"])
        self.assertFalse(self.check("26.10.21", "26.10.21")["update"])
        # Основной релиз бывает старше свежего prerelease — это не повод предлагать «обновление».
        self.assertFalse(self.check("26.10.21", "26.3.27")["update"])
        self.assertTrue(web.XrayRelease.newer("26.11.1", "26.10.21"))

    def test_withdrawn(self):
        info = self.check("26.10.17", "26.10.21", ours_exists=False)
        self.assertTrue(info["withdrawn"])
        self.assertFalse(self.check("26.10.21", "26.10.21")["withdrawn"])

    def test_stale_container(self):
        # docker-compose.yml обновили (scp), а контейнер не пересоздали — работает старая версия.
        release = web.XrayRelease()
        with mock.patch.object(release, "current", return_value="26.10.21"):
            info = release.info("ghcr.io/xtls/xray-core:26.10.17")
            self.assertEqual((info["running"], info["stale"]), ("26.10.17", True))
            self.assertFalse(release.info("ghcr.io/xtls/xray-core:26.10.21")["stale"])
            self.assertFalse(release.info(None)["stale"])  # контейнера нет

    def test_kernel_update(self):
        files = ["vmlinuz-6.12.107+deb13-amd64", "vmlinuz-6.12.113+deb13-amd64", "initrd.img-6.12.113+deb13-amd64"]
        with mock.patch.object(web.os, "listdir", return_value=files):
            for running, expected in (("6.12.107+deb13-amd64", "6.12.113+deb13-amd64"), ("6.12.113+deb13-amd64", None)):
                with self.subTest(running=running), \
                        mock.patch.object(web.os, "uname", return_value=mock.Mock(release=running)):
                    self.assertEqual(web.kernel_update(), expected)

    def test_current_from_compose(self):
        self.assertRegex(web.XrayRelease.current(), r"^\d+\.\d+\.\d+$")


class DevicesTest(unittest.TestCase):
    MAC = "5a:a1:3c:77:fb:d8"

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.devices = web.Devices(os.path.join(self.dir.name, "devices.json"))

    def tearDown(self):
        self.dir.cleanup()

    def test_neighbours_parsing(self):
        out = ("192.168.0.1 dev enp2s0 lladdr 74:DA:88:13:85:F8 REACHABLE\n"
               "192.168.0.178 dev enp2s0 FAILED\n"
               f"192.168.0.184 dev enp2s0 lladdr {self.MAC} STALE")
        with mock.patch.object(web, "run", return_value=(True, out, "")):
            self.assertEqual(web.Devices.neighbours(), {"192.168.0.1": "74:da:88:13:85:f8", "192.168.0.184": self.MAC})

    def test_key_by_mac_and_fallback_to_ip(self):
        self.assertEqual(self.devices.key_for("192.168.0.184", {"192.168.0.184": self.MAC}), "устройство " + self.MAC)
        self.assertEqual(self.devices.key_for("192.168.0.178", {}), "устройство 192.168.0.178")

    def test_rename_and_labels(self):
        self.devices.key_for("192.168.0.184", {"192.168.0.184": self.MAC})
        self.assertEqual(self.devices.resolve("устройство " + self.MAC), ("устройство 192.168.0.184", self.MAC))
        self.assertTrue(self.devices.rename({"device": self.MAC.upper(), "name": "Телефон"})[0])
        self.assertEqual(self.devices.resolve("устройство " + self.MAC), ("Телефон", self.MAC))
        # старая запись статистики по IP получает имя устройства с этим адресом
        self.assertEqual(self.devices.resolve("устройство 192.168.0.184"), ("Телефон", self.MAC))
        self.assertEqual(self.devices.resolve("firefox"), ("firefox", None))
        # имя переживает перезапуск
        self.assertEqual(web.Devices(self.devices.path).resolve("устройство " + self.MAC)[0], "Телефон")
        self.assertTrue(self.devices.rename({"device": self.MAC, "name": ""})[0])
        self.assertEqual(self.devices.resolve("устройство " + self.MAC)[0], "устройство 192.168.0.184")

    def test_summary_merges_ip_and_mac_records(self):
        self.devices.key_for("192.168.0.184", {"192.168.0.184": self.MAC})
        log = web.HostLog(os.path.join(self.dir.name, "hosts.json"))
        today = web.datetime.date.today().isoformat()
        log.data["days"] = {today: {"устройство 192.168.0.184": {"youtube.com": 5}, "устройство " + self.MAC: {"t.me": 2}}}
        with mock.patch.object(web, "DEVICES", self.devices):
            summary = log.summary(1, False)
            self.assertEqual([(a["app"], a["count"]) for a in summary["apps"]], [("устройство " + self.MAC, 7)])
            # фильтр по устройству — по объединённому ключу
            self.assertEqual(log.summary(1, False, "устройство " + self.MAC)["total"], 7)

    def test_rename_rejects_bad_input(self):
        self.devices.key_for("192.168.0.184", {"192.168.0.184": self.MAC})
        for body in ({"device": "aa:bb:cc:dd:ee:ff", "name": "x"}, {"device": "../etc", "name": "x"},
                     {"device": self.MAC, "name": "x" * 41}, {"device": self.MAC, "name": "a\nb"}, None):
            with self.subTest(body=body):
                self.assertFalse(self.devices.rename(body)[0])


if __name__ == "__main__":
    unittest.main()
