"""Тесты веб-интерфейса (web.py): защита запросов, пароль и блокировка подбора, сохранение правил.

Сервер поднимается на свободном порту 127.0.0.1; Docker и Xray подменены.
Запуск: python3 -m unittest discover tests
"""
import base64
import http.client
import json
import os
import sys
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
        self.assertEqual(self.env, {"ROUTING_MODE": "filter", "VPN_APPS": "", "VPN_HOSTS": "youtube.com, t.me",
                                    "DIRECT_HOSTS": "work.ru"})
        self.assertIn("перезапущен", message)

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


if __name__ == "__main__":
    unittest.main()
