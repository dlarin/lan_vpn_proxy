"""Тесты автопереключения в web.py (AutoSwitch): Docker, Xray и сеть подменены.

Запуск: python3 -m unittest discover tests
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import web  # noqa: E402

SERVERS = {"current": 0, "servers": [{"name": "A"}, {"name": "B"}, {"name": "C"}]}


class AutoSwitchTest(unittest.TestCase):
    def setUp(self):
        self.auto = web.AutoSwitch()
        self.dir = tempfile.TemporaryDirectory()
        self.config = os.path.join(self.dir.name, "config.json")
        with open(self.config, "w") as f:
            json.dump({"inbounds": [{"tag": "http"}, {"tag": "health"}]}, f)
        self.selected = []
        self.patches = [
            mock.patch.object(web, "DEFAULT_OUTPUT", self.config),
            mock.patch.object(web, "container_state", return_value={"running": True}),
            mock.patch.object(web, "load_servers", return_value=SERVERS),
            mock.patch.object(web, "select_server", side_effect=lambda i: (self.selected.append(i), (True, ""))[1]),
            mock.patch("builtins.print"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.dir.cleanup()

    def run_checks(self, probe_delay, delays, times=web.AUTO_FAILS):
        def check_servers():
            web.last_check["delays"] = delays
            return True, ""
        with mock.patch.object(web, "probe", return_value=probe_delay), \
                mock.patch.object(web, "check_servers", side_effect=check_servers) as full:
            for _ in range(times):
                self.auto.check()
        return full

    def test_working_server_is_kept(self):
        full = self.run_checks(150, {})
        full.assert_not_called()
        self.assertEqual((self.auto.fails, self.selected), (0, []))

    def test_switches_to_fastest_after_fails(self):
        full = self.run_checks(None, {"A": None, "B": 300, "C": 120})
        full.assert_called_once()
        self.assertEqual(self.selected, [2])
        self.assertIn("с A на C", self.auto.event["text"])

    def test_no_switch_before_threshold(self):
        full = self.run_checks(None, {"A": None, "B": 100}, times=web.AUTO_FAILS - 1)
        full.assert_not_called()
        self.assertEqual(self.auto.fails, web.AUTO_FAILS - 1)

    def test_current_ok_on_full_check_means_temporary_failure(self):
        self.run_checks(None, {"A": 200, "B": 100})
        self.assertEqual(self.selected, [])

    def test_nothing_works_no_switch(self):
        self.run_checks(None, {"A": None, "B": None, "C": None})
        self.assertEqual(self.selected, [])
        self.assertIn("рабочих серверов нет", self.auto.event["text"])

    def test_vpn_off_is_left_alone(self):
        with mock.patch.object(web, "container_state", return_value={"running": False}):
            full = self.run_checks(None, {"B": 100})
        full.assert_not_called()

    def test_old_config_without_health_is_not_a_failure(self):
        with open(self.config, "w") as f:
            json.dump({"inbounds": [{"tag": "http"}]}, f)
        full = self.run_checks(None, {"B": 100})
        full.assert_not_called()
        self.assertEqual(self.auto.fails, 0)


if __name__ == "__main__":
    unittest.main()
