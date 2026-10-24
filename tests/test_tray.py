"""Тесты tray.py: строки меню и состояние значка. Без gi (не системный Python) тест пропускается.

Запуск: /usr/bin/python3 -m unittest discover tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import tray  # noqa: E402
except ImportError:
    tray = None


def status(**changes):
    return {"running": True, "watcher": True, "proxy_mode": "manual", "server": {"name": "Лама"},
            "routing": {"mode": "filter", "hosts": ["a.com"], "gateway": False},
            "traffic": [{"vpn_down": 2048, "vpn_up": 10}], "auto": {"event": None}, "cisco": None, **changes}


@unittest.skipIf(tray is None, "нет gi — запускайте системным /usr/bin/python3")
class Describe(unittest.TestCase):
    def test_on(self):
        lines, state = tray.describe("Ноутбук", status(), "")
        self.assertEqual(state, "on")
        self.assertIn("Лама", lines[0])
        self.assertIn("↓ 2.0 КБ", "\n".join(lines))

    def test_unreachable(self):
        self.assertEqual(tray.describe("green", None, "недоступен"), (["green: недоступен"], None))

    def test_container_without_gnome_proxy_warns(self):
        self.assertEqual(tray.describe("Ноутбук", status(proxy_mode="none"), "")[1], "warn")
        # На шлюзе прокси GNOME нет — это не повод для предупреждения.
        gateway = status(proxy_mode="none", routing={"mode": "all", "gateway": True})
        self.assertEqual(tray.describe("green", gateway, "")[1], "on")

    def test_auto_switch_probe(self):
        probe = lambda delay, fails=0: "\n".join(tray.describe("green", status(auto={  # noqa: E731
            "enabled": True, "fails": fails, "probe": {"time": "2026-10-24T23:10", "delay": delay}}), "")[0])
        self.assertIn("проверка сервера 23:10: 180 мс", probe(180))
        self.assertIn("23:10: не ответил (2 подряд)", probe(None, 2))
        self.assertNotIn("проверка", "\n".join(tray.describe("Ноутбук", status(), "")[0]))  # выключено

    def test_stale_container_and_kernel(self):
        lines, state = tray.describe("green", status(
            xray={"current": "26.10.21", "running": "26.10.17", "stale": True}, kernel="6.12.120+deb13-amd64"), "")
        self.assertEqual(state, "warn")
        text = "\n".join(lines)
        self.assertIn("пересоздайте", text)
        self.assertIn("нужна перезагрузка", text)

    def test_stopped_service_warns(self):
        self.assertEqual(tray.describe("Ноутбук", status(running=False, watcher=False), "")[1], "warn")


if __name__ == "__main__":
    unittest.main()
