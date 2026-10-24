"""Тесты sync-rules.py: чьи правила взять. Запуск: /usr/bin/python3 -m unittest discover tests"""
import importlib.util
import os
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("sync_rules", os.path.join(PROJECT_DIR, "sync-rules.py"))
sync_rules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_rules)


def rules(updated, hosts=("youtube.com",), gateway=False):
    return {"mode": "filter", "apps": [], "hosts": list(hosts), "direct": [], "updated": updated, "gateway": gateway}


class Choose(unittest.TestCase):
    def test_same_rules_need_nothing(self):
        # Время и флаг шлюза не в счёт — только сами правила.
        self.assertIsNone(sync_rules.choose(rules(1), rules(2, gateway=True)))

    def test_newer_wins(self):
        self.assertEqual(sync_rules.choose(rules(2, ["a.com"]), rules(1)), "laptop")
        self.assertEqual(sync_rules.choose(rules(0, ["a.com"]), rules(1)), "green")

    def test_same_time_needs_choice(self):
        with self.assertRaises(ValueError):
            sync_rules.choose(rules(0, ["a.com"]), rules(0))
        self.assertEqual(sync_rules.choose(rules(0, ["a.com"]), rules(0), "green"), "green")


if __name__ == "__main__":
    unittest.main()
