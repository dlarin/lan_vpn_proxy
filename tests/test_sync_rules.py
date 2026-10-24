"""Тесты sync-rules.py: чьи правила взять. Запуск: /usr/bin/python3 -m unittest discover tests"""
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

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


class Main(unittest.TestCase):
    """main() целиком: ssh и web.py подменены «машинами» — словарями с правилами."""

    def run_main(self, laptop, green, *args):
        machines = {"laptop": laptop, "green": green}
        calls = []

        def run(cmd, input=None, **kwargs):
            who = "green" if cmd[0] == "ssh" else "laptop"
            action = cmd[-1]
            calls.append((who, action))
            if action == "true":  # проверка, что сервер доступен
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if action.endswith("rules"):
                return subprocess.CompletedProcess(cmd, 0, json.dumps(machines[who]), "")
            body = json.loads(input)  # rules-set: как save_rules — время из тела или текущее
            machines[who] = {**{k: body[k] for k in sync_rules.RULE_KEYS}, "updated": body["updated"] or 999}
            return subprocess.CompletedProcess(cmd, 0, "Сохранено.", "")

        with mock.patch.object(sync_rules.subprocess, "run", run), \
                mock.patch.object(sys, "argv", ["sync-rules.py", *args]), mock.patch("builtins.print") as out:
            try:
                sync_rules.main()
                code = 0
            except SystemExit as e:
                code = e.code
        return machines, calls, code, " ".join(str(c.args[0]) for c in out.call_args_list)

    def test_newer_goes_to_other_side_with_its_time(self):
        machines, calls, code, out = self.run_main(rules(100), rules(200, ["new.com"]))
        self.assertEqual(code, 0)
        self.assertEqual(("laptop", "rules-set"), calls[-1])
        self.assertEqual(machines["laptop"]["hosts"], ["new.com"])
        self.assertEqual(machines["laptop"]["updated"], 200)  # время перенесено как есть
        self.assertIn("green → ноутбук", out)
        # Следующий запуск видит, что всё совпадает, и ничего не применяет.
        _, calls, _, out = self.run_main(machines["laptop"], machines["green"])
        self.assertNotIn("rules-set", [action for _, action in calls])
        self.assertIn("совпадают", out)

    def test_server_unreachable_is_not_an_error(self):
        with mock.patch.object(sync_rules.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 255, "", "")), \
                mock.patch.object(sys, "argv", ["sync-rules.py"]), mock.patch("builtins.print") as out:
            sync_rules.main()
        self.assertIn("недоступен", out.call_args.args[0])

    def test_same_time_without_from_fails(self):
        machines, calls, code, _ = self.run_main(rules(0, ["a.com"]), rules(0))
        self.assertNotEqual(code, 0)
        self.assertNotIn("rules-set", [action for _, action in calls])
        machines, _, code, _ = self.run_main(rules(0, ["a.com"]), rules(0), "--from", "laptop")
        self.assertEqual((code, machines["green"]["hosts"]), (0, ["a.com"]))


if __name__ == "__main__":
    unittest.main()
