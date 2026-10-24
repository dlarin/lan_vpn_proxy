"""shellcheck для bash-скриптов проекта — в Docker, на компьютер ничего не ставится.

Запуск: /usr/bin/python3 -m unittest discover tests; без Docker тест пропускается, пропустить явно — SHELLCHECK=0.
"""
import glob
import os
import shutil
import subprocess
import unittest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "koalaman/shellcheck:v0.11.0"


class ShellCheck(unittest.TestCase):
    @unittest.skipIf(os.environ.get("SHELLCHECK") == "0" or not shutil.which("docker"), "нет Docker или SHELLCHECK=0")
    def test_scripts(self):
        scripts = sorted(os.path.relpath(p, PROJECT_DIR) for p in glob.glob(os.path.join(PROJECT_DIR, "*.sh")))
        self.assertTrue(scripts)
        result = subprocess.run(["docker", "run", "--rm", "-v", f"{PROJECT_DIR}:/mnt:ro", "-w", "/mnt", IMAGE, *scripts],
                                capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
