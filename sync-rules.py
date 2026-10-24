#!/usr/bin/env python3
"""Синхронизация правил (вкладка «Правила»: режим, VPN_APPS, VPN_HOSTS, DIRECT_HOSTS) между ноутбуком и green.

    ./sync-rules.py [--from laptop|green] [пользователь@сервер]

Запускается на ноутбуке. Правила, сохранённые позже (RULES_UPDATED в .env, его пишет web.py), переносятся
на другую сторону через `web.py rules-set` — тот же путь, что у кнопки «Сохранить и применить»: проверка
конфига Xray и перезапуск контейнера, если VPN включён. Время переносится как есть, поэтому следующий
запуск видит, что правила совпадают. Сервер недоступен (ноутбук не дома) — выходит без ошибки.
--from — когда время одинаковое и не понять, чьи новее (например, первый запуск).
"""
import argparse
import json
import os
import subprocess
import sys

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR = "lan_vpn_proxy"
RULE_KEYS = ("mode", "apps", "hosts", "direct")


def ssh(host, *cmd):
    # BatchMode: без вопросов о пароле; ключ хоста проверяется — в чужой сети с тем же адресом не подключимся.
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, *cmd]


def get_rules(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True)
    return json.loads(result.stdout)


def same(a, b):
    return all(a.get(k) == b.get(k) for k in RULE_KEYS)


def choose(local, remote, force=None):
    """'laptop', 'green' — чьи правила взять, None — уже совпадают; ValueError — не понять, чьи новее."""
    if same(local, remote):
        return None
    if force:
        return force
    if local.get("updated", 0) == remote.get("updated", 0):
        raise ValueError("правила различаются, а время изменения одинаковое — укажите --from laptop или --from green")
    return "laptop" if local.get("updated", 0) > remote.get("updated", 0) else "green"


def main():
    parser = argparse.ArgumentParser(description="Синхронизация правил между ноутбуком и green")
    parser.add_argument("host", nargs="?", default="dima@192.168.0.2")
    parser.add_argument("--from", dest="source", choices=("laptop", "green"))
    args = parser.parse_args()

    if subprocess.run(ssh(args.host, "true"), capture_output=True).returncode != 0:
        print(f"сервер {args.host} недоступен — пропускаю")
        return
    local_cmd = [sys.executable, os.path.join(PROJECT_DIR, "web.py")]
    remote_cmd = ssh(args.host, f"cd {REMOTE_DIR} && python3 web.py")
    local, remote = get_rules([*local_cmd, "rules"]), get_rules([*remote_cmd, "rules"])
    try:
        source = choose(local, remote, args.source)
    except ValueError as e:
        sys.exit(str(e))
    if source is None:
        print("правила совпадают")
        return
    rules, target_cmd = (local, remote_cmd) if source == "laptop" else (remote, local_cmd)
    body = {k: rules[k] for k in RULE_KEYS}
    body["updated"] = rules.get("updated") or None  # без времени web.py поставит текущее
    result = subprocess.run([*target_cmd, "rules-set"], input=json.dumps(body), capture_output=True, text=True,
                            timeout=120)
    target = "green" if source == "laptop" else "ноутбук"
    print(f"{source} → {target}: {(result.stdout + result.stderr).strip()}")
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
