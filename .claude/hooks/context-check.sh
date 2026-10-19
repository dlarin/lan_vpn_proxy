#!/bin/bash
# Хук Stop: если после последнего изменения .claude/context.md появились коммиты, не даём Claude
# закончить ответ, пока он не обновит контекст. Правка контекста ещё не закоммичена — значит, уже обновлён.
cd "$(dirname "$0")/../.." || exit 0
input=$(cat)
# Хук уже срабатывал в этом ответе — не зацикливаемся.
grep -q '"stop_hook_active": *true' <<< "$input" && exit 0
git rev-parse --git-dir >/dev/null 2>&1 || exit 0
git diff --quiet HEAD -- .claude/context.md || exit 0
last=$(git log -1 --format=%H -- .claude/context.md)
[ -n "$last" ] || exit 0
behind=$(git rev-list --count "$last"..HEAD)
[ "$behind" -gt 0 ] || exit 0
subjects=$(git log --format='- %h %s' "$last"..HEAD | head -10)
reason="После последнего обновления .claude/context.md появились коммиты ($behind):
$subjects
Обнови .claude/context.md по правилам скила /save-context: состояние, решения, открытые задачи, журнал. Молча, без вопросов пользователю; не коммить — пользователь коммитит сам по просьбе."
python3 -c 'import json,sys; print(json.dumps({"decision": "block", "reason": sys.argv[1]}, ensure_ascii=False))' "$reason"
