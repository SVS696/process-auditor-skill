# Интеграция Process Auditor

## Граница с другими скиллами

Process Auditor не импортирует их внутренний Python и не меняет их state machine.
Интеграция строится через hash-bound файлы:

- Vigers: `mode-decision.json`, `manifest.json`, `ledger.json`,
  `agent-ledger.json`, `automation-timing.json`, final validation receipt и
  опциональный `policy-shadow.json`;
- Delivery Engineering: requirements handoff, implementation manifest,
  agent-ledger, verification receipts и terminal outcome;
- Work Metrics: `activity-reconciliation.json`, yield summary и coverage state;
- harness: bounded transcript/session evidence, interruption/limit markers и
  пользовательский stop reason, если он был явно дан.

Отсутствующий companion не блокирует episode: coverage фиксируется как сигнал
или evidence gap. Нельзя подменять отсутствующий ledger нулевыми затратами.

## Точки запуска

Запускай аудит при первом terminal исходе workflow и создавай новый episode для
последующего recovery/follow-up. Один episode не должен поглощать ожидание между
циклами.

Обязательные триггеры:

- terminal success;
- blocked/cancelled/external failure;
- user stop;
- guard stop;
- remediation/convergence limit;
- повторный запуск после остановки — как новый связанный episode.

Routine audit остаётся одним ограниченным независимым проходом. Deep audit
разбирает причинную цепочку, но не открывает новые исправительные роли внутри
исходного workflow.

## Stop-hook

`scripts/process_audit_hook.py` — только fail-closed напоминание и state ledger.
Он не вызывает модель, не читает секреты, не правит проекты и не принимает
решение за reviewer.

Hook помечает материальный turn по локальным/внешним write-tools и запуску
субагентов. Простое чтение контракта, lint или test-run не являются мутацией сами
по себе. На первом Stop без
валидного audit receipt он возвращает `decision=block` и точную команду
`ack-hook`. `stop_hook_active=true` пропускается, чтобы не создать бесконечный
цикл.

State хранится в durable user-local каталоге и ключуется session identity, а не
cwd. Потеря/порча state на Stop трактуется fail-closed как evidence gap.
Проверяется не только JSON/schema, но и типы/границы generation-счётчиков,
stop-флагов и interruption status; `audited_generation` выше material generation
также считается порчей. Hook read и `ack-hook` используют один общий полный
валидатор state: повреждённый state нельзя закрыть даже валидной episode+verdict
парой.

Если пользователь прервал работу до первого Stop, следующий prompt помечает
`user_stopped`. Если незакрытый turn уже проходил Stop-gate или
`stop_hook_active` bypass, причина считается `audit_unclosed`, а не ручной
остановкой: hook не фабрикует волю пользователя. Никакой hook не имеет права
автоматически продолжить исходную работу.

`ack-hook --generation N` разрешён только для пары episode+verdict, прошедшей полную
валидацию и evidence read-back; episode обязан совпадать с session identity и
session cwd закрываемого state. Ack берёт тот же file lock и отклоняется, если
текущее `material_generation` уже не равно `N`. Для state с
`interruption_status=user_stopped` ack принимает только episode с outcome
`user_stopped`, а `manual_stop.at` обязан точно совпасть с
`manual_stop_observed_at` из state; episode `user_stopped` также запрещён без
соответствующего state. Выполняй ack последним tool-call:
последующая материальная мутация снова открывает gate.

Команды самого `process_audit.py` не создают рекурсивное material generation.
Для запуска внешнего reviewer через `cli_caller.py` используй префикс
`PROCESS_AUDITOR_META=1`; исключение действует только для этого audit-plumbing
скрипта по его canonical path `~/.agents/skills/cli-agents/cli_caller.py`, только
как точный leading environment assignment и только при явном
`--access read-only`. Отсутствующий, `workspace-write` или `inherit` access,
meta-строка внутри prompt, другой файл с basename `cli_caller.py` и иная
неканоническая форма считаются material.
Любая реальная мутация в той же shell-цепочке всё равно открывает gate.
Read-only исключения интерпретаторов применяются к одному shell-сегменту, а не
ко всей строке: тест или audit-plumbing справа от `&&` не может скрыть mutation
слева.

Для `exec_command` действует fail-closed classifier: material считается любой
командой, кроме узкого allowlist диагностик, read-only git/find/sed, test/lint и
audit-plumbing. Shell newline равен `;`; абсолютный путь к интерпретатору и
неизвестные `make/bash/curl` сценарии не получают неявного read-only статуса.
Write redirection разбирается shell-tokenizer, поэтому формы с пробелами и без
них эквивалентны, а quoted `>` не считается редиректом.
Опции, которые пишут файл без shell-redirection, также material: как минимум
`sort -o/--output` (включая кластеризованную short-option форму),
`git diff/show --output`, второй positional output у
`python -m json.tool` и `find -fprint/-fprintf/-fls`.

Shell-capable surface фиксируется exact harness operations:
Codex `exec_command`/`write_stdin` и Claude `Bash`/`Shell`. Только явно переданный
`chars=""` poll `write_stdin` read-only только при точной input-схеме poll без
посторонних полей; missing, nested, expression, dynamic, non-string, непустой
`chars` или дополнительный payload material. Nested wrapper разбирается balanced
parser, поэтому `)` внутри строки не обрывает call. Любая ссылка на `tools` в
не-командном строковом поле wrapper event, не соответствующая полностью
распознанному direct `tools.<operation>(...)`, material: имя поля не даёт
exemption, bracket access, alias, destructuring и Reflect/dynamic operation тоже.
Interpreter исключения позиционные и только для Python (`python -m
<known-read-only-module>` или реально исполняемый `test_*.py`); второй output у
`json.tool`, `node/ruby/osascript test_*`, `ruff format` и `ruff --fix*` material.
Командная или
process substitution (`$()`, backticks, `<()`, `>()`) fail-closed material.
Смешанный wrapper считается material, если хотя бы один `cmd:` literal не удалось
полностью разобрать; распознанный read-only sibling не снимает это решение.

Для остальных tool events read-only разрешён только точному allowlist реально
проверенных harness-операций. Неизвестный прямой или nested tool material по
умолчанию; суффикс вроде `remote_shell`, `runbash` или префикс `find_` сам по себе
не даёт exemption. Поэтому новый MCP/plugin не получает write exemption только
из-за похожего имени.

В `functions.exec` escaped identifier, bracket/alias/Reflect/globalThis,
динамически собранное имя операции и иной неразобранный dispatch material по
умолчанию. Для shell allowlist проверяются не только executable, но и
write-capable subcommands/options: как минимум `ruff clean`, `rg --pre` /
`--pre-glob`, sed `w`/`e`, `-f` и in-place формы material.

После defect-verdict полный audit workflow не повторяется. Команда
`remediation-episode` создаёт единственный hash-bound targeted recheck выбранных
source findings; новый finding, scope expansion, policy pattern, второй recheck
и automatic follow-up отклоняются схемой. Targeted observation не участвует в
training cohort.

## Граница policy-learning Vigers

Vigers `policy-learning` остаётся локальной telemetry конкретной постановочной
машины. Он не является process reviewer. Его episode может стать одним evidence
ref Process Auditor, а policy candidate Vigers не должен продвигаться без
независимого process verdict и допустимого origin.
Для promotion дополнительно обязателен process outcome `completed`; manual stop,
blocked/cancelled и external failure не являются evidence безопасности ablation,
даже если повреждённый внешний producer прислал classification `KEEP`.

Process Auditor, в свою очередь, не меняет Vigers policy model. Связь
однонаправленная до отдельного human-approved promotion workflow.

Установку обоих harness и discovery links подтверждает санитизированный read-back:

```text
python3 {baseDir}/scripts/verify_installation.py --write <receipt.json>
```

Receipt не копирует permissions, токены или остальную пользовательскую
конфигурацию.
