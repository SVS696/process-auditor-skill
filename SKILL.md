---
name: process-auditor
description: "Независимо оценивает завершённый, заблокированный или вручную остановленный рабочий прогон нескольких скиллов; отделяет оправданный процесс от ошибки исполнения, дефекта процесса и внешнего сбоя, сохраняет KEEP/no-change и формирует только shadow-кандидаты на улучшение. Применяй после содержательной работы Vigers, Delivery Engineering, Work Metrics и других оркестрационных скиллов, а также после ручного stop. Не применяй к обычному короткому ответу без рабочего прогона."
---

# Process Auditor

Проверяй не результат ещё раз, а соразмерность и сходимость процесса, которым он
был получен. Аудит запускается после каждого содержательного skill-governed
прогона: успешного, заблокированного, прерванного, остановленного защитой или
пользователем. Обычный короткий ответ без workflow и материальной работы не
создаёт аудит.

## Неподвижные правила

1. **Независимость.** Автор и аудитор имеют разные `run_id`; первичный аудитор
   получает свежий evidence-only context и не наследует выводы автора, прошлый
   verdict или предлагаемую правку. В targeted remediation независимый reviewer
   видит только hash-bound source pair, выбранные findings и evidence их фикса.
   В Codex используй отдельного read-only Claude reviewer; в другом harness —
   отдельного reviewer, который не участвовал в прогоне.
2. **Ручной stop — авторитетная пауза.** Сохрани состояние непосредственно перед
   остановкой. Аудитор может подтвердить или не подтвердить дефект, но не может
   возобновить работу: `resume_authority=user_only` и `no_auto_resume=true`.
3. **`KEEP` — полноценное наблюдение.** Отсутствие дефекта записывается, а не
   теряется. Не предлагай изменение только потому, что аудит был запущен.
4. **Разделяй причину.** Один verdict выбирает `KEEP`, `EXECUTION_DEFECT`,
   `PROCESS_DEFECT`, `EXTERNAL_FAILURE`, `EVIDENCE_GAP`,
   `MANUAL_STOP_VALIDATED` или `MANUAL_STOP_UNCONFIRMED`.
5. **Никакого самоприменения.** Аудитор read-only относительно исходной работы и
   скиллов. Он создаёт episode, verdict, project-local history и shadow-candidate;
   изменение скилла требует отдельного решения человека, реализации и replay.
6. **Происхождение важнее красивого финала.** `historical-biased` можно разбирать,
   но нельзя использовать для policy promotion. Обучающие origins — только
   `prospective-clean` и `frozen-replay`.
7. **Evidence-bound.** Каждый источник фиксируется SHA-256. Изменившийся или
   отсутствующий evidence делает запись невалидной. Не превращай отсутствующие
   данные, токены, время, findings или пользовательскую причину в нули.
8. **Таймер не судья.** Время, retries и число review — сигналы для расследования,
   но не доказательство дефекта и не основание снижать assurance или scope.
9. **Remediation не новый аудит.** После defect-verdict создай максимум один
   `remediation-episode`, привязанный к конкретным one-based findings. В verdict
   такого recheck запрещены новые findings, process pattern и scope expansion;
   несвязанные наблюдения не запускают автоматический follow-up. Второй
   remediation-episode от remediation-episode машинно запрещён.

## Рабочий цикл

1. Собери неизменяемый episode командой `episode`. Включи версии всех реально
   использованных скиллов, terminal outcome, сигналы, evidence-файлы и сведения
   о ручной остановке. Для старых многократно исправлявшихся прогонов ставь
   `historical-biased`.
2. Выбери глубину: `routine` для штатного завершения; `deep` для manual/guard
   stop, исчерпания remediation, повторных review, scope drift, human rework,
   quality regression или неразделённого внешнего сбоя. Для последнего передай
   `--depth deep`; обязательную deep-глубину нельзя понизить до routine.
3. Передай независимому reviewer только episode, связанные evidence и текущие
   контракты фактически использованных скиллов. Попроси вернуть draft для verdict
   schema 2
   из [audit-contract.md](references/audit-contract.md), без правок файлов. Для
   внешнего Claude используй готовый evidence-only prompt из
   [reviewer-prompt.md](references/reviewer-prompt.md).
4. Выполни `validate-verdict`, затем `update`. Невалидный или зависимый verdict не
   заменяй собственным мнением — исправь evidence gap либо сохрани
   `EVIDENCE_GAP` независимым проходом.
5. Выполни `recommend`. `baseline_retained` и `no_change` — нормальный результат.
   Shadow-кандидат не меняет скиллы, gates, роли, assurance или остановленную
   работу.
   После проверки при записи изменение исходного evidence отмечается как drift,
   но не стирает историческое KEEP или defect-наблюдение. Структурно битые и
   legacy schema 1 записи не обучают; `quarantine-stale` переносит именно их в
   явный карантин, не удаляя KEEP/verdict.
6. Если Stop-hook дал точную команду `ack-hook --generation N`, выполни её
   последним tool-call
   после валидации записи. Любая последующая материальная работа открывает новый
   аудит.

После исправления конкретных findings не повторяй этот полный цикл. Используй
bounded workflow из [targeted-remediation.md](references/targeted-remediation.md):
один finding-bound recheck и стоп независимо от `closed | open | unverified`.

Команды, схемы и границы promotion описаны в
[audit-contract.md](references/audit-contract.md). Интеграция с Vigers, Delivery,
Work Metrics и hook-событиями — в
[integration-contract.md](references/integration-contract.md).

## Минимальный вызов

```text
python3 {baseDir}/scripts/process_audit.py episode \
  --episode-id "<stable-id>" --work-item-id "<id>" \
  --project-root "<root>" --workflow "<workflow>" \
  --outcome completed --origin prospective-clean \
  --author-run-id "<run-id>" --skill "vigers@<revision>" \
  --evidence-file "<artifact-or-ledger>" --write "<episode.json>"

python3 {baseDir}/scripts/process_audit.py validate-verdict \
  --episode "<episode.json>" --verdict "<verdict.json>"

python3 {baseDir}/scripts/process_audit.py update \
  --episode "<episode.json>" --verdict "<verdict.json>"

python3 {baseDir}/scripts/process_audit.py recommend \
  --project-root "<root>" --write "<shadow.json>"

python3 {baseDir}/scripts/process_audit.py remediation-episode \
  --episode-id "<source-id>-remediation-1" \
  --source-episode "<source-episode.json>" \
  --source-verdict "<source-verdict.json>" \
  --finding-index 1 --author-run-id "<run-id>" \
  --skill "process-auditor@<revision>" \
  --evidence-file "<fix-or-regression-evidence>" \
  --write "<remediation-episode.json>"
```

## Граница результата

- `KEEP` означает: наблюдавшаяся стоимость объясняется реальным риском или
  обязательным quality gate; процесс не менять.
- `EXECUTION_DEFECT` означает: исправлять конкретный результат/исполнение, а не
  универсальное правило по одному случаю.
- `PROCESS_DEFECT` требует `process_pattern_id`, точного target skill и evidence.
  Один `blocker` допускает срочный human review; обычный candidate требует не
  меньше трёх eligible эпизодов одного project-local pattern.
- `EXTERNAL_FAILURE` не превращай в обвинение процесса, пока не доказано, что
  retry/fallback policy сама создала ущерб.
- `EVIDENCE_GAP` не является ни PASS, ни FAIL.

Перед завершением запусти:

```text
python3 {baseDir}/scripts/test_process_audit.py
python3 {baseDir}/scripts/verify_installation.py
python3 ~/.codex/skills/.system/skill-creator/scripts/quick_validate.py {baseDir}
```
