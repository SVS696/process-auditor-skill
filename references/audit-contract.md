# Контракт независимого аудита процесса

## Эпизод. Схема 1

Эпизод фиксирует состояние одного завершённого или прерванного прогона. Создай его до оценки процесса.

| Что записать | Поля и значения |
|---|---|
| Прогон и проект | `episode_id`, `work_item_id`, канонический путь `project_root`, ключ `project_key` |
| Процесс и исход | `workflow`, `outcome` |
| Происхождение | `origin` со значением `historical-biased`, `prospective-clean` или `frozen-replay` |
| Автор и скиллы | `author_run_id`, непустой `skill_chain` с элементами `{name, version}` |
| Источники | `evidence_refs` с элементами `{ref, sha256}` |
| Условия проверки | `signals`, `required_depth`, `manual_stop` |
| Время и контрольная сумма | `recorded_at`, `fingerprint` |

Возможные значения `outcome`: `completed`, `blocked`, `user_stopped`, `guard_stopped`, `cancelled`, `external_failure`.

При `user_stopped` укажи `manual_stop.authority=user`, время остановки и `resume_authority=user_only`. Если пользователь не назвал причину, сохрани `unknown`. Для этого исхода возможны только `MANUAL_STOP_VALIDATED` и `MANUAL_STOP_UNCONFIRMED`. Классификация `KEEP` допустима только для `completed`.

При остановке пользователем или защитой требуется `required_depth=deep`. Ту же глубину требуют сигналы `excessive_reviews`, `remediation_limit`, `scope_drift`, `human_rework` и `quality_regression`. При `limit_exhausted` или `external_error` укажи `--depth deep`, если внешняя причина ещё не отделена от причин внутри процесса.

### Эпизод исправления

Команда `remediation-episode` добавляет в схему 1 объект `review_scope`. В нём указывают режим `targeted_remediation`, исходный эпизод и заключение с их хешами, отпечаток исходного заключения и непустой список выбранных замечаний `{index, fingerprint, target_skill}`.

Сохрани связь с исходным эпизодом и его идентификаторы задачи, проекта и процесса. Укажи `new_findings_policy=backlog_only`, `max_rechecks=1`, `automatic_followup=false`. В эпизоде исправления `outcome=completed`, список сигналов пуст, глубина `routine`. Из этого эпизода нельзя открыть ещё одну проверку исправлений.

## Заключение. Схема 2

Независимый аудитор готовит заключение. Пример полей после выполнения `seal-verdict`:

```json
{
  "schema": 2,
  "episode_id": "episode-id",
  "episode_fingerprint": "sha256",
  "evaluator": {
    "run_id": "different-run-id",
    "model": "model-id",
    "independent": true,
    "context_policy": "evidence-only",
    "review_depth": "routine"
  },
  "classification": "KEEP",
  "severity": "none",
  "summary": "Краткий доказательный вывод",
  "process_pattern_id": null,
  "findings": [],
  "actions": [
    {
      "kind": "no_change",
      "target_skill": null,
      "description": "Текущий процесс соразмерен доказанному риску"
    }
  ],
  "manual_stop_assessment": "not_applicable",
  "no_auto_resume": true,
  "auto_apply": false,
  "recorded_at": "ISO-8601",
  "fingerprint": "sha256"
}
```

При проверке исправлений добавь в `remediation_results` по одному результату для каждого выбранного отпечатка. Сохрани их порядок. В каждом результате укажи статус `closed`, `open` или `unverified` и хеш текущего подтверждения. Укажи `findings=[]`, `process_pattern_id=null`, `scope_expansion=false`, `automatic_followup=false`. Если все статусы `closed`, укажи `KEEP` и `severity=none`. Если есть хотя бы один `open`, укажи `EXECUTION_DEFECT` и ненулевую существенность. Если открытых замечаний нет, но есть `unverified`, укажи `EVIDENCE_GAP`.

| Классификация | Что подтверждают источники | Допустимое действие |
|---|---|---|
| `KEEP` | Ход работы оправдан | `no_change` |
| `EXECUTION_DEFECT` | Ошибка в конкретном исполнении | `repair_result`, `investigate`, `no_change` |
| `PROCESS_DEFECT` | Дефект правила или порядка выполнения работ | `propose_policy_change`, `investigate` |
| `EXTERNAL_FAILURE` | Установлена внешняя причина сбоя | `no_change`, `investigate` |
| `EVIDENCE_GAP` | Для вывода не хватает сведений | `investigate` |
| `MANUAL_STOP_VALIDATED` | На момент решения пользователя существовал подтверждённый риск или процесс вышел из-под контроля | `propose_policy_change`, `repair_result`, `investigate` |
| `MANUAL_STOP_UNCONFIRMED` | Пользователь остановил работу. Источники не подтверждают дефект. Пауза сохраняется | `no_change`, `investigate` |

Допустимые значения `severity`: `none`, `minor`, `major`, `blocker`. Для `KEEP` требуется `none`. Классификации `EXTERNAL_FAILURE`, `EVIDENCE_GAP` и `MANUAL_STOP_UNCONFIRMED` исключают `blocker`. Для `PROCESS_DEFECT` укажи `process_pattern_id` и хотя бы одно замечание. В каждом таком замечании укажи `target_skill` и `evidence_sha256` из эпизода. Для всех классификаций допустимы только хеши источников, закреплённых в этом эпизоде. Вывод без источника не обосновывает предложение по изменению правила.

## Независимость проверки

1. Создай эпизод до заключения. Сверь его отпечаток с `episode_fingerprint` в заключении.
2. Для аудитора требуется `evaluator.run_id != episode.author_run_id`, `independent=true` и `context_policy=evidence-only`. Аудитор не редактирует исходную работу и скиллы.
3. Сверь `evaluator.review_depth` с `episode.required_depth`. Значения должны совпадать.
4. Внутренний `PASS` от Vigers или Delivery учитывается как один источник. Аудитор сам формулирует вывод, прежде чем увидит историю заключений. Историю используют на этапе объединения наблюдений.

## История проекта и изменение правил

Команда `update` хранит историю по пути:

```text
<project-root>/.process-auditor/audit-model.json
```

Для нового заключения требуется схема 2. Старое заключение схемы 1 допустимо только в уже существующей истории. Его глубину и порядок создания записей нельзя подтвердить машинно. Такая запись не участвует в отборе предложений.

Команда сверяет источники при добавлении наблюдения. Если позднее файл изменился или исчез, команда `recommend` отмечает запись в `evidence_drift_audits`. Ранее проверенные `KEEP` и замечания сохраняются. Если повреждена отдельная запись, `recommend` выводит её в `stale_or_invalid_audits` и продолжает работу. Команда `quarantine-stale` переносит старые и структурно ошибочные записи в карантин. Она сохраняет исходное значение, включая `null`, строку или неполный объект, без выполнения и учёта в расчёте. Валидные наблюдения схемы 2 из прежнего карантина расхождений сохраняют вес при оценке. Если сама модель принадлежит другому проекту или использует другую схему, операция завершается ошибкой. Не удаляй модель, чтобы продолжить работу. Одновременные `update` и `quarantine-stale` используют файловую блокировку.

Записи `historical-biased` используй для ретроспективы или поиска гипотез. Для обычного предложения по изменению правила нужны не менее трёх допустимых эпизодов с `origin` равным `prospective-clean` или `frozen-replay` и с одинаковыми `project_key + process_pattern_id + target_skill`. Связанные через `parent_episode_id` восстановления и продолжения одного исходного инцидента считай одним наблюдением. Без этой связи разные идентификаторы эпизодов обозначают отдельные прогоны, даже у одной задачи. Эпизоды проверки исправлений сохраняются в истории и не участвуют в отборе.

Один `PROCESS_DEFECT` уровня `blocker` или подтверждённая ручная остановка с таким уровнем допускает `urgent-human-review`. Для каждого предложения сохраняй также число `KEEP` в том же процессе. Предложение остаётся предварительным.

Чтобы изменить правило процесса:

1. Получи решение человека.
2. Отдельно реализуй изменение.
3. Проверь его на зафиксированных исходных материалах (`frozen-replay`). Не подсказывай проверяющему финал прогона.
4. Получи независимую проверку качества.
5. Укажи условие отката и наблюдай результат в новых эпизодах `prospective-clean`.

Сохрани обязательные проверки блоков и итогового результата, а также требуемый уровень гарантий. Возобновить остановленную работу вправе только пользователь.
