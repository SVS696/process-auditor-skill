# Контракт независимого аудита процесса

## Episode schema 1

Episode фиксирует один terminal или interrupted workflow до появления оценки.

Обязательные поля:

- `episode_id`, `work_item_id`, canonical `project_root` и `project_key`;
- `workflow` и `outcome`;
- `origin`: `historical-biased | prospective-clean | frozen-replay`;
- `author_run_id`;
- непустой `skill_chain` вида `{name, version}`;
- evidence refs `{ref, sha256}`;
- `signals`, `required_depth`, `manual_stop`, `recorded_at`, `fingerprint`.

Outcomes:

- `completed`;
- `blocked`;
- `user_stopped`;
- `guard_stopped`;
- `cancelled`;
- `external_failure`.

`user_stopped` требует `manual_stop.authority=user`, timestamp и
`resume_authority=user_only`. Отсутствующая причина остаётся `unknown`.
Для `user_stopped` допустимы только `MANUAL_STOP_VALIDATED` и
`MANUAL_STOP_UNCONFIRMED`. `KEEP` допустим только для outcome `completed`;
blocked, guard-stopped, cancelled и external-failure эпизоды не могут становиться
KEEP-контрвесом.

`required_depth=deep` обязателен для manual/guard stop и сигналов
`excessive_reviews`, `remediation_limit`, `scope_drift`, `human_rework`,
`quality_regression`. `limit_exhausted` и `external_error` требуют deep только
если причина не изолирована как внешняя.

### Targeted remediation extension

`remediation-episode` добавляет к schema 1 объект `review_scope` с mode
`targeted_remediation`, hash-bound source episode/verdict, source verdict
fingerprint и непустым списком выбранных findings `{index, fingerprint,
target_skill}`. Обязательны `new_findings_policy=backlog_only`,
`max_rechecks=1`, `automatic_followup=false`; outcome только `completed`, signals
пусты, depth только `routine`. Parent, work item, project и workflow совпадают с
source episode. Source remediation-episode не может открыть второй recheck.

## Verdict schema 2

Независимый reviewer создаёт JSON:

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

Для targeted remediation verdict дополнительно содержит ровно один
`remediation_results` на каждый выбранный finding fingerprint. Допустимые status:
`closed | open | unverified`; каждый результат цитирует текущее remediation
evidence. `findings=[]`, `process_pattern_id=null`, `scope_expansion=false` и
`automatic_followup=false` обязательны. Все closed требуют `KEEP/none`, любой
open — ненулевой `EXECUTION_DEFECT`, только unverified — `EVIDENCE_GAP`.
Targeted verdict не создаёт новый finding или policy pattern.

Классификации:

| Classification | Смысл | Допустимое следующее действие |
|---|---|---|
| `KEEP` | Процесс оправдан | `no_change` |
| `EXECUTION_DEFECT` | Ошибка конкретного исполнения | `repair_result`, `investigate`, `no_change` |
| `PROCESS_DEFECT` | Дефект правила или orchestration | `propose_policy_change`, `investigate` |
| `EXTERNAL_FAILURE` | Причина вне workflow | `no_change`, `investigate` |
| `EVIDENCE_GAP` | Нельзя доказать вывод | `investigate` |
| `MANUAL_STOP_VALIDATED` | Пользователь корректно остановил runaway/риск | `propose_policy_change`, `repair_result`, `investigate` |
| `MANUAL_STOP_UNCONFIRMED` | Дефект не доказан, но пауза сохраняется | `no_change`, `investigate` |

Severity: `none | minor | major | blocker`. `KEEP`, `EXTERNAL_FAILURE`,
`EVIDENCE_GAP` и `MANUAL_STOP_UNCONFIRMED` не могут изображать доказанный
`blocker` процесса. `PROCESS_DEFECT` требует `process_pattern_id` и хотя бы один
finding с `target_skill` и evidence SHA-256 из episode.

`findings[].evidence_sha256` ссылается только на уже закреплённые evidence refs.
Текстовый вывод без такой связи не создаёт policy candidate.

## Независимость

Минимальные машинные условия:

- `evaluator.run_id != episode.author_run_id`;
- `independent=true`;
- `context_policy=evidence-only`;
- `evaluator.review_depth` совпадает с `episode.required_depth`;
- reviewer не изменял исходную работу или скиллы;
- episode создан до verdict и fingerprint совпадает.

Внутренний PASS исходного Vigers/Delivery reviewer является evidence, но не
заменяет этот аудит. Аудитор не получает прошлые process verdicts до завершения
собственного вывода; history открывается только стадии aggregation.

## Обучение и promotion

Project-local history хранится в:

```text
<project-root>/.process-auditor/audit-model.json
```

`historical-biased` участвует только в ретроспективе и поиске гипотез. Обычный
shadow candidate требует не меньше трёх `prospective-clean|frozen-replay`
эпизодов с одинаковыми `project_key + process_pattern_id + target_skill`.
Только явно связанные через `parent_episode_id` recovery/follow-up episodes
одного root incident считаются одним наблюдением. Незалинкованные episode IDs —
отдельные prospective runs, даже если относятся к одному work item.

Новые verdict принимаются только в schema 2. Schema 1 разрешена лишь как legacy
запись уже существующей модели: она не участвует в обучении, потому что её
review depth и порядок episode/verdict нельзя подтвердить машинно.

Evidence проверяется при добавлении записи. Позднейшее изменение или удаление
исходного файла отмечается как `evidence_drift_audits`, но не стирает уже
проверенное историческое KEEP или defect-наблюдение. Структурно битые и legacy
записи могут быть перенесены `quarantine-stale`; валидные schema 2 наблюдения из
старого drift-карантина сохраняются как контрвес. Удалять модель ради
продолжения запрещено.

Структурно битая отдельная запись не делает модель недоступной: `recommend`
показывает её в `stale_or_invalid_audits`, а `quarantine-stale` переносит в
карантин. Envelope другой schema/project остаётся hard failure. Concurrent
`update` и `quarantine-stale` сериализуются file lock, чтобы не терять
наблюдения.
Даже malformed record (`null`, строка или неполный object) карантинится как
непрозрачное исходное значение и не исполняется/не агрегируется.

Один `blocker` PROCESS_DEFECT или подтверждённый ручной stop с blocker допускает
`urgent-human-review`, но не автоматическое изменение. Каждый candidate хранит
число `KEEP` в том же workflow: отрицательные наблюдения нельзя выбрасывать.

Promotion всегда требует:

1. решения человека;
2. отдельной реализации изменения;
3. frozen replay на исходных материалах без подсматривания в финал;
4. независимой проверки качества;
5. rollback condition и наблюдения на новых prospective-clean эпизодах.

Удаление обязательного final/block review, снижение assurance и автоматическое
возобновление остановленной работы запрещены.
