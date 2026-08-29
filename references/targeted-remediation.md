# Targeted remediation

Используй этот режим только после валидного defect-verdict, когда пользователь
разрешил исправить конкретные findings. Это recheck исправления, а не новый
поиск дефектов.

## Машинные границы

- `remediation-episode` принимает валидную source episode+verdict пару и
  one-based `--finding-index` для каждого исправляемого finding.
- Source episode и verdict автоматически входят в `evidence_refs` с SHA-256.
  Их schema/fingerprint проверяются без повторного read-back старых mutable
  evidence-файлов: исправление закономерно меняет их. Закрытие доказывается
  только текущим remediation evidence.
- `review_scope.mode=targeted_remediation` хранит fingerprint каждого выбранного
  finding, `new_findings_policy=backlog_only`, `max_rechecks=1` и
  `automatic_followup=false`.
- Outcome фиксирован как `completed`, сигналы пусты, recheck имеет routine depth:
  глубина исходного аудита не расширяет breadth targeted проверки.
- Source episode с `review_scope` нельзя использовать для следующего
  remediation-episode. Любой дальнейший цикл требует нового явного решения
  пользователя, а не автоматического продолжения.
- Targeted verdict обязан иметь `findings=[]`, `process_pattern_id=null`,
  `scope_expansion=false`, `automatic_followup=false` и ровно один
  `remediation_results` на каждый выбранный fingerprint.
- Статусы результатов: `closed`, `open`, `unverified`. Все `closed` требуют
  `KEEP/none`; любой `open` требует `EXECUTION_DEFECT` с ненулевой severity;
  только `unverified` требует `EVIDENCE_GAP`.
- Targeted episodes сохраняются в history, но исключаются из training cohort и
  не создают policy candidate.

## Reviewer input

Передай независимому reviewer только:

1. remediation episode;
2. hash-bound source episode и verdict из `review_scope`;
3. выбранные source findings;
4. текущий diff/файлы фикса и regression evidence;
5. этот контракт и verdict schema.

Не проси ревьюить остальную поверхность. Reviewer не возвращает unrelated
findings и не предлагает новый audit round. Если случайно замечено что-то вне
scope, это не влияет на targeted verdict и может быть вынесено человеку отдельно
без автоматического действия.

Draft targeted verdict включает обычные evaluator/classification/severity/
summary/actions поля и:

```json
{
  "findings": [],
  "process_pattern_id": null,
  "remediation_results": [
    {
      "finding_fingerprint": "<sha256 из review_scope>",
      "status": "closed",
      "summary": "Что именно перепроверено",
      "evidence_sha256": ["<current remediation evidence hash>"]
    }
  ]
}
```

`seal-verdict` детерминированно добавит `scope_expansion=false` и
`automatic_followup=false`.
