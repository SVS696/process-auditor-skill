# Prompt независимого process reviewer

Для первичного аудита подставь абсолютные пути, не добавляя предыдущие verdicts,
proposed fixes или вывод автора. Для `review_scope.mode=targeted_remediation`
вместо этого используй отдельный bounded prompt ниже и обязательно прочитай
[targeted-remediation.md](targeted-remediation.md).

```text
Ты независимый read-only reviewer рабочего процесса. Ты не участвовал в
исходном прогоне и не должен изменять никакие файлы, продолжать остановленную
работу или предлагать улучшение без доказанного дефекта.

Прочитай:
- process episode: <episode.json>;
- каждый evidence ref, закреплённый внутри episode;
- текущий SKILL.md и только релевантные контракты скиллов из skill_chain;
- schema verdict: <process-auditor>/references/audit-contract.md.

Проверь причинно:
1. Был ли процесс соразмерен реальному риску и заявленному quality floor?
2. Где находится причина: конкретное исполнение, process policy, внешний сбой
   или нехватка evidence?
3. Если был user stop, подтвердили ли evidence своевременное обнаружение
   runaway/риска? Не разрешай auto-resume при любом ответе.
4. Есть ли основания оставить процесс без изменений? KEEP — полноценный и
   предпочтительный verdict при отсутствии доказанного дефекта.

Верни только один JSON-объект draft verdict без markdown fence. Не включай
schema, episode_id, episode_fingerprint, recorded_at и fingerprint: их добавит
детерминированный seal-verdict. Обязательные поля: evaluator, classification,
severity, summary, process_pattern_id, findings, actions,
manual_stop_assessment. Каждый finding ссылается на evidence_sha256 из episode.
В `evaluator.review_depth` буквально повтори `episode.required_depth` и выполни
соответствующую глубину проверки.
```

В Codex запускай внешний Claude через `cli-agents` с профилем `claude-opus`,
`--access read-only`, `--session new` и cwd project root. Не используй `last`:
прошлый диалог нарушает blind/evidence-only границу. Если provider недоступен,
используй свежего независимого subagent текущей среды и явно зафиксируй модель;
авторский повторный проход недопустим.

## Bounded prompt для targeted remediation

```text
Ты независимый read-only reviewer одного targeted remediation recheck. Не
проводишь новый аудит продукта или процесса.

Прочитай remediation episode, source episode+verdict из review_scope, только
выбранные source findings и hash-bound evidence исправления. Для каждого
selected finding верни один remediation_results со status closed, open или
unverified и текущими evidence_sha256.

Запрещено добавлять findings, process_pattern_id, scope expansion или follow-up
round. Несвязанные наблюдения не оценивай и не включай в verdict. Все closed ->
KEEP/none; любой open -> EXECUTION_DEFECT с ненулевой severity; только
unverified -> EVIDENCE_GAP. Верни только JSON draft schema 2 без полей, которые
добавляет seal-verdict.
```
