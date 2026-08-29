from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import process_audit
import process_audit_hook
import verify_installation


class ProcessAuditTests(unittest.TestCase):
    def make_evidence(self, root: Path, name: str = "evidence.json") -> Path:
        path = root / name
        path.write_text('{"status":"observed"}\n', encoding="utf-8")
        return path

    def make_episode(
        self,
        root: Path,
        episode_id: str,
        *,
        outcome: str = "completed",
        origin: str = "prospective-clean",
        author_run_id: str | None = None,
        parent_episode_id: str | None = None,
        work_item_id: str | None = None,
        depth: str | None = None,
    ) -> dict[str, object]:
        kwargs: dict[str, object] = {}
        if outcome == "user_stopped":
            kwargs.update(
                manual_stop_at="2026-08-29T10:15:00+03:00",
                manual_stop_reason="review loop continued after the stop criterion",
            )
        return process_audit.build_episode(
            episode_id=episode_id,
            work_item_id=work_item_id or f"work-{episode_id}",
            parent_episode_id=parent_episode_id,
            project_root=str(root),
            workflow="vigers-delivery",
            outcome=outcome,
            origin=origin,
            author_run_id=author_run_id or f"author-{episode_id}",
            skills=["vigers@af46f28", "delivery-engineering@2b4ee00"],
            evidence_paths=[self.make_evidence(root, f"{episode_id}.json")],
            signals=[],
            started_at="2026-08-29T10:00:00+03:00",
            ended_at="2026-08-29T10:20:00+03:00",
            **kwargs,
            depth=depth,
        )

    def verdict(
        self,
        episode: dict[str, object],
        *,
        classification: str = "KEEP",
        severity: str = "none",
        pattern: str | None = None,
    ) -> dict[str, object]:
        evidence_hash = episode["evidence_refs"][0]["sha256"]  # type: ignore[index]
        finding = {
            "target_skill": "vigers",
            "description": "Remediation budget reopened without new user evidence",
            "evidence_sha256": [evidence_hash],
        }
        if classification == "KEEP":
            actions = [
                {
                    "kind": "no_change",
                    "target_skill": None,
                    "description": "Process cost is proportionate to the observed risk",
                }
            ]
            findings: list[dict[str, object]] = []
        elif classification == "PROCESS_DEFECT":
            actions = [
                {
                    "kind": "propose_policy_change",
                    "target_skill": "vigers",
                    "description": "Bound epoch reset by explicit user evidence",
                }
            ]
            findings = [finding]
        elif classification == "EXECUTION_DEFECT":
            actions = [
                {
                    "kind": "repair_result",
                    "target_skill": "vigers",
                    "description": "Repair the evidence-bound execution defect",
                }
            ]
            findings = [finding]
        elif classification == "MANUAL_STOP_VALIDATED":
            actions = [
                {
                    "kind": "propose_policy_change",
                    "target_skill": "vigers",
                    "description": "Prevent another unapproved review epoch",
                }
            ]
            findings = [finding]
        elif classification == "EXTERNAL_FAILURE":
            actions = [
                {
                    "kind": "no_change",
                    "target_skill": None,
                    "description": "Keep workflow policy unchanged",
                }
            ]
            findings = []
        else:
            raise AssertionError(classification)
        assessment = "not_applicable"
        if classification == "MANUAL_STOP_VALIDATED":
            assessment = "validated"
        draft = {
            "evaluator": {
                "run_id": f"review-{episode['episode_id']}",
                "model": "independent-test-model",
                "independent": True,
                "context_policy": "evidence-only",
                "review_depth": episode["required_depth"],
            },
            "classification": classification,
            "severity": severity,
            "summary": "Evidence-bound independent conclusion",
            "process_pattern_id": pattern,
            "findings": findings,
            "actions": actions,
            "manual_stop_assessment": assessment,
        }
        return process_audit.seal_verdict(episode, draft)

    def test_user_stop_is_deep_and_cannot_auto_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = self.make_episode(root, "stopped-1", outcome="user_stopped")
            self.assertEqual("deep", episode["required_depth"])
            self.assertEqual("user_only", episode["manual_stop"]["resume_authority"])
            verdict = self.verdict(
                episode,
                classification="MANUAL_STOP_VALIDATED",
                severity="major",
                pattern="unbounded-review-epoch",
            )
            self.assertTrue(verdict["no_auto_resume"])
            self.assertFalse(verdict["auto_apply"])

    def test_targeted_remediation_is_finding_bound_and_cannot_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_episode = self.make_episode(root, "target-source", depth="deep")
            source_verdict = self.verdict(
                source_episode,
                classification="EXECUTION_DEFECT",
                severity="major",
            )
            source_episode_path = root / "source-episode.json"
            source_verdict_path = root / "source-verdict.json"
            process_audit.atomic_json(source_episode_path, source_episode)
            process_audit.atomic_json(source_verdict_path, source_verdict)
            model = process_audit.empty_model(str(root))
            process_audit.update_model(model, source_episode, source_verdict)
            Path(source_episode["evidence_refs"][0]["ref"]).write_text(
                '{"status":"changed-by-remediation"}\n', encoding="utf-8"
            )
            remediation_evidence = self.make_evidence(root, "remediation-check.json")

            episode = process_audit.build_remediation_episode(
                episode_id="target-recheck",
                source_episode_path=source_episode_path,
                source_verdict_path=source_verdict_path,
                finding_indices=[1],
                author_run_id="target-remediation-author",
                skills=["process-auditor@targeted-remediation"],
                evidence_paths=[remediation_evidence],
            )
            scope = episode["review_scope"]
            selected = scope["selected_findings"]
            self.assertEqual("targeted_remediation", scope["mode"])
            self.assertEqual("backlog_only", scope["new_findings_policy"])
            self.assertEqual(1, scope["max_rechecks"])
            self.assertFalse(scope["automatic_followup"])
            self.assertEqual("routine", episode["required_depth"])
            self.assertEqual([], episode["signals"])
            self.assertEqual(
                process_audit.finding_fingerprint(source_verdict["findings"][0]),
                selected[0]["fingerprint"],
            )
            evidence_hash = next(
                item["sha256"]
                for item in episode["evidence_refs"]
                if item["ref"] == str(remediation_evidence.resolve())
            )
            draft = {
                "evaluator": {
                    "run_id": "targeted-reviewer",
                    "model": "independent-test-model",
                    "independent": True,
                    "context_policy": "evidence-only",
                    "review_depth": "routine",
                },
                "classification": "KEEP",
                "severity": "none",
                "summary": "Only the selected source finding was rechecked and closed",
                "process_pattern_id": None,
                "findings": [],
                "actions": [
                    {
                        "kind": "no_change",
                        "target_skill": None,
                        "description": "Close the bounded remediation without follow-up",
                    }
                ],
                "manual_stop_assessment": "not_applicable",
                "remediation_results": [
                    {
                        "finding_fingerprint": selected[0]["fingerprint"],
                        "status": "closed",
                        "summary": "The regression evidence closes the selected defect",
                        "evidence_sha256": [evidence_hash],
                    }
                ],
            }
            verdict = process_audit.seal_verdict(episode, draft)
            self.assertFalse(verdict["scope_expansion"])
            self.assertFalse(verdict["automatic_followup"])

            expanded = json.loads(json.dumps(draft))
            expanded["findings"] = source_verdict["findings"]
            with self.assertRaisesRegex(
                process_audit.AuditError, "cannot introduce findings"
            ):
                process_audit.seal_verdict(episode, expanded)

            wrong_status = json.loads(json.dumps(draft))
            wrong_status["remediation_results"][0]["status"] = "open"
            with self.assertRaisesRegex(
                process_audit.AuditError, "open remediation results"
            ):
                process_audit.seal_verdict(episode, wrong_status)

            process_audit.update_model(model, episode, verdict)
            recommendation = process_audit.build_recommendation(model)
            self.assertEqual(["target-recheck"], recommendation["targeted_remediation_excluded"])

            episode_path = root / "target-episode.json"
            verdict_path = root / "target-verdict.json"
            process_audit.atomic_json(episode_path, episode)
            process_audit.atomic_json(verdict_path, verdict)
            with self.assertRaisesRegex(
                process_audit.AuditError, "cannot open another remediation recheck"
            ):
                process_audit.build_remediation_episode(
                    episode_id="forbidden-second-recheck",
                    source_episode_path=episode_path,
                    source_verdict_path=verdict_path,
                    finding_indices=[1],
                    author_run_id="second-remediation-author",
                    skills=["process-auditor@forbidden-chain"],
                    evidence_paths=[remediation_evidence],
                )

    def test_same_run_cannot_review_itself(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = self.make_episode(root, "self-review")
            draft = {
                "evaluator": {
                    "run_id": episode["author_run_id"],
                    "model": "same-model",
                    "independent": True,
                    "context_policy": "evidence-only",
                },
                "classification": "KEEP",
                "severity": "none",
                "summary": "Self review is invalid",
                "actions": [
                    {
                        "kind": "no_change",
                        "target_skill": None,
                        "description": "No change",
                    }
                ],
            }
            with self.assertRaisesRegex(process_audit.AuditError, "differ from author"):
                process_audit.seal_verdict(episode, draft)

    def test_changed_evidence_is_reported_but_preserves_verified_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = self.make_episode(root, "tamper")
            verdict = self.verdict(episode)
            model = process_audit.empty_model(str(root))
            process_audit.update_model(model, episode, verdict)
            Path(episode["evidence_refs"][0]["ref"]).write_text(  # type: ignore[index]
                '{"status":"changed"}\n', encoding="utf-8"
            )
            self.assertEqual([], process_audit.validate_model(model, project_root=str(root)))
            result = process_audit.build_recommendation(model)
            self.assertNotIn("tamper", result["stale_or_invalid_audits"])
            self.assertIn("tamper", result["evidence_drift_audits"])
            self.assertEqual(1, result["keep_observations"]["vigers-delivery"])
            fresh = self.make_episode(root, "fresh-after-tamper")
            process_audit.update_model(model, fresh, self.verdict(fresh))
            moved = process_audit.quarantine_stale(model)
            self.assertEqual([], moved)
            self.assertIn("tamper", model["audits"])
            self.assertIn("fresh-after-tamper", model["audits"])

    def test_new_schema_one_verdict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = self.make_episode(root, "legacy-downgrade", depth="deep")
            verdict = self.verdict(episode)
            verdict["schema"] = 1
            verdict["evaluator"]["review_depth"] = "routine"  # type: ignore[index]
            verdict["recorded_at"] = "2020-01-01T00:00:00+00:00"
            verdict["fingerprint"] = process_audit.fingerprint(verdict)
            errors = process_audit.validate_verdict(episode, verdict)
            self.assertIn("unsupported verdict schema", errors)
            with self.assertRaisesRegex(process_audit.AuditError, "unsupported"):
                process_audit.update_model(
                    process_audit.empty_model(str(root)), episode, verdict
                )

    def test_keep_requires_a_completed_episode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for outcome in (
                "blocked",
                "user_stopped",
                "guard_stopped",
                "cancelled",
                "external_failure",
            ):
                episode = self.make_episode(root, f"not-keep-{outcome}", outcome=outcome)
                with self.assertRaises(process_audit.AuditError):
                    self.verdict(episode)

    def test_historical_cases_never_create_policy_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            for index in range(1, 5):
                episode = self.make_episode(
                    root,
                    f"historical-{index}",
                    origin="historical-biased",
                )
                verdict = self.verdict(
                    episode,
                    classification="PROCESS_DEFECT",
                    severity="major",
                    pattern="unbounded-review-epoch",
                )
                process_audit.update_model(model, episode, verdict)
            result = process_audit.build_recommendation(model)
            self.assertEqual("baseline_retained", result["status"])
            self.assertEqual(4, result["historical_biased_excluded"])

    def test_three_clean_defects_create_shadow_candidate_and_keep_counterweight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            keep = self.make_episode(root, "keep-1")
            process_audit.update_model(model, keep, self.verdict(keep))
            Path(keep["evidence_refs"][0]["ref"]).write_text(  # type: ignore[index]
                '{"status":"changed-after-ingest"}\n', encoding="utf-8"
            )
            for index in range(1, 4):
                episode = self.make_episode(root, f"defect-{index}")
                verdict = self.verdict(
                    episode,
                    classification="PROCESS_DEFECT",
                    severity="major",
                    pattern="unbounded-review-epoch",
                )
                process_audit.update_model(model, episode, verdict)
            result = process_audit.build_recommendation(model)
            self.assertEqual("shadow_candidates", result["status"])
            candidate = result["candidates"][0]
            self.assertEqual(3, candidate["eligible_count"])
            self.assertEqual(1, candidate["keep_observations_same_workflows"])
            self.assertIn("keep-1", result["evidence_drift_audits"])
            self.assertFalse(candidate["auto_apply"])

    def test_schema_two_drift_quarantine_keeps_counterweight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            keep = self.make_episode(root, "old-quarantined-keep")
            process_audit.update_model(model, keep, self.verdict(keep))
            record = model["audits"].pop("old-quarantined-keep")
            model["audit_count"] = 0
            model["quarantined_audits"]["old-quarantined-keep"] = {
                "record": record,
                "reasons": ["evidence changed after binding"],
                "quarantined_at": process_audit.now_utc(),
            }
            for index in range(1, 4):
                episode = self.make_episode(root, f"retained-defect-{index}")
                process_audit.update_model(
                    model,
                    episode,
                    self.verdict(
                        episode,
                        classification="PROCESS_DEFECT",
                        severity="major",
                        pattern="retained-counterweight",
                    ),
                )
            result = process_audit.build_recommendation(model)
            self.assertEqual(1, result["retained_quarantined_observations"])
            self.assertEqual(
                1, result["candidates"][0]["keep_observations_same_workflows"]
            )

    def test_one_blocker_requests_human_review_but_never_auto_applies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            episode = self.make_episode(root, "blocker-1")
            verdict = self.verdict(
                episode,
                classification="PROCESS_DEFECT",
                severity="blocker",
                pattern="unsafe-auto-resume",
            )
            process_audit.update_model(model, episode, verdict)
            candidate = process_audit.build_recommendation(model)["candidates"][0]
            self.assertEqual("urgent-human-review", candidate["kind"])
            self.assertTrue(candidate["human_approval_required"])
            self.assertFalse(candidate["auto_apply"])

    def test_three_recovery_episodes_count_as_one_incident(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            parent = self.make_episode(root, "incident-root", origin="historical-biased")
            process_audit.update_model(model, parent, self.verdict(parent))
            for index in range(1, 4):
                episode = self.make_episode(
                    root,
                    f"recovery-{index}",
                    parent_episode_id="incident-root",
                    work_item_id=f"recovery-work-{index}",
                )
                verdict = self.verdict(
                    episode,
                    classification="PROCESS_DEFECT",
                    severity="major",
                    pattern="same-incident-pattern",
                )
                process_audit.update_model(model, episode, verdict)
            result = process_audit.build_recommendation(model)
            self.assertEqual("baseline_retained", result["status"])

    def test_unlinked_runs_on_one_work_item_count_as_independent_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            for index in range(1, 4):
                episode = self.make_episode(
                    root,
                    f"independent-{index}",
                    work_item_id="same-work-item",
                )
                process_audit.update_model(
                    model,
                    episode,
                    self.verdict(
                        episode,
                        classification="PROCESS_DEFECT",
                        severity="major",
                        pattern="same-work-new-run",
                    ),
                )
            candidate = process_audit.build_recommendation(model)["candidates"][0]
            self.assertEqual(3, candidate["eligible_count"])

    def test_external_failure_and_keep_do_not_propose_process_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = process_audit.empty_model(str(root))
            episode = self.make_episode(root, "external", outcome="external_failure")
            verdict = self.verdict(episode, classification="EXTERNAL_FAILURE", severity="major")
            process_audit.update_model(model, episode, verdict)
            self.assertEqual("baseline_retained", process_audit.build_recommendation(model)["status"])

    def test_hook_blocks_material_turn_until_valid_audit_ack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "hook-state"
            event = {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": str(root),
                "hook_event_name": "PostToolUse",
                "tool_name": "apply_patch",
                "tool_input": {"patch": "small change"},
            }
            with mock.patch.dict(os.environ, {"PROCESS_AUDITOR_STATE_ROOT": str(state_root)}):
                self.assertIsNone(process_audit_hook.process_event(event, "codex"))
                stop = dict(event, hook_event_name="Stop", tool_name="", tool_input={})
                blocked = process_audit_hook.process_event(stop, "codex")
                self.assertEqual("block", blocked["decision"])
                self.assertIn("--generation 1", blocked["reason"])
                episode = self.make_episode(
                    root,
                    "hook-audit",
                    author_run_id="session-1",
                )
                verdict = self.verdict(episode)
                state_path = process_audit_hook.state_path(event, "codex")
                process_audit.ack_hook(state_path, episode, verdict, generation=1)
                self.assertIsNone(process_audit_hook.process_event(stop, "codex"))

    def test_ack_rejects_a_new_material_generation_after_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "hook-state"
            material = {
                "session_id": "session-generation-race",
                "cwd": str(root),
                "hook_event_name": "PostToolUse",
                "tool_name": "apply_patch",
                "tool_input": {"patch": "first change"},
            }
            with mock.patch.dict(
                os.environ, {"PROCESS_AUDITOR_STATE_ROOT": str(state_root)}
            ):
                process_audit_hook.process_event(material, "codex")
                episode = self.make_episode(
                    root,
                    "generation-race",
                    author_run_id="session-generation-race",
                )
                verdict = self.verdict(episode)
                process_audit_hook.process_event(material, "codex")
                with self.assertRaisesRegex(
                    process_audit.AuditError, "generation changed"
                ):
                    process_audit.ack_hook(
                        process_audit_hook.state_path(material, "codex"),
                        episode,
                        verdict,
                        generation=1,
                    )

    def test_ack_rejects_any_corrupt_hook_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "hook-state"
            material = {
                "session_id": "session-corrupt-state",
                "cwd": str(root),
                "hook_event_name": "PostToolUse",
                "tool_name": "apply_patch",
                "tool_input": {"patch": "material change"},
            }
            with mock.patch.dict(
                os.environ, {"PROCESS_AUDITOR_STATE_ROOT": str(state_root)}
            ):
                process_audit_hook.process_event(material, "codex")
                state_path = process_audit_hook.state_path(material, "codex")
                pristine = process_audit.read_json(state_path)
                episode = self.make_episode(
                    root,
                    "corrupt-state-ack",
                    author_run_id="session-corrupt-state",
                )
                verdict = self.verdict(episode)
                corrupt_states = []
                for field, value in (
                    ("material_generation", True),
                    ("interruption_status", "corrupt-value"),
                    ("audited_generation", 2),
                ):
                    state = json.loads(json.dumps(pristine))
                    state[field] = value
                    corrupt_states.append((field, state))
                missing_flag = json.loads(json.dumps(pristine))
                missing_flag.pop("stop_gate_blocked")
                corrupt_states.append(("missing stop_gate_blocked", missing_flag))
                missing_stop_time = json.loads(json.dumps(pristine))
                missing_stop_time["interruption_status"] = "user_stopped"
                missing_stop_time["manual_stop_observed_at"] = None
                corrupt_states.append(("missing manual stop timestamp", missing_stop_time))

                for label, state in corrupt_states:
                    with self.subTest(label=label):
                        process_audit.atomic_json(state_path, state)
                        self.assertFalse(process_audit_hook.valid_state(state))
                        with self.assertRaisesRegex(
                            process_audit.AuditError, "Invalid hook state"
                        ):
                            process_audit.ack_hook(
                                state_path, episode, verdict, generation=1
                            )

    def test_new_prompt_marks_unclosed_material_turn_as_manual_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                material = {
                    "session_id": "session-2",
                    "turn_id": "turn-1",
                    "cwd": str(root),
                    "hook_event_name": "PostToolUse",
                    "tool_name": "spawn_agent",
                    "tool_input": {},
                }
                process_audit_hook.process_event(material, "codex")
                next_prompt = dict(
                    material,
                    turn_id="turn-2",
                    hook_event_name="UserPromptSubmit",
                    tool_name="",
                )
                context = process_audit_hook.process_event(next_prompt, "codex")
                self.assertIn("user_stopped", json.dumps(context))
                state = process_audit.read_json(process_audit_hook.state_path(material, "codex"))
                self.assertEqual("user_stopped", state["interruption_status"])

    def test_ack_binds_manual_stop_episode_to_observed_hook_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                material = {
                    "session_id": "session-manual-stop-ack",
                    "cwd": str(root),
                    "hook_event_name": "PostToolUse",
                    "tool_name": "apply_patch",
                    "tool_input": {"patch": "material change"},
                }
                process_audit_hook.process_event(material, "codex")
                process_audit_hook.process_event(
                    dict(material, hook_event_name="UserPromptSubmit"), "codex"
                )
                state_path = process_audit_hook.state_path(material, "codex")
                state = process_audit.read_json(state_path)

                completed = self.make_episode(
                    root,
                    "manual-stop-as-completed",
                    author_run_id="session-manual-stop-ack",
                )
                with self.assertRaisesRegex(
                    process_audit.AuditError, "requires a user_stopped audit episode"
                ):
                    process_audit.ack_hook(
                        state_path, completed, self.verdict(completed), generation=1
                    )

                mismatched = self.make_episode(
                    root,
                    "manual-stop-wrong-time",
                    outcome="user_stopped",
                    author_run_id="session-manual-stop-ack",
                )
                with self.assertRaisesRegex(
                    process_audit.AuditError, "manual_stop.at does not match"
                ):
                    process_audit.ack_hook(
                        state_path,
                        mismatched,
                        self.verdict(
                            mismatched,
                            classification="MANUAL_STOP_VALIDATED",
                            severity="major",
                            pattern="manual-stop-ack-binding",
                        ),
                        generation=1,
                    )

                observed = process_audit.build_episode(
                    episode_id="manual-stop-observed",
                    work_item_id="work-manual-stop-observed",
                    project_root=str(root),
                    workflow="vigers-delivery",
                    outcome="user_stopped",
                    origin="prospective-clean",
                    author_run_id="session-manual-stop-ack",
                    skills=["vigers@af46f28", "delivery-engineering@2b4ee00"],
                    evidence_paths=[self.make_evidence(root, "manual-stop-observed.json")],
                    manual_stop_at=state["manual_stop_observed_at"],
                    manual_stop_reason="user interrupted before process audit",
                )
                process_audit.ack_hook(
                    state_path,
                    observed,
                    self.verdict(
                        observed,
                        classification="MANUAL_STOP_VALIDATED",
                        severity="major",
                        pattern="manual-stop-ack-binding",
                    ),
                    generation=1,
                )

    def test_wrapped_apply_patch_is_material(self) -> None:
        for field in ("code", "source", "payload", "note", "chars"):
            event = {
                "hook_event_name": "PostToolUse",
                "tool_name": "functions.exec",
                "tool_input": {field: "await tools.apply_patch(patch)"},
            }
            self.assertEqual(
                "material_command", process_audit_hook.material_reason(event)
            )

    def test_shell_mutations_are_material_but_read_only_checks_are_not(self) -> None:
        for command in (
            "rm -rf build/",
            "sed -i '' 's/a/b/' file.py",
            "echo x > file.py",
            "printf y >> file.py",
            "echo x>file.py",
            "printf y>>file.py",
            "python3 -c \"open('a.py','w').write('x')\"",
            "python3 build.py",
            "MODE=write python3 build.py",
            "python3 migrate_db.py && python3 test_smoke.py",
            "python3 deploy.py && python3 scripts/process_audit.py validate-episode --episode e.json",
            "python3 deploy.py --suite pytest",
            "node deploy.js pytest",
            "/usr/bin/python3 build.py",
            "bash deploy.sh",
            "make deploy",
            "find . -delete",
            "git -C repo commit -am change",
            "python3 -m black tests/test_api.py",
            "python3 deploy.py -m pytest",
            "node build.js -m pytest",
            "node test_deploy.js",
            "ruby test_release.rb",
            "osascript test_publish.scpt",
            "PROCESS_AUDITOR_META=1 python3 cli_caller.py --model claude --access workspace-write --prompt review",
            "PROCESS_AUDITOR_META=1 python3 cli_caller.py --model claude --access inherit --prompt review",
            "PROCESS_AUDITOR_META=1 python3 cli_caller.py --model claude --prompt review",
            "PROCESS_AUDITOR_META=1 python3 cli_caller.py --model claude --access read-only --access read-only --prompt review",
            "PROCESS_AUDITOR_META=1 python3 cli_caller.py --model claude --access read-only --unknown value --prompt review",
            "python3 cli_caller.py --model claude --access read-only --prompt PROCESS_AUDITOR_META=1",
            "PROCESS_AUDITOR_META=1 python3 /tmp/cli_caller.py --model claude --access read-only --prompt review",
            "sort -o out.txt in.txt",
            "sort -oout.txt in.txt",
            "sort -no out.txt in.txt",
            "sort --output=out.txt in.txt",
            "python3 -m json.tool in.json out.json",
            "git diff --output=/tmp/diff.txt",
            "git show --output /tmp/show.txt HEAD",
            "find . -fprint /tmp/list.txt",
            "ruff format .",
            "ruff check --fix .",
            "ruff clean",
            "rg --pre 'touch /tmp/process-audit-bypass' needle files",
            "rg --pre-glob '*.gz' needle files",
            "sed -n 'w /tmp/process-audit-bypass' input.txt",
            "sed -n 'e touch /tmp/process-audit-bypass' input.txt",
            "sed -f /tmp/process-audit-script.sed input.txt",
            "echo \"$(git commit -m x)\"",
            "echo $(rm -rf /tmp/victim)",
            "echo `rm -rf /tmp/victim`",
            "cat <<'EOF' | python3 -",
            "git worktree add ../wt",
            "git switch -c feature/audit",
            "gh pr create --title x --body y",
            "curl -X POST https://api.example.com/deploy",
        ):
            event = {
                "hook_event_name": "PostToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": command},
            }
            self.assertEqual("material_command", process_audit_hook.material_reason(event))
        for command in (
            "ruff check scripts",
            "python3 -m pytest -q",
            "python3 scripts/test_process_audit.py -v",
            "python3 test_deploy.py",
            "python3 -m json.tool receipt.json",
            "python3 -m json.tool --indent 2 receipt.json",
            "python3 scripts/process_audit.py validate-episode --episode episode.json",
            f"PROCESS_AUDITOR_META=1 python3 {process_audit_hook.CLI_CALLER_SCRIPT} "
            "--model claude --access read-only --prompt review",
            "cat /tmp/vigers/SKILL.md",
            "rg TODO . 2>/dev/null",
            "ruff check . > /dev/null 2>&1",
            "rg 'rm -rf' docs/",
            "rg 'x>file.py' docs/",
            "sort -kfoo input.txt",
            "sort -Tfoo input.txt",
            "sort -t,o input.txt",
        ):
            event = {
                "hook_event_name": "PostToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": command},
            }
            self.assertIsNone(process_audit_hook.material_reason(event))

        write_stdin = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.write_stdin",
            "tool_input": {"session_id": 42, "chars": ""},
        }
        self.assertIsNone(process_audit_hook.material_reason(write_stdin))
        for extra in (
            {"cmd": "rg TODO ."},
            {"cmd": "rm -rf /tmp/victim"},
            {"note": "tools.apply_patch(patch)"},
            {"source": 'tools["write_stdin"]({chars: "make deploy"})'},
        ):
            guarded_poll = {
                **write_stdin,
                "tool_input": {**write_stdin["tool_input"], **extra},
            }
            self.assertEqual(
                "material_command", process_audit_hook.material_reason(guarded_poll)
            )
        write_stdin["tool_input"]["chars"] = "rm -rf /tmp/victim\n"
        self.assertEqual(
            "material_command", process_audit_hook.material_reason(write_stdin)
        )

        chained_mutation = {
            "hook_event_name": "PostToolUse",
            "tool_name": "exec_command",
            "tool_input": {
                "cmd": "python3 scripts/process_audit.py validate-episode "
                "--episode episode.json && rm -rf build/"
            },
        }
        self.assertEqual(
            "material_command", process_audit_hook.material_reason(chained_mutation)
        )

        wrapped_read = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {"code": 'await tools.exec_command({cmd: "rg TODO ."});'},
        }
        self.assertIsNone(process_audit_hook.material_reason(wrapped_read))
        wrapped_unknown = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {
                "code": 'await tools.exec_command({cmd: "/usr/bin/python3 build.py"});'
            },
        }
        self.assertEqual(
            "material_command", process_audit_hook.material_reason(wrapped_unknown)
        )
        wrapped_mixed = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {
                "code": 'await tools.exec_command({cmd: "rg TODO ."});\n'
                "await tools.exec_command({cmd: `rm -rf /tmp/victim`});"
            },
        }
        self.assertEqual(
            "material_command", process_audit_hook.material_reason(wrapped_mixed)
        )

        for name in (
            "mcp__codex_app__automation_update",
            "mcp__codex_app__set_thread_archived",
            "image_gen__imagegen",
        ):
            self.assertTrue(
                process_audit_hook.material_reason(
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": name,
                        "tool_input": {},
                    }
                )
            )
        self.assertIsNone(
            process_audit_hook.material_reason(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "mcp__codex_app__list_threads",
                    "tool_input": {},
                }
            )
        )
        for name in (
            "mcp__unknown__list_threads",
            "mcp__unknown__read",
            "mcp__unknown__exec_command",
        ):
            self.assertIsNotNone(
                process_audit_hook.material_reason(
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": name,
                        "tool_input": {},
                    }
                )
            )
        nested_read = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {"code": "await tools.mcp__codex_app__list_threads({});"},
        }
        self.assertIsNone(process_audit_hook.material_reason(nested_read))
        for name in (
            "mcp__unknown__list_threads",
            "mcp__unknown__read",
            "mcp__unknown__exec_command",
        ):
            self.assertIsNotNone(
                process_audit_hook.material_reason(
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": "functions.exec",
                        "tool_input": {"code": f"await tools.{name}({{}});"},
                    }
                )
            )
        nested_update = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {
                "code": "await tools.mcp__codex_app__automation_update(args);"
            },
        }
        self.assertEqual(
            "material_tool:nested", process_audit_hook.material_reason(nested_update)
        )
        nested_write_poll = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {
                "code": 'await tools.write_stdin({session_id: 1, chars: ""});'
            },
        }
        self.assertIsNone(process_audit_hook.material_reason(nested_write_poll))
        nested_write_command = {
            "hook_event_name": "PostToolUse",
            "tool_name": "functions.exec",
            "tool_input": {
                "code": 'await tools.write_stdin({session_id: 1, chars: "rm -rf x\\n"});'
            },
        }
        self.assertEqual(
            "material_command",
            process_audit_hook.material_reason(nested_write_command),
        )
        nested_write_shapes = (
            'await tools.write_stdin({session_id: 1, chars: "git commit -m \\\"wip (r7)\\\""});',
            'await tools.write_stdin({session_id: 1, chars: "rm -rf $(pwd)/build"});',
            "await tools.write_stdin({session_id: 1, chars: `rm -rf ${dir}`});",
            "const p = {session_id: 1, chars: 'make deploy'}; await tools.write_stdin(p);",
            'await tools.write_stdin({meta: fn(), session_id: 1, chars: "make deploy"});',
            'await tools.write_stdin({session_id: 1, chars: "" + payload});',
            'await tools.write_stdin({session_id: 1, chars: "".concat(cmd)});',
            'await tools.write_stdin({session_id: 1, chars: "" || cmd});',
            'await tools.write_stdin({session_id: 1, chars: "" ? a : "make deploy"});',
            'await tools["write_stdin"]({session_id: 1, chars: "make deploy"});',
            "const t = tools; t.write_stdin({session_id: 1, chars: 'make deploy'});",
            "const {write_stdin} = tools; write_stdin({chars: 'make deploy'});",
            'const op = "write_stdin"; tools[op]({chars: "make deploy"});',
            "const op = choose(); Reflect.get(tools, op)({chars: 'make deploy'});",
            "const op='apply'+'_'+'patch'; await t\\u006fols[op](patch);",
            "const key='to'+'ols'; globalThis[key].apply_patch(patch);",
        )
        for code in nested_write_shapes:
            self.assertEqual(
                "material_command",
                process_audit_hook.material_reason(
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": "functions.exec",
                        "tool_input": {"code": code},
                    }
                ),
            )
        for name, tool_input in (
            ("mcp__ssh__remote_shell", {"script": "make deploy"}),
            ("mcp__ssh__remote_shell", {}),
            ("mcp__ci__runbash", {"script": "make deploy"}),
            ("KillShell", {}),
            ("write_stdin", {"arguments": {"chars": "make deploy\n"}}),
            ("write_stdin", {"session_id": 1, "chars": 7}),
            ("write_stdin", {"session_id": 1}),
            ("mcp__example__find_and_delete", {}),
        ):
            self.assertTrue(
                process_audit_hook.material_reason(
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_name": name,
                        "tool_input": tool_input,
                    }
                )
            )

    def test_ack_literal_cannot_hide_a_real_mutation(self) -> None:
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "rm -rf build/ # process_audit.py ack-hook"},
        }
        self.assertEqual("material_command", process_audit_hook.material_reason(event))

    def test_multiline_exemptions_cannot_hide_interpreter_mutation(self) -> None:
        commands = (
            "python3 scripts/test_process_audit.py\npython3 tools/regenerate_skill.py --write",
            "python3 scripts/process_audit.py validate-episode --episode e.json\n"
            "python3 tools/regenerate_skill.py --write",
            "PROCESS_AUDITOR_META=1 python3 cli_caller.py --model claude-opus\n"
            "python3 tools/regenerate_skill.py --write",
            "python3 -m pytest\npython3 tools/regenerate_skill.py --write",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                for index, command in enumerate(commands):
                    prompt = {
                        "session_id": f"multiline-{index}",
                        "cwd": str(root),
                        "hook_event_name": "UserPromptSubmit",
                    }
                    process_audit_hook.process_event(prompt, "codex")
                    event = dict(
                        prompt,
                        hook_event_name="PostToolUse",
                        tool_name="exec_command",
                        tool_input={"cmd": command},
                    )
                    process_audit_hook.process_event(event, "codex")
                    state = process_audit.read_json(
                        process_audit_hook.state_path(prompt, "codex")
                    )
                    self.assertEqual(1, state["material_generation"])
                    blocked = process_audit_hook.process_event(
                        dict(prompt, hook_event_name="Stop"), "codex"
                    )
                    self.assertEqual("block", blocked["decision"])

    def test_shell_capability_fail_closed_matrix_reaches_stop_gate(self) -> None:
        events = (
            {
                "tool_name": "write_stdin",
                "tool_input": {"session_id": 1, "chars": "rm -rf /tmp/victim\n"},
            },
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "python3 -m black tests/test_api.py"},
            },
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "python3 deploy.py -m pytest"},
            },
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "ruff check --fix ."},
            },
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "ruff clean"},
            },
            {
                "tool_name": "exec_command",
                "tool_input": {
                    "cmd": "rg --pre 'touch /tmp/process-audit-bypass' needle files"
                },
            },
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "rg --pre-glob '*.gz' needle files"},
            },
            {
                "tool_name": "exec_command",
                "tool_input": {
                    "cmd": "sed -n 'w /tmp/process-audit-bypass' input.txt"
                },
            },
            {
                "tool_name": "exec_command",
                "tool_input": {
                    "cmd": "sed -n 'e touch /tmp/process-audit-bypass' input.txt"
                },
            },
            {
                "tool_name": "exec_command",
                "tool_input": {
                    "cmd": "sed -f /tmp/process-audit-script.sed input.txt"
                },
            },
            {
                "tool_name": "exec_command",
                "tool_input": {"cmd": "echo $(rm -rf /tmp/victim)"},
            },
            {
                "tool_name": "functions.exec",
                "tool_input": {
                    "code": 'await tools.exec_command({cmd: "rg TODO ."});\n'
                    "await tools.exec_command({cmd: `rm -rf /tmp/victim`});"
                },
            },
            {
                "tool_name": "functions.exec",
                "tool_input": {
                    "code": 'await tools.write_stdin({session_id: 1, '
                    'chars: "git commit -m \\\"wip (r7)\\\""});'
                },
            },
            {
                "tool_name": "functions.exec",
                "tool_input": {
                    "code": "const p = {session_id: 1, chars: 'make deploy'}; "
                    "await tools.write_stdin(p);"
                },
            },
            {
                "tool_name": "functions.exec",
                "tool_input": {
                    "code": "const op='apply'+'_'+'patch'; "
                    "await t\\u006fols[op](patch);"
                },
            },
            {
                "tool_name": "mcp__ssh__remote_shell",
                "tool_input": {"script": "make deploy"},
            },
            {
                "tool_name": "write_stdin",
                "tool_input": {"arguments": {"chars": "make deploy\n"}},
            },
        )
        self.assertEqual(
            {
                "bash",
                "exec_command",
                "functions.exec_command",
                "shell",
                "write_stdin",
                "functions.write_stdin",
            },
            process_audit_hook.SHELL_CAPABLE_TOOL_NAMES,
        )
        self.assertIsNone(
            process_audit_hook.material_reason(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "rg TODO ."},
                }
            )
        )
        self.assertEqual(
            "material_command",
            process_audit_hook.material_reason(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "make deploy"},
                }
            ),
        )
        self.assertTrue(
            process_audit_hook.SHELL_CAPABLE_TOOL_NAMES.isdisjoint(
                process_audit_hook.NEUTRAL_TOOL_NAMES
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                for index, event_fields in enumerate(events):
                    prompt = {
                        "session_id": f"capability-{index}",
                        "cwd": str(root),
                        "hook_event_name": "UserPromptSubmit",
                    }
                    process_audit_hook.process_event(prompt, "codex")
                    process_audit_hook.process_event(
                        {
                            **prompt,
                            **event_fields,
                            "hook_event_name": "PostToolUse",
                        },
                        "codex",
                    )
                    state = process_audit.read_json(
                        process_audit_hook.state_path(prompt, "codex")
                    )
                    self.assertEqual(1, state["material_generation"])
                    blocked = process_audit_hook.process_event(
                        dict(prompt, hook_event_name="Stop"), "codex"
                    )
                    self.assertEqual("block", blocked["decision"])

    def test_real_carrier_matrices_are_discriminating_and_fail_closed(self) -> None:
        wrapper_forms = (
            'await tools.write_stdin({chars: "make deploy"});',
            'await tools.write_stdin({chars: "" + payload});',
            'await tools["write_stdin"]({chars: "make deploy"});',
            "const t = tools; t.write_stdin({chars: 'make deploy'});",
            "const {write_stdin} = tools; write_stdin({chars: 'make deploy'});",
            'const op = "write_stdin"; tools[op]({chars: "make deploy"});',
            "const op = choose(); Reflect.get(tools, op)({chars: 'make deploy'});",
        )
        shell_carriers = (
            ("exec_command", "cmd"),
            ("bash", "command"),
            ("shell", "command"),
        )
        shell_mutations = (
            "rm -rf build/",
            "echo x>artifact.txt",
            "sort -o artifact.txt input.txt",
            "sort -no artifact.txt input.txt",
            "git diff --output=artifact.diff",
            "python3 -m json.tool in.json out.json",
            "find . -fprint artifact.txt",
            "node test_deploy.js",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                case = 0
                for field in ("code", "source", "chars"):
                    for form in wrapper_forms:
                        for sibling in (False, True):
                            case += 1
                            prompt = {
                                "session_id": f"cartesian-{case}",
                                "cwd": str(root),
                                "hook_event_name": "UserPromptSubmit",
                            }
                            process_audit_hook.process_event(prompt, "codex")
                            tool_input = {field: form}
                            if sibling:
                                tool_input["cmd"] = "rg TODO ."
                            benign_input = {field: "1 + 1;"}
                            if sibling:
                                benign_input["cmd"] = "rg TODO ."
                            self.assertIsNone(
                                process_audit_hook.material_reason(
                                    {
                                        "hook_event_name": "PostToolUse",
                                        "tool_name": "functions.exec",
                                        "tool_input": benign_input,
                                    }
                                )
                            )
                            process_audit_hook.process_event(
                                {
                                    **prompt,
                                    "hook_event_name": "PostToolUse",
                                    "tool_name": "functions.exec",
                                    "tool_input": tool_input,
                                },
                                "codex",
                            )
                            state = process_audit.read_json(
                                process_audit_hook.state_path(prompt, "codex")
                            )
                            self.assertEqual(1, state["material_generation"])
                            blocked = process_audit_hook.process_event(
                                dict(prompt, hook_event_name="Stop"), "codex"
                            )
                            self.assertEqual("block", blocked["decision"])
                for carrier, command_field in shell_carriers:
                    self.assertIsNone(
                        process_audit_hook.material_reason(
                            {
                                "hook_event_name": "PostToolUse",
                                "tool_name": carrier,
                                "tool_input": {command_field: "rg TODO ."},
                            }
                        )
                    )
                    for command in shell_mutations:
                        case += 1
                        prompt = {
                            "session_id": f"shell-matrix-{case}",
                            "cwd": str(root),
                            "hook_event_name": "UserPromptSubmit",
                        }
                        process_audit_hook.process_event(prompt, "codex")
                        process_audit_hook.process_event(
                            {
                                **prompt,
                                "hook_event_name": "PostToolUse",
                                "tool_name": carrier,
                                "tool_input": {command_field: command},
                            },
                            "codex",
                        )
                        state = process_audit.read_json(
                            process_audit_hook.state_path(prompt, "codex")
                        )
                        self.assertEqual(1, state["material_generation"])
                        blocked = process_audit_hook.process_event(
                            dict(prompt, hook_event_name="Stop"), "codex"
                        )
                        self.assertEqual("block", blocked["decision"])

    def test_missing_or_corrupt_state_blocks_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "hook-state"
            stop = {
                "session_id": "session-missing",
                "cwd": str(root),
                "hook_event_name": "Stop",
            }
            with mock.patch.dict(os.environ, {"PROCESS_AUDITOR_STATE_ROOT": str(state_root)}):
                blocked = process_audit_hook.process_event(stop, "codex")
                self.assertEqual("block", blocked["decision"])
                path = process_audit_hook.state_path(stop, "codex")
                path.write_text("not-json", encoding="utf-8")
                blocked = process_audit_hook.process_event(stop, "codex")
                self.assertEqual("block", blocked["decision"])
                for corrupt in (
                    {"schema": 1},
                    {
                        **process_audit_hook.empty_state(stop, "codex"),
                        "material_generation": "3",
                    },
                    {
                        **process_audit_hook.empty_state(stop, "codex"),
                        "material_generation": 1,
                        "audited_generation": 2,
                    },
                ):
                    path.write_text(json.dumps(corrupt), encoding="utf-8")
                    blocked = process_audit_hook.process_event(stop, "codex")
                    self.assertEqual("block", blocked["decision"])

    def test_state_key_survives_cwd_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = {"session_id": "stable-session", "cwd": str(root)}
            second = {"session_id": "stable-session", "cwd": str(root / "nested")}
            self.assertEqual(
                process_audit_hook.state_path(first, "codex"),
                process_audit_hook.state_path(second, "codex"),
            )

    def test_prompt_without_turn_id_detects_real_manual_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                prompt = {
                    "session_id": "session-no-turn",
                    "cwd": str(root),
                    "hook_event_name": "UserPromptSubmit",
                }
                process_audit_hook.process_event(prompt, "codex")
                material = dict(
                    prompt,
                    hook_event_name="PostToolUse",
                    tool_name="apply_patch",
                    tool_input={"patch": "change"},
                )
                process_audit_hook.process_event(material, "codex")
                context = process_audit_hook.process_event(prompt, "codex")
                self.assertIn("user_stopped", json.dumps(context))

    def test_stop_hook_bypass_never_fabricates_user_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(
                os.environ,
                {"PROCESS_AUDITOR_STATE_ROOT": str(root / "hook-state")},
            ):
                prompt = {
                    "session_id": "session-bypass",
                    "cwd": str(root),
                    "hook_event_name": "UserPromptSubmit",
                }
                process_audit_hook.process_event(prompt, "codex")
                process_audit_hook.process_event(
                    dict(
                        prompt,
                        hook_event_name="PostToolUse",
                        tool_name="apply_patch",
                        tool_input={"patch": "change"},
                    ),
                    "codex",
                )
                process_audit_hook.process_event(
                    dict(prompt, hook_event_name="Stop", stop_hook_active=True),
                    "codex",
                )
                context = process_audit_hook.process_event(prompt, "codex")
                rendered = json.dumps(context)
                self.assertIn("blocked_or_evidence_gap", rendered)
                self.assertNotIn("outcome=user_stopped", rendered)

    def test_deep_can_be_requested_for_unisolated_external_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = process_audit.build_episode(
                episode_id="deep-external",
                work_item_id="deep-external",
                project_root=str(root),
                workflow="external-provider",
                outcome="external_failure",
                origin="prospective-clean",
                author_run_id="author-deep",
                skills=["process-auditor@test"],
                evidence_paths=[self.make_evidence(root)],
                signals=["external_error"],
                depth="deep",
            )
            self.assertEqual("deep", episode["required_depth"])

    def test_verdict_v2_cannot_predate_episode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = self.make_episode(root, "ordered")
            verdict = self.verdict(episode)
            verdict["recorded_at"] = "2020-01-01T00:00:00+00:00"
            verdict["fingerprint"] = process_audit.fingerprint(verdict)
            errors = process_audit.validate_verdict(episode, verdict)
            self.assertIn("precedes episode", " ".join(errors))

    def test_broken_record_can_be_recommended_then_quarantined_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model_path = root / ".process-auditor" / "audit-model.json"
            episode = self.make_episode(root, "broken-cli")
            model = process_audit.empty_model(str(root))
            process_audit.update_model(model, episode, self.verdict(episode))
            model["audits"]["broken-cli"]["episode"]["fingerprint"] = "0" * 64
            model["audits"]["broken-null"] = None
            model["audits"]["broken-string"] = "not-an-object"
            model["audit_count"] = 3
            process_audit.atomic_json(model_path, model)
            shadow_path = root / "shadow.json"
            recommend = subprocess.run(
                [
                    sys.executable,
                    str(Path(process_audit.__file__).resolve()),
                    "recommend",
                    "--project-root",
                    str(root),
                    "--write",
                    str(shadow_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, recommend.returncode, recommend.stderr)
            self.assertIn(
                "broken-cli",
                process_audit.read_json(shadow_path)["stale_or_invalid_audits"],
            )
            self.assertIn(
                "broken-null",
                process_audit.read_json(shadow_path)["stale_or_invalid_audits"],
            )
            quarantine = subprocess.run(
                [
                    sys.executable,
                    str(Path(process_audit.__file__).resolve()),
                    "quarantine-stale",
                    "--project-root",
                    str(root),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, quarantine.returncode, quarantine.stderr)
            loaded = process_audit.load_model(model_path, project_root=str(root))
            self.assertNotIn("broken-cli", loaded["audits"])
            self.assertIn("broken-cli", loaded["quarantined_audits"])
            self.assertIn("broken-null", loaded["quarantined_audits"])
            self.assertIn("broken-string", loaded["quarantined_audits"])
            self.assertEqual([], process_audit.validate_model(loaded, project_root=str(root)))

    def test_concurrent_cli_updates_do_not_lose_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands: list[list[str]] = []
            for index in range(8):
                episode = self.make_episode(root, f"concurrent-{index}")
                verdict = self.verdict(episode)
                episode_path = root / f"episode-{index}.json"
                verdict_path = root / f"verdict-{index}.json"
                process_audit.atomic_json(episode_path, episode)
                process_audit.atomic_json(verdict_path, verdict)
                commands.append(
                    [
                        sys.executable,
                        str(Path(process_audit.__file__).resolve()),
                        "update",
                        "--episode",
                        str(episode_path),
                        "--verdict",
                        str(verdict_path),
                    ]
                )
            processes = [
                subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for command in commands
            ]
            for process in processes:
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(0, process.returncode, stderr.decode())
            model = process_audit.load_model(
                process_audit.default_model_path(str(root)), project_root=str(root)
            )
            self.assertEqual(8, model["audit_count"])

    def test_unreadable_evidence_is_reported_as_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            episode = self.make_episode(root, "unreadable")
            record = {"episode": episode, "verdict": self.verdict(episode)}
            with mock.patch.object(
                process_audit,
                "sha256_file",
                side_effect=process_audit.AuditError("permission denied"),
            ):
                errors = process_audit.audit_evidence_drift(record)
            self.assertIn("unreadable", " ".join(errors))

    def test_installation_receipt_is_sanitized_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "skill"
            skill.mkdir()
            agents_link = root / "agents-link"
            claude_link = root / "claude-link"
            agents_link.symlink_to(verify_installation.SKILL_ROOT)
            claude_link.symlink_to(verify_installation.SKILL_ROOT)
            configs: dict[str, Path] = {}
            for harness in ("codex", "claude"):
                command = (
                    f"python3 {verify_installation.HOOK_SCRIPT} --harness {harness}"
                )
                payload = {
                    "hooks": {
                        event: [{"hooks": [{"type": "command", "command": command}]}]
                        for event in verify_installation.EVENTS
                    }
                }
                path = root / f"{harness}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                configs[harness] = path
            result = verify_installation.verify(
                codex_hooks=configs["codex"],
                claude_settings=configs["claude"],
                agents_link=agents_link,
                claude_link=claude_link,
            )
            self.assertEqual("complete", result["status"])
            self.assertNotIn("permissions", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
