#!/usr/bin/env python3
"""Build, validate, and aggregate independent workflow process audits."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EPISODE_SCHEMA = 1
VERDICT_SCHEMA = 2
LEGACY_VERDICT_SCHEMA = 1
MODEL_SCHEMA = 2
SHADOW_SCHEMA = 1
HOOK_STATE_SCHEMA = 1
MIN_PATTERN_COHORT = 3

ORIGINS = {"historical-biased", "prospective-clean", "frozen-replay"}
TRAINING_ORIGINS = {"prospective-clean", "frozen-replay"}
OUTCOMES = {
    "completed",
    "blocked",
    "user_stopped",
    "guard_stopped",
    "cancelled",
    "external_failure",
}
SIGNALS = {
    "manual_stop",
    "guard_stop",
    "excessive_reviews",
    "remediation_limit",
    "limit_exhausted",
    "external_error",
    "human_rework",
    "quality_regression",
    "scope_drift",
}
DEEP_SIGNALS = {
    "manual_stop",
    "guard_stop",
    "excessive_reviews",
    "remediation_limit",
    "human_rework",
    "quality_regression",
    "scope_drift",
}
CLASSIFICATIONS = {
    "KEEP",
    "EXECUTION_DEFECT",
    "PROCESS_DEFECT",
    "EXTERNAL_FAILURE",
    "EVIDENCE_GAP",
    "MANUAL_STOP_VALIDATED",
    "MANUAL_STOP_UNCONFIRMED",
}
SEVERITIES = {"none", "minor", "major", "blocker"}
MANUAL_ASSESSMENTS = {"not_applicable", "validated", "unconfirmed"}
ACTION_KINDS = {
    "no_change",
    "repair_result",
    "propose_policy_change",
    "investigate",
}
CLASSIFICATION_ACTIONS = {
    "KEEP": {"no_change"},
    "EXECUTION_DEFECT": {"repair_result", "investigate", "no_change"},
    "PROCESS_DEFECT": {"propose_policy_change", "investigate"},
    "EXTERNAL_FAILURE": {"no_change", "investigate"},
    "EVIDENCE_GAP": {"investigate"},
    "MANUAL_STOP_VALIDATED": {
        "propose_policy_change",
        "repair_result",
        "investigate",
    },
    "MANUAL_STOP_UNCONFIRMED": {"no_change", "investigate"},
}
PATTERN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditError(RuntimeError):
    """Invalid process-audit artifact or operation."""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def fingerprint(payload: dict[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "fingerprint"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def finding_fingerprint(finding: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(finding).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AuditError(f"Cannot bind evidence {path}: {exc}") from exc
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"Cannot read JSON {path}: {exc}") from exc


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)


def canonical_root(value: str) -> str:
    return str(Path(value).expanduser().resolve())


def project_key(project_root: str) -> str:
    return hashlib.sha256(canonical_root(project_root).encode("utf-8")).hexdigest()


def parse_iso(value: Any, label: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def validate_hook_state(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["hook state must be an object"]
    if payload.get("schema") != HOOK_STATE_SCHEMA:
        errors.append("unsupported hook state schema")
    for field in ("harness", "session_identity", "session_cwd"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            errors.append(f"hook state {field} must be a non-empty string")
    identity = payload.get("session_identity")
    identity_hash = payload.get("session_identity_sha256")
    if isinstance(identity, str) and identity:
        expected_hash = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()
        if identity_hash != expected_hash:
            errors.append("hook state session_identity_sha256 does not match")
    elif not isinstance(identity_hash, str) or not SHA256_RE.fullmatch(identity_hash):
        errors.append("hook state session_identity_sha256 must be SHA-256")
    cwd = payload.get("session_cwd")
    if isinstance(cwd, str) and cwd and cwd != canonical_root(cwd):
        errors.append("hook state session_cwd must be canonical")
    for field in ("prompt_generation", "material_generation", "audited_generation"):
        value = payload.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"hook state {field} must be a non-negative integer")
    material = payload.get("material_generation")
    audited = payload.get("audited_generation")
    if (
        isinstance(material, int)
        and not isinstance(material, bool)
        and isinstance(audited, int)
        and not isinstance(audited, bool)
        and audited > material
    ):
        errors.append("hook state audited_generation exceeds material_generation")
    reasons = payload.get("material_reasons")
    if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
        errors.append("hook state material_reasons must be a string list")
    interruption = payload.get("interruption_status")
    if interruption not in {
        "none",
        "user_stopped",
        "audit_unclosed",
        "state_integrity_unknown",
    }:
        errors.append("hook state interruption_status is invalid")
    observed_at = payload.get("manual_stop_observed_at")
    if observed_at is not None and parse_iso(observed_at, "manual_stop_observed_at") is None:
        errors.append("hook state manual_stop_observed_at must be timezone-aware ISO-8601")
    if interruption == "user_stopped" and observed_at is None:
        errors.append("hook state user_stopped requires manual_stop_observed_at")
    if interruption == "none" and observed_at is not None:
        errors.append("hook state without interruption cannot retain manual_stop_observed_at")
    for field in ("stop_gate_blocked", "stop_hook_bypass"):
        if not isinstance(payload.get(field), bool):
            errors.append(f"hook state {field} must be boolean")
    receipt = payload.get("audit_receipt")
    if receipt is not None:
        if not isinstance(receipt, dict):
            errors.append("hook state audit_receipt must be an object or null")
        else:
            if not isinstance(receipt.get("episode_id"), str) or not receipt["episode_id"]:
                errors.append("hook state receipt episode_id must be non-empty")
            for field in ("episode_fingerprint", "verdict_fingerprint"):
                value = receipt.get(field)
                if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                    errors.append(f"hook state receipt {field} must be SHA-256")
            receipt_generation = receipt.get("material_generation")
            if (
                not isinstance(receipt_generation, int)
                or isinstance(receipt_generation, bool)
                or receipt_generation < 0
            ):
                errors.append("hook state receipt material_generation is invalid")
            elif isinstance(audited, int) and not isinstance(audited, bool):
                if receipt_generation != audited:
                    errors.append(
                        "hook state receipt material_generation must equal audited_generation"
                    )
            if parse_iso(receipt.get("acknowledged_at"), "acknowledged_at") is None:
                errors.append("hook state receipt acknowledged_at must be timezone-aware ISO-8601")
    if parse_iso(payload.get("updated_at"), "updated_at") is None:
        errors.append("hook state updated_at must be timezone-aware ISO-8601")
    return errors


def evidence_ref(path: Path) -> dict[str, str]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise AuditError(f"Evidence is not a file: {resolved}")
    return {"ref": str(resolved), "sha256": sha256_file(resolved)}


def parse_skill(value: str) -> dict[str, str]:
    if "@" not in value:
        raise AuditError(f"Skill must use name@version: {value}")
    name, version = value.split("@", 1)
    if not name.strip() or not version.strip():
        raise AuditError(f"Skill must use non-empty name@version: {value}")
    return {"name": name.strip(), "version": version.strip()}


def required_depth(outcome: str, signals: list[str]) -> str:
    if outcome in {"user_stopped", "guard_stopped"} or DEEP_SIGNALS.intersection(signals):
        return "deep"
    return "routine"


def build_episode(
    *,
    episode_id: str,
    work_item_id: str,
    project_root: str,
    workflow: str,
    outcome: str,
    origin: str,
    author_run_id: str,
    skills: list[str],
    evidence_paths: list[Path],
    signals: list[str] | None = None,
    parent_episode_id: str | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    manual_stop_at: str | None = None,
    manual_stop_reason: str | None = None,
    depth: str | None = None,
) -> dict[str, Any]:
    signals = sorted(set(signals or []))
    if outcome == "user_stopped" and "manual_stop" not in signals:
        signals.append("manual_stop")
        signals.sort()
    if outcome == "guard_stopped" and "guard_stop" not in signals:
        signals.append("guard_stop")
        signals.sort()
    root = canonical_root(project_root)
    manual_stop: dict[str, Any] | None = None
    if outcome == "user_stopped":
        manual_stop = {
            "authority": "user",
            "at": manual_stop_at,
            "reason": manual_stop_reason if manual_stop_reason else "unknown",
            "reason_status": "provided" if manual_stop_reason else "unknown",
            "resume_authority": "user_only",
        }
    minimum_depth = required_depth(outcome, signals)
    if depth not in {None, "routine", "deep"}:
        raise AuditError("depth must be routine or deep")
    if depth == "routine" and minimum_depth == "deep":
        raise AuditError("routine depth cannot override a mandatory deep audit")
    payload: dict[str, Any] = {
        "schema": EPISODE_SCHEMA,
        "episode_id": episode_id,
        "work_item_id": work_item_id,
        "parent_episode_id": parent_episode_id,
        "project_root": root,
        "project_key": project_key(root),
        "workflow": workflow,
        "outcome": outcome,
        "origin": origin,
        "author_run_id": author_run_id,
        "skill_chain": [parse_skill(value) for value in skills],
        "evidence_refs": [evidence_ref(path) for path in evidence_paths],
        "signals": signals,
        "required_depth": "deep" if depth == "deep" else minimum_depth,
        "window": {"started_at": started_at, "ended_at": ended_at},
        "manual_stop": manual_stop,
        "recorded_at": now_utc(),
    }
    payload["fingerprint"] = fingerprint(payload)
    errors = validate_episode(payload, verify_evidence=True)
    if errors:
        raise AuditError("Invalid episode: " + "; ".join(errors))
    return payload


def build_remediation_episode(
    *,
    episode_id: str,
    source_episode_path: Path,
    source_verdict_path: Path,
    finding_indices: list[int],
    author_run_id: str,
    skills: list[str],
    evidence_paths: list[Path],
) -> dict[str, Any]:
    resolved_episode = source_episode_path.expanduser().resolve()
    resolved_verdict = source_verdict_path.expanduser().resolve()
    source_episode = read_json(resolved_episode)
    source_verdict = read_json(resolved_verdict)
    errors = validate_verdict(source_episode, source_verdict, verify_evidence=False)
    if errors:
        raise AuditError("Invalid source audit pair: " + "; ".join(errors))
    if source_episode.get("review_scope") is not None:
        raise AuditError("A targeted remediation episode cannot open another remediation recheck")
    findings = source_verdict.get("findings")
    if not isinstance(findings, list) or not findings:
        raise AuditError("Source verdict has no findings to remediate")
    normalized_indices = sorted(set(finding_indices))
    if not normalized_indices or any(
        not isinstance(index, int)
        or isinstance(index, bool)
        or index < 1
        or index > len(findings)
        for index in normalized_indices
    ):
        raise AuditError("finding indices must select existing one-based source findings")
    selected_findings = [
        {
            "index": index,
            "fingerprint": finding_fingerprint(findings[index - 1]),
            "target_skill": findings[index - 1].get("target_skill"),
        }
        for index in normalized_indices
    ]
    bound_paths: list[Path] = []
    seen: set[str] = set()
    for path in [resolved_episode, resolved_verdict, *evidence_paths]:
        resolved = path.expanduser().resolve()
        if str(resolved) in seen:
            continue
        seen.add(str(resolved))
        bound_paths.append(resolved)
    payload = build_episode(
        episode_id=episode_id,
        work_item_id=source_episode["work_item_id"],
        parent_episode_id=source_episode["episode_id"],
        project_root=source_episode["project_root"],
        workflow=source_episode["workflow"],
        outcome="completed",
        origin="prospective-clean",
        author_run_id=author_run_id,
        skills=skills,
        evidence_paths=bound_paths,
        signals=[],
        depth="routine",
    )
    payload["review_scope"] = {
        "mode": "targeted_remediation",
        "source_episode_ref": str(resolved_episode),
        "source_episode_sha256": sha256_file(resolved_episode),
        "source_episode_id": source_episode["episode_id"],
        "source_verdict_ref": str(resolved_verdict),
        "source_verdict_sha256": sha256_file(resolved_verdict),
        "source_verdict_fingerprint": source_verdict["fingerprint"],
        "selected_findings": selected_findings,
        "new_findings_policy": "backlog_only",
        "max_rechecks": 1,
        "automatic_followup": False,
    }
    payload["fingerprint"] = fingerprint(payload)
    errors = validate_episode(payload, verify_evidence=True)
    if errors:
        raise AuditError("Invalid remediation episode: " + "; ".join(errors))
    return payload


def validate_review_scope(
    payload: dict[str, Any],
    refs_by_path: dict[str, str],
    *,
    verify_evidence: bool,
) -> list[str]:
    scope = payload.get("review_scope")
    if scope is None:
        return []
    if not isinstance(scope, dict):
        return ["review_scope must be an object or null"]
    errors: list[str] = []
    if scope.get("mode") != "targeted_remediation":
        errors.append("review_scope mode must be targeted_remediation")
    if scope.get("new_findings_policy") != "backlog_only":
        errors.append("targeted remediation requires backlog_only new findings policy")
    if scope.get("max_rechecks") != 1:
        errors.append("targeted remediation max_rechecks must equal 1")
    if scope.get("automatic_followup") is not False:
        errors.append("targeted remediation automatic_followup must be false")
    if payload.get("outcome") != "completed":
        errors.append("targeted remediation episode outcome must be completed")
    if payload.get("signals") != []:
        errors.append("targeted remediation episode cannot open new process signals")
    if payload.get("required_depth") != "routine":
        errors.append("targeted remediation recheck must use routine depth")
    selected = scope.get("selected_findings")
    if not isinstance(selected, list) or not selected:
        errors.append("targeted remediation requires selected_findings")
        selected = []
    seen_indices: set[int] = set()
    seen_fingerprints: set[str] = set()
    for item in selected:
        if not isinstance(item, dict):
            errors.append("selected finding must be an object")
            continue
        index = item.get("index")
        selected_fingerprint = item.get("fingerprint")
        if not isinstance(index, int) or isinstance(index, bool) or index < 1:
            errors.append("selected finding index must be a positive integer")
        elif index in seen_indices:
            errors.append("selected finding indices must be unique")
        else:
            seen_indices.add(index)
        if (
            not isinstance(selected_fingerprint, str)
            or not SHA256_RE.fullmatch(selected_fingerprint)
        ):
            errors.append("selected finding fingerprint must be SHA-256")
        elif selected_fingerprint in seen_fingerprints:
            errors.append("selected finding fingerprints must be unique")
        else:
            seen_fingerprints.add(selected_fingerprint)
        target = item.get("target_skill")
        if target is not None and (not isinstance(target, str) or not target):
            errors.append("selected finding target_skill must be null or non-empty")
    if [item.get("index") for item in selected if isinstance(item, dict)] != sorted(
        seen_indices
    ):
        errors.append("selected findings must be sorted by index")
    source_paths: dict[str, tuple[str, str]] = {}
    for kind in ("episode", "verdict"):
        ref = scope.get(f"source_{kind}_ref")
        expected = scope.get(f"source_{kind}_sha256")
        if not isinstance(ref, str) or ref != canonical_root(ref):
            errors.append(f"source_{kind}_ref must be a canonical absolute path")
            continue
        if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            errors.append(f"source_{kind}_sha256 must be SHA-256")
            continue
        if refs_by_path.get(ref) != expected:
            errors.append(f"source {kind} must be hash-bound in evidence_refs")
        source_paths[kind] = (ref, expected)
    if not isinstance(scope.get("source_episode_id"), str) or not scope[
        "source_episode_id"
    ]:
        errors.append("source_episode_id must be non-empty")
    source_verdict_fingerprint = scope.get("source_verdict_fingerprint")
    if (
        not isinstance(source_verdict_fingerprint, str)
        or not SHA256_RE.fullmatch(source_verdict_fingerprint)
    ):
        errors.append("source_verdict_fingerprint must be SHA-256")
    if not verify_evidence or set(source_paths) != {"episode", "verdict"}:
        return errors
    try:
        source_episode = read_json(Path(source_paths["episode"][0]))
        source_verdict = read_json(Path(source_paths["verdict"][0]))
    except AuditError as exc:
        errors.append(str(exc))
        return errors
    if isinstance(source_episode, dict) and source_episode.get("review_scope") is not None:
        errors.append("targeted remediation cannot chain from another targeted recheck")
        return errors
    source_errors = validate_verdict(source_episode, source_verdict, verify_evidence=False)
    errors.extend(f"source audit: {error}" for error in source_errors)
    if source_errors:
        return errors
    if payload.get("parent_episode_id") != source_episode.get("episode_id"):
        errors.append("targeted remediation parent must be the source episode")
    for field in ("work_item_id", "project_root", "project_key", "workflow"):
        if payload.get(field) != source_episode.get(field):
            errors.append(f"targeted remediation {field} must match source episode")
    if scope.get("source_episode_id") != source_episode.get("episode_id"):
        errors.append("source_episode_id does not match source episode")
    if scope.get("source_verdict_fingerprint") != source_verdict.get("fingerprint"):
        errors.append("source_verdict_fingerprint does not match source verdict")
    source_findings = source_verdict.get("findings")
    if not isinstance(source_findings, list):
        errors.append("source verdict findings are invalid")
        return errors
    for item in selected:
        if not isinstance(item, dict) or not isinstance(item.get("index"), int):
            continue
        index = item["index"]
        if index < 1 or index > len(source_findings):
            errors.append("selected finding index is outside source verdict")
            continue
        source_finding = source_findings[index - 1]
        if not isinstance(source_finding, dict):
            errors.append("selected source finding is invalid")
            continue
        if item.get("fingerprint") != finding_fingerprint(source_finding):
            errors.append("selected finding fingerprint does not match source verdict")
        if item.get("target_skill") != source_finding.get("target_skill"):
            errors.append("selected finding target_skill does not match source verdict")
    return errors


def validate_episode(payload: Any, *, verify_evidence: bool = True) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["episode must be an object"]
    if payload.get("schema") != EPISODE_SCHEMA:
        errors.append("unsupported episode schema")
    for field in ("episode_id", "work_item_id", "project_root", "workflow", "author_run_id"):
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            errors.append(f"{field} must be a non-empty string")
    root = payload.get("project_root")
    if isinstance(root, str):
        if root != canonical_root(root):
            errors.append("project_root must be canonical")
        if payload.get("project_key") != project_key(root):
            errors.append("project_key does not match project_root")
    if payload.get("origin") not in ORIGINS:
        errors.append("invalid origin")
    if payload.get("outcome") not in OUTCOMES:
        errors.append("invalid outcome")
    parent = payload.get("parent_episode_id")
    if parent is not None and (not isinstance(parent, str) or not parent.strip()):
        errors.append("parent_episode_id must be null or non-empty")
    skills = payload.get("skill_chain")
    if not isinstance(skills, list) or not skills:
        errors.append("skill_chain must be non-empty")
    else:
        names: set[str] = set()
        for item in skills:
            if not isinstance(item, dict):
                errors.append("skill_chain entries must be objects")
                continue
            name, version = item.get("name"), item.get("version")
            if not isinstance(name, str) or not name.strip():
                errors.append("skill name must be non-empty")
            elif name in names:
                errors.append(f"duplicate skill name: {name}")
            else:
                names.add(name)
            if not isinstance(version, str) or not version.strip():
                errors.append("skill version must be non-empty")
    refs = payload.get("evidence_refs")
    refs_by_path: dict[str, str] = {}
    if not isinstance(refs, list) or not refs:
        errors.append("evidence_refs must be non-empty")
    else:
        seen_refs: set[str] = set()
        for item in refs:
            if not isinstance(item, dict):
                errors.append("evidence ref must be an object")
                continue
            ref, expected = item.get("ref"), item.get("sha256")
            if not isinstance(ref, str) or not ref:
                errors.append("evidence ref path must be non-empty")
                continue
            if ref in seen_refs:
                errors.append(f"duplicate evidence ref: {ref}")
            seen_refs.add(ref)
            if isinstance(expected, str):
                refs_by_path[ref] = expected
            if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
                errors.append(f"invalid evidence sha256: {ref}")
            elif verify_evidence:
                path = Path(ref)
                if not path.is_file():
                    errors.append(f"missing evidence: {ref}")
                else:
                    try:
                        actual = sha256_file(path)
                    except AuditError as exc:
                        errors.append(str(exc))
                    else:
                        if actual != expected:
                            errors.append(f"changed evidence: {ref}")
    signals = payload.get("signals")
    if not isinstance(signals, list) or any(item not in SIGNALS for item in signals):
        errors.append("invalid signals")
    elif signals != sorted(set(signals)):
        errors.append("signals must be unique and sorted")
    else:
        minimum_depth = required_depth(str(payload.get("outcome")), signals)
        actual_depth = payload.get("required_depth")
        if actual_depth not in {"routine", "deep"}:
            errors.append("required_depth must be routine or deep")
        elif minimum_depth == "deep" and actual_depth != "deep":
            errors.append("required_depth is weaker than outcome/signals")
    window = payload.get("window")
    if not isinstance(window, dict):
        errors.append("window must be an object")
    else:
        started_raw, ended_raw = window.get("started_at"), window.get("ended_at")
        started = parse_iso(started_raw, "started_at") if started_raw is not None else None
        ended = parse_iso(ended_raw, "ended_at") if ended_raw is not None else None
        if started_raw is not None and started is None:
            errors.append("started_at must be timezone-aware ISO-8601 or null")
        if ended_raw is not None and ended is None:
            errors.append("ended_at must be timezone-aware ISO-8601 or null")
        if started and ended and ended < started:
            errors.append("ended_at precedes started_at")
    manual = payload.get("manual_stop")
    if payload.get("outcome") == "user_stopped":
        if not isinstance(manual, dict):
            errors.append("user_stopped requires manual_stop")
        else:
            if manual.get("authority") != "user":
                errors.append("manual_stop authority must be user")
            if manual.get("resume_authority") != "user_only":
                errors.append("manual_stop resume_authority must be user_only")
            if parse_iso(manual.get("at"), "manual_stop.at") is None:
                errors.append("manual_stop.at must be timezone-aware ISO-8601")
            if manual.get("reason_status") not in {"provided", "unknown"}:
                errors.append("invalid manual_stop reason_status")
    elif manual is not None:
        errors.append("manual_stop is allowed only for user_stopped")
    errors.extend(validate_review_scope(payload, refs_by_path, verify_evidence=verify_evidence))
    if parse_iso(payload.get("recorded_at"), "recorded_at") is None:
        errors.append("recorded_at must be timezone-aware ISO-8601")
    if payload.get("fingerprint") != fingerprint(payload):
        errors.append("episode fingerprint mismatch")
    return errors


def seal_verdict(episode: dict[str, Any], draft: Any) -> dict[str, Any]:
    if not isinstance(draft, dict):
        raise AuditError("Verdict draft must be an object")
    payload = dict(draft)
    payload["schema"] = VERDICT_SCHEMA
    payload["episode_id"] = episode["episode_id"]
    payload["episode_fingerprint"] = episode["fingerprint"]
    payload.setdefault("process_pattern_id", None)
    payload.setdefault("findings", [])
    payload.setdefault("actions", [])
    payload.setdefault("manual_stop_assessment", "not_applicable")
    payload["no_auto_resume"] = True
    payload["auto_apply"] = False
    if episode.get("review_scope") is not None:
        payload["scope_expansion"] = False
        payload["automatic_followup"] = False
    payload["recorded_at"] = now_utc()
    payload["fingerprint"] = fingerprint(payload)
    errors = validate_verdict(episode, payload, verify_evidence=True)
    if errors:
        raise AuditError("Invalid verdict: " + "; ".join(errors))
    return payload


def validate_remediation_verdict(
    episode: dict[str, Any],
    verdict: dict[str, Any],
    evidence_hashes: set[str],
) -> list[str]:
    scope = episode.get("review_scope")
    if scope is None:
        if "remediation_results" in verdict:
            return ["remediation_results are allowed only for targeted remediation"]
        return []
    errors: list[str] = []
    if verdict.get("findings") != []:
        errors.append("targeted remediation verdict cannot introduce findings")
    if verdict.get("process_pattern_id") is not None:
        errors.append("targeted remediation cannot create a process pattern")
    if verdict.get("scope_expansion") is not False:
        errors.append("targeted remediation scope_expansion must be false")
    if verdict.get("automatic_followup") is not False:
        errors.append("targeted remediation automatic_followup must be false")
    selected = scope.get("selected_findings") if isinstance(scope, dict) else []
    expected = [
        item.get("fingerprint") for item in selected if isinstance(item, dict)
    ]
    results = verdict.get("remediation_results")
    if not isinstance(results, list) or not results:
        errors.append("targeted remediation verdict requires remediation_results")
        results = []
    actual: list[str] = []
    statuses: list[str] = []
    source_hashes = {
        scope.get("source_episode_sha256"),
        scope.get("source_verdict_sha256"),
    }
    for item in results:
        if not isinstance(item, dict):
            errors.append("remediation result must be an object")
            continue
        finding_id = item.get("finding_fingerprint")
        if not isinstance(finding_id, str) or not SHA256_RE.fullmatch(finding_id):
            errors.append("remediation result finding_fingerprint must be SHA-256")
        else:
            actual.append(finding_id)
        status = item.get("status")
        if status not in {"closed", "open", "unverified"}:
            errors.append("remediation result status is invalid")
        else:
            statuses.append(status)
        if not isinstance(item.get("summary"), str) or not item["summary"].strip():
            errors.append("remediation result summary must be non-empty")
        hashes = item.get("evidence_sha256")
        if not isinstance(hashes, list) or not hashes:
            errors.append("remediation result must cite evidence_sha256")
        elif any(value not in evidence_hashes for value in hashes):
            errors.append("remediation result cites evidence outside episode")
        elif not any(value not in source_hashes for value in hashes):
            errors.append("remediation result must cite current remediation evidence")
    if actual != expected:
        errors.append("remediation results must match selected findings in order")
    classification = verdict.get("classification")
    severity = verdict.get("severity")
    if statuses and all(status == "closed" for status in statuses):
        if classification != "KEEP" or severity != "none":
            errors.append("all closed remediation results require KEEP severity none")
    elif "open" in statuses:
        if classification != "EXECUTION_DEFECT" or severity == "none":
            errors.append("open remediation results require non-none EXECUTION_DEFECT")
    elif statuses and classification != "EVIDENCE_GAP":
        errors.append("unverified remediation results require EVIDENCE_GAP")
    return errors


def validate_verdict(
    episode: Any,
    verdict: Any,
    *,
    verify_evidence: bool = True,
    allow_legacy_schema: bool = False,
) -> list[str]:
    errors = validate_episode(episode, verify_evidence=verify_evidence)
    if errors:
        return [f"episode: {error}" for error in errors]
    if not isinstance(verdict, dict):
        return ["verdict must be an object"]
    verdict_schema = verdict.get("schema")
    if verdict_schema != VERDICT_SCHEMA and not (
        allow_legacy_schema and verdict_schema == LEGACY_VERDICT_SCHEMA
    ):
        errors.append("unsupported verdict schema")
    if verdict.get("episode_id") != episode.get("episode_id"):
        errors.append("verdict episode_id mismatch")
    if verdict.get("episode_fingerprint") != episode.get("fingerprint"):
        errors.append("verdict episode_fingerprint mismatch")
    evaluator = verdict.get("evaluator")
    if not isinstance(evaluator, dict):
        errors.append("evaluator must be an object")
    else:
        run_id = evaluator.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            errors.append("evaluator.run_id must be non-empty")
        elif run_id == episode.get("author_run_id"):
            errors.append("evaluator must differ from author")
        if not isinstance(evaluator.get("model"), str) or not evaluator["model"].strip():
            errors.append("evaluator.model must be non-empty")
        if evaluator.get("independent") is not True:
            errors.append("evaluator.independent must be true")
        if evaluator.get("context_policy") != "evidence-only":
            errors.append("evaluator.context_policy must be evidence-only")
        if verdict_schema == VERDICT_SCHEMA and evaluator.get("review_depth") != episode.get(
            "required_depth"
        ):
            errors.append("evaluator.review_depth must match episode required_depth")
    classification = verdict.get("classification")
    if classification not in CLASSIFICATIONS:
        errors.append("invalid classification")
    outcome = episode.get("outcome")
    if outcome == "user_stopped" and classification not in {
        "MANUAL_STOP_VALIDATED",
        "MANUAL_STOP_UNCONFIRMED",
    }:
        errors.append("user_stopped requires a manual stop classification")
    elif classification == "KEEP" and outcome != "completed":
        errors.append("KEEP requires a completed episode")
    severity = verdict.get("severity")
    if severity not in SEVERITIES:
        errors.append("invalid severity")
    if not isinstance(verdict.get("summary"), str) or not verdict["summary"].strip():
        errors.append("summary must be non-empty")
    pattern = verdict.get("process_pattern_id")
    if pattern is not None and (not isinstance(pattern, str) or not PATTERN_RE.fullmatch(pattern)):
        errors.append("invalid process_pattern_id")
    if classification == "PROCESS_DEFECT" and pattern is None:
        errors.append("PROCESS_DEFECT requires process_pattern_id")
    if classification == "MANUAL_STOP_VALIDATED" and any(
        item.get("kind") == "propose_policy_change"
        for item in verdict.get("actions", [])
        if isinstance(item, dict)
    ) and pattern is None:
        errors.append("policy-changing MANUAL_STOP_VALIDATED requires process_pattern_id")
    protected_none = {"KEEP", "EXTERNAL_FAILURE", "EVIDENCE_GAP", "MANUAL_STOP_UNCONFIRMED"}
    if classification in protected_none and severity == "blocker":
        errors.append(f"{classification} cannot claim blocker severity")
    if classification == "KEEP" and severity != "none":
        errors.append("KEEP requires severity none")
    evidence_hashes = {
        item["sha256"]
        for item in episode.get("evidence_refs", [])
        if isinstance(item, dict) and isinstance(item.get("sha256"), str)
    }
    findings = verdict.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        findings = []
    for item in findings:
        if not isinstance(item, dict):
            errors.append("finding must be an object")
            continue
        if not isinstance(item.get("description"), str) or not item["description"].strip():
            errors.append("finding description must be non-empty")
        target = item.get("target_skill")
        if target is not None and (not isinstance(target, str) or not target.strip()):
            errors.append("finding target_skill must be null or non-empty")
        hashes = item.get("evidence_sha256")
        if not isinstance(hashes, list) or not hashes:
            errors.append("finding must cite evidence_sha256")
        elif any(value not in evidence_hashes for value in hashes):
            errors.append("finding cites evidence outside episode")
        if classification == "PROCESS_DEFECT" and not target:
            errors.append("PROCESS_DEFECT findings require target_skill")
    if classification in {"PROCESS_DEFECT", "MANUAL_STOP_VALIDATED"} and not findings:
        errors.append(f"{classification} requires at least one finding")
    actions = verdict.get("actions")
    if not isinstance(actions, list) or not actions:
        errors.append("actions must be a non-empty list")
        actions = []
    allowed = CLASSIFICATION_ACTIONS.get(str(classification), set())
    for item in actions:
        if not isinstance(item, dict):
            errors.append("action must be an object")
            continue
        kind = item.get("kind")
        if kind not in ACTION_KINDS or kind not in allowed:
            errors.append(f"action {kind!r} is invalid for {classification}")
        if not isinstance(item.get("description"), str) or not item["description"].strip():
            errors.append("action description must be non-empty")
        target = item.get("target_skill")
        if kind == "propose_policy_change" and (
            not isinstance(target, str) or not target.strip()
        ):
            errors.append("propose_policy_change requires target_skill")
    manual_assessment = verdict.get("manual_stop_assessment")
    if manual_assessment not in MANUAL_ASSESSMENTS:
        errors.append("invalid manual_stop_assessment")
    if episode.get("outcome") == "user_stopped":
        if manual_assessment not in {"validated", "unconfirmed"}:
            errors.append("user_stopped requires a manual stop assessment")
        expected = {
            "MANUAL_STOP_VALIDATED": "validated",
            "MANUAL_STOP_UNCONFIRMED": "unconfirmed",
        }.get(str(classification))
        if expected and manual_assessment != expected:
            errors.append("manual stop classification/assessment mismatch")
    elif manual_assessment != "not_applicable":
        errors.append("manual_stop_assessment must be not_applicable")
    if classification in {"MANUAL_STOP_VALIDATED", "MANUAL_STOP_UNCONFIRMED"} and episode.get(
        "outcome"
    ) != "user_stopped":
        errors.append("manual stop classification requires user_stopped episode")
    if verdict.get("no_auto_resume") is not True:
        errors.append("no_auto_resume must be true")
    if verdict.get("auto_apply") is not False:
        errors.append("auto_apply must be false")
    errors.extend(validate_remediation_verdict(episode, verdict, evidence_hashes))
    verdict_recorded = parse_iso(verdict.get("recorded_at"), "recorded_at")
    if verdict_recorded is None:
        errors.append("verdict recorded_at must be timezone-aware ISO-8601")
    elif verdict_schema == VERDICT_SCHEMA:
        episode_recorded = parse_iso(episode.get("recorded_at"), "episode.recorded_at")
        if episode_recorded is not None and verdict_recorded < episode_recorded:
            errors.append("verdict recorded_at precedes episode recorded_at")
    if verdict.get("fingerprint") != fingerprint(verdict):
        errors.append("verdict fingerprint mismatch")
    return errors


def default_model_path(project_root: str) -> Path:
    return Path(canonical_root(project_root)) / ".process-auditor" / "audit-model.json"


def empty_model(project_root: str) -> dict[str, Any]:
    root = canonical_root(project_root)
    return {
        "schema": MODEL_SCHEMA,
        "project_root": root,
        "project_key": project_key(root),
        "audit_count": 0,
        "audits": {},
        "quarantined_audits": {},
        "updated_at": now_utc(),
    }


def migrate_model(payload: Any, *, project_root: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AuditError("model must be an object")
    if payload.get("schema") == 1:
        migrated = dict(payload)
        migrated["schema"] = MODEL_SCHEMA
        migrated["quarantined_audits"] = {}
        migrated["updated_at"] = now_utc()
        return migrated
    return payload


def validate_model(payload: Any, *, project_root: str, verify_evidence: bool = False) -> list[str]:
    errors: list[str] = []
    root = canonical_root(project_root)
    if not isinstance(payload, dict):
        return ["model must be an object"]
    if payload.get("schema") != MODEL_SCHEMA:
        errors.append("unsupported model schema")
    if payload.get("project_root") != root or payload.get("project_key") != project_key(root):
        errors.append("model belongs to another project root")
    audits = payload.get("audits")
    if not isinstance(audits, dict):
        errors.append("audits must be an object")
        return errors
    if payload.get("audit_count") != len(audits):
        errors.append("audit_count mismatch")
    for episode_id, record in audits.items():
        if not isinstance(record, dict):
            errors.append(f"audit {episode_id} must be an object")
            continue
        episode, verdict = record.get("episode"), record.get("verdict")
        if isinstance(episode, dict) and episode.get("episode_id") != episode_id:
            errors.append(f"audit key mismatch: {episode_id}")
        errors.extend(
            f"audit {episode_id}: {error}"
            for error in validate_verdict(
                episode,
                verdict,
                verify_evidence=verify_evidence,
                allow_legacy_schema=True,
            )
        )
    quarantined = payload.get("quarantined_audits")
    if not isinstance(quarantined, dict):
        errors.append("quarantined_audits must be an object")
    else:
        for episode_id, item in quarantined.items():
            if not isinstance(item, dict) or "record" not in item:
                errors.append(f"quarantined audit {episode_id} is invalid")
                continue
            if not isinstance(item.get("reasons"), list) or not item["reasons"]:
                errors.append(f"quarantined audit {episode_id} requires reasons")
    if parse_iso(payload.get("updated_at"), "updated_at") is None:
        errors.append("updated_at must be timezone-aware ISO-8601")
    return errors


def model_envelope_errors(payload: Any, *, project_root: str) -> list[str]:
    root = canonical_root(project_root)
    if not isinstance(payload, dict):
        return ["model must be an object"]
    errors: list[str] = []
    if payload.get("schema") != MODEL_SCHEMA:
        errors.append("unsupported model schema")
    if payload.get("project_root") != root or payload.get("project_key") != project_key(root):
        errors.append("model belongs to another project root")
    if not isinstance(payload.get("audits"), dict):
        errors.append("audits must be an object")
    if not isinstance(payload.get("quarantined_audits"), dict):
        errors.append("quarantined_audits must be an object")
    return errors


def load_model(path: Path, *, project_root: str) -> dict[str, Any]:
    if not path.exists():
        return empty_model(project_root)
    payload = read_json(path)
    payload = migrate_model(payload, project_root=project_root)
    errors = model_envelope_errors(payload, project_root=project_root)
    if errors:
        raise AuditError("Invalid audit model: " + "; ".join(errors))
    payload["audit_count"] = len(payload["audits"])
    if parse_iso(payload.get("updated_at"), "updated_at") is None:
        payload["updated_at"] = now_utc()
    return payload


def update_model(
    model: dict[str, Any],
    episode: dict[str, Any],
    verdict: dict[str, Any],
    *,
    replace: bool = False,
) -> bool:
    errors = validate_verdict(episode, verdict, verify_evidence=True)
    if errors:
        raise AuditError("Invalid audit pair: " + "; ".join(errors))
    if model.get("project_key") != episode.get("project_key"):
        raise AuditError("Episode belongs to another project model")
    episode_id = episode["episode_id"]
    current = model["audits"].get(episode_id)
    if (
        isinstance(current, dict)
        and current.get("episode") == episode
        and current.get("verdict") == verdict
    ):
        return False
    record = {
        "episode": episode,
        "verdict": verdict,
        "evidence_ingest": {
            "verified_at": now_utc(),
            "refs": episode.get("evidence_refs", []),
        },
    }
    if current is not None and not replace:
        raise AuditError(f"Changed audit {episode_id} requires --replace")
    model["audits"][episode_id] = record
    model["audit_count"] = len(model["audits"])
    model["updated_at"] = now_utc()
    return True


def process_targets(verdict: dict[str, Any]) -> set[str]:
    targets = {
        str(item.get("target_skill"))
        for item in verdict.get("findings", [])
        if isinstance(item, dict) and item.get("target_skill")
    }
    targets.update(
        str(item.get("target_skill"))
        for item in verdict.get("actions", [])
        if isinstance(item, dict) and item.get("kind") == "propose_policy_change"
        and item.get("target_skill")
    )
    return targets


def incident_key(
    episode: dict[str, Any],
    audits: dict[str, dict[str, Any]],
) -> str:
    current = episode
    seen: set[str] = set()
    while isinstance(current.get("parent_episode_id"), str):
        parent_id = str(current["parent_episode_id"])
        if parent_id in seen:
            return f"cycle:{parent_id}"
        seen.add(parent_id)
        parent = audits.get(parent_id)
        if not isinstance(parent, dict) or not isinstance(parent.get("episode"), dict):
            return f"parent:{parent_id}"
        current = parent["episode"]
    return f"episode:{current.get('episode_id')}"


def audit_record_errors(record: Any) -> list[str]:
    if not isinstance(record, dict):
        return ["audit record must be an object"]
    return validate_verdict(
        record.get("episode"),
        record.get("verdict"),
        verify_evidence=False,
        allow_legacy_schema=True,
    )


def audit_evidence_drift(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    episode = record.get("episode")
    if not isinstance(episode, dict):
        return ["episode must be an object"]
    for binding in episode.get("evidence_refs", []):
        if not isinstance(binding, dict):
            continue
        reference, expected = binding.get("ref"), binding.get("sha256")
        if not isinstance(reference, str) or not isinstance(expected, str):
            continue
        path = Path(reference).expanduser().resolve()
        if not path.is_file():
            errors.append(f"evidence missing after verified ingest: {reference}")
        else:
            try:
                actual = sha256_file(path)
            except AuditError as exc:
                errors.append(f"evidence unreadable after verified ingest: {exc}")
                continue
            if actual != expected:
                errors.append(f"evidence changed after verified ingest: {reference}")
    return errors


def audit_training_errors(record: Any) -> list[str]:
    errors = audit_record_errors(record)
    if not isinstance(record, dict):
        return errors
    verdict = record.get("verdict")
    if isinstance(verdict, dict) and verdict.get("schema") != VERDICT_SCHEMA:
        errors.append("legacy verdict schema has unverified review depth/order")
    return errors


def quarantine_stale(model: dict[str, Any]) -> list[str]:
    moved: list[str] = []
    for episode_id, record in list(model["audits"].items()):
        reasons = audit_training_errors(record)
        if not reasons:
            continue
        model["quarantined_audits"][episode_id] = {
            "record": record,
            "reasons": reasons,
            "quarantined_at": now_utc(),
        }
        del model["audits"][episode_id]
        moved.append(episode_id)
    if moved:
        model["audit_count"] = len(model["audits"])
        model["updated_at"] = now_utc()
    return moved


def build_recommendation(model: dict[str, Any]) -> dict[str, Any]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    keep_by_workflow: dict[str, int] = defaultdict(int)
    historical_excluded = 0
    eligible_count = 0
    stale_or_invalid: dict[str, list[str]] = {}
    evidence_drift: dict[str, list[str]] = {}
    legacy_unverified: dict[str, list[str]] = {}
    targeted_remediation_excluded: list[str] = []
    aggregation_records = dict(model["audits"])
    retained_quarantined = 0
    for episode_id, item in model.get("quarantined_audits", {}).items():
        record = item.get("record") if isinstance(item, dict) else None
        if (
            episode_id not in aggregation_records
            and isinstance(record, dict)
            and not audit_record_errors(record)
            and isinstance(record.get("verdict"), dict)
            and record["verdict"].get("schema") == VERDICT_SCHEMA
        ):
            aggregation_records[episode_id] = record
            retained_quarantined += 1
    for episode_id, record in aggregation_records.items():
        record_errors = audit_record_errors(record)
        if record_errors:
            stale_or_invalid[episode_id] = record_errors
            continue
        verdict = record["verdict"]
        if verdict.get("schema") != VERDICT_SCHEMA:
            legacy_unverified[episode_id] = [
                "legacy verdict schema has unverified review depth/order"
            ]
            continue
        drift = audit_evidence_drift(record)
        if drift:
            evidence_drift[episode_id] = drift
        episode = record["episode"]
        if episode.get("review_scope") is not None:
            targeted_remediation_excluded.append(episode_id)
            continue
        if episode["origin"] not in TRAINING_ORIGINS:
            historical_excluded += 1
            continue
        eligible_count += 1
        if verdict["classification"] == "KEEP":
            keep_by_workflow[episode["workflow"]] += 1
        if verdict["classification"] not in {"PROCESS_DEFECT", "MANUAL_STOP_VALIDATED"}:
            continue
        pattern = verdict.get("process_pattern_id")
        if not pattern:
            continue
        for target in process_targets(verdict):
            groups[(pattern, target)].append(record)
    candidates: list[dict[str, Any]] = []
    for (pattern, target), records in sorted(groups.items()):
        incident_ids = {
            incident_key(record["episode"], aggregation_records) for record in records
        }
        blocker = any(record["verdict"]["severity"] == "blocker" for record in records)
        if len(incident_ids) < MIN_PATTERN_COHORT and not blocker:
            continue
        workflows = sorted({record["episode"]["workflow"] for record in records})
        candidates.append(
            {
                "kind": "urgent-human-review" if blocker else "policy-change-replay",
                "process_pattern_id": pattern,
                "target_skill": target,
                "eligible_episode_ids": sorted(
                    record["episode"]["episode_id"] for record in records
                ),
                "eligible_count": len(incident_ids),
                "eligible_episode_count": len(records),
                "independent_incident_ids": sorted(incident_ids),
                "keep_observations_same_workflows": sum(
                    keep_by_workflow[workflow] for workflow in workflows
                ),
                "workflows": workflows,
                "auto_apply": False,
                "human_approval_required": True,
                "frozen_replay_required": True,
                "rollback_required": True,
                "assurance_change": False,
                "gate_removal": False,
            }
        )
    return {
        "schema": SHADOW_SCHEMA,
        "project_root": model["project_root"],
        "project_key": model["project_key"],
        "status": "shadow_candidates" if candidates else "baseline_retained",
        "audit_count": model["audit_count"],
        "training_eligible_count": eligible_count,
        "historical_biased_excluded": historical_excluded,
        "stale_or_invalid_audits": stale_or_invalid,
        "evidence_drift_audits": evidence_drift,
        "legacy_unverified_audits": legacy_unverified,
        "targeted_remediation_excluded": sorted(targeted_remediation_excluded),
        "quarantined_audit_count": len(model.get("quarantined_audits", {})),
        "retained_quarantined_observations": retained_quarantined,
        "keep_observations": dict(sorted(keep_by_workflow.items())),
        "candidates": candidates,
        "auto_apply": False,
        "generated_at": now_utc(),
    }


def state_root() -> Path:
    configured = os.environ.get("PROCESS_AUDITOR_STATE_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path.home().resolve() / ".local" / "state" / "process-auditor" / "hooks"


@contextlib.contextmanager
def file_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = path.with_suffix(".lock")
    descriptor = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def ack_hook(
    state_path: Path,
    episode: dict[str, Any],
    verdict: dict[str, Any],
    *,
    generation: int,
) -> None:
    root = state_root()
    resolved = state_path.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AuditError(f"Hook state must be inside {root}") from exc
    errors = validate_verdict(episode, verdict, verify_evidence=True)
    if errors:
        raise AuditError("Cannot acknowledge invalid audit: " + "; ".join(errors))
    with file_lock(resolved):
        state = read_json(resolved)
        state_errors = validate_hook_state(state)
        if state_errors:
            raise AuditError("Invalid hook state: " + "; ".join(state_errors))
        if episode.get("project_root") != state.get("session_cwd"):
            raise AuditError("Audit project_root does not match hook session_cwd")
        if episode.get("author_run_id") != state.get("session_identity"):
            raise AuditError("Audit author_run_id does not match hook session identity")
        interruption_status = state.get("interruption_status")
        manual_stop_observed_at = state.get("manual_stop_observed_at")
        if interruption_status == "user_stopped":
            manual_stop = episode.get("manual_stop")
            if episode.get("outcome") != "user_stopped":
                raise AuditError(
                    "Hook user_stopped state requires a user_stopped audit episode"
                )
            if (
                not isinstance(manual_stop, dict)
                or manual_stop.get("at") != manual_stop_observed_at
            ):
                raise AuditError(
                    "Audit manual_stop.at does not match hook manual_stop_observed_at"
                )
        elif episode.get("outcome") == "user_stopped":
            raise AuditError("Hook state does not contain a matching user_stopped interruption")
        current_generation = state.get("material_generation")
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
        ):
            raise AuditError("Acknowledged generation must be a positive integer")
        if not isinstance(current_generation, int) or current_generation < 1:
            raise AuditError("Hook state has no material generation")
        if generation != current_generation:
            raise AuditError(
                "Hook material generation changed after audit episode was prepared"
            )
        state["audited_generation"] = current_generation
        state["audit_receipt"] = {
            "episode_id": episode["episode_id"],
            "episode_fingerprint": episode["fingerprint"],
            "verdict_fingerprint": verdict["fingerprint"],
            "material_generation": current_generation,
            "acknowledged_at": now_utc(),
        }
        atomic_json(resolved, state)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    episode = subparsers.add_parser("episode", help="Create an immutable process episode")
    episode.add_argument("--episode-id", required=True)
    episode.add_argument("--work-item-id", required=True)
    episode.add_argument("--parent-episode-id")
    episode.add_argument("--project-root", required=True)
    episode.add_argument("--workflow", required=True)
    episode.add_argument("--outcome", choices=sorted(OUTCOMES), required=True)
    episode.add_argument("--origin", choices=sorted(ORIGINS), required=True)
    episode.add_argument("--author-run-id", required=True)
    episode.add_argument("--skill", action="append", required=True)
    episode.add_argument("--evidence-file", type=Path, action="append", required=True)
    episode.add_argument("--signal", choices=sorted(SIGNALS), action="append", default=[])
    episode.add_argument("--started-at")
    episode.add_argument("--ended-at")
    episode.add_argument("--manual-stop-at")
    episode.add_argument("--manual-stop-reason")
    episode.add_argument("--depth", choices=("routine", "deep"))
    episode.add_argument("--write", type=Path, required=True)

    remediation = subparsers.add_parser(
        "remediation-episode",
        help="Create one finding-bound targeted remediation recheck",
    )
    remediation.add_argument("--episode-id", required=True)
    remediation.add_argument("--source-episode", type=Path, required=True)
    remediation.add_argument("--source-verdict", type=Path, required=True)
    remediation.add_argument("--finding-index", type=int, action="append", required=True)
    remediation.add_argument("--author-run-id", required=True)
    remediation.add_argument("--skill", action="append", required=True)
    remediation.add_argument("--evidence-file", type=Path, action="append", required=True)
    remediation.add_argument("--write", type=Path, required=True)

    validate_episode_parser = subparsers.add_parser("validate-episode")
    validate_episode_parser.add_argument("--episode", type=Path, required=True)

    seal = subparsers.add_parser("seal-verdict", help="Bind an independent verdict draft")
    seal.add_argument("--episode", type=Path, required=True)
    seal.add_argument("--draft", type=Path, required=True)
    seal.add_argument("--write", type=Path, required=True)

    validate = subparsers.add_parser("validate-verdict")
    validate.add_argument("--episode", type=Path, required=True)
    validate.add_argument("--verdict", type=Path, required=True)

    update = subparsers.add_parser("update", help="Add a validated audit to project history")
    update.add_argument("--episode", type=Path, required=True)
    update.add_argument("--verdict", type=Path, required=True)
    update.add_argument("--model", type=Path)
    update.add_argument("--replace", action="store_true")

    recommend = subparsers.add_parser("recommend", help="Build shadow process candidates")
    recommend.add_argument("--project-root", required=True)
    recommend.add_argument("--model", type=Path)
    recommend.add_argument("--write", type=Path, required=True)

    validate_model_parser = subparsers.add_parser("validate-model")
    validate_model_parser.add_argument("--project-root", required=True)
    validate_model_parser.add_argument("--model", type=Path)

    quarantine = subparsers.add_parser("quarantine-stale")
    quarantine.add_argument("--project-root", required=True)
    quarantine.add_argument("--model", type=Path)

    ack = subparsers.add_parser("ack-hook", help="Close one material hook generation")
    ack.add_argument("--state", type=Path, required=True)
    ack.add_argument("--generation", type=int, required=True)
    ack.add_argument("--episode", type=Path, required=True)
    ack.add_argument("--verdict", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "episode":
            payload = build_episode(
                episode_id=args.episode_id,
                work_item_id=args.work_item_id,
                parent_episode_id=args.parent_episode_id,
                project_root=args.project_root,
                workflow=args.workflow,
                outcome=args.outcome,
                origin=args.origin,
                author_run_id=args.author_run_id,
                skills=args.skill,
                evidence_paths=args.evidence_file,
                signals=args.signal,
                started_at=args.started_at,
                ended_at=args.ended_at,
                manual_stop_at=args.manual_stop_at,
                manual_stop_reason=args.manual_stop_reason,
                depth=args.depth,
            )
            atomic_json(args.write.expanduser().resolve(), payload)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0
        if args.command == "remediation-episode":
            payload = build_remediation_episode(
                episode_id=args.episode_id,
                source_episode_path=args.source_episode,
                source_verdict_path=args.source_verdict,
                finding_indices=args.finding_index,
                author_run_id=args.author_run_id,
                skills=args.skill,
                evidence_paths=args.evidence_file,
            )
            atomic_json(args.write.expanduser().resolve(), payload)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0
        if args.command == "validate-episode":
            errors = validate_episode(read_json(args.episode), verify_evidence=True)
            if errors:
                raise AuditError("; ".join(errors))
            print("PASS episode")
            return 0
        if args.command == "seal-verdict":
            episode = read_json(args.episode)
            errors = validate_episode(episode, verify_evidence=True)
            if errors:
                raise AuditError("Invalid episode: " + "; ".join(errors))
            verdict = seal_verdict(episode, read_json(args.draft))
            atomic_json(args.write.expanduser().resolve(), verdict)
            print(json.dumps(verdict, ensure_ascii=False, indent=2))
            return 0
        if args.command == "validate-verdict":
            errors = validate_verdict(
                read_json(args.episode), read_json(args.verdict), verify_evidence=True
            )
            if errors:
                raise AuditError("; ".join(errors))
            print("PASS verdict")
            return 0
        if args.command == "update":
            episode, verdict = read_json(args.episode), read_json(args.verdict)
            root = episode.get("project_root") if isinstance(episode, dict) else None
            if not isinstance(root, str):
                raise AuditError("Episode has no project_root")
            model_path = args.model or default_model_path(root)
            model_path = model_path.expanduser().resolve()
            with file_lock(model_path):
                model = load_model(model_path, project_root=root)
                changed = update_model(model, episode, verdict, replace=args.replace)
                if changed:
                    atomic_json(model_path, model)
            print(
                json.dumps(
                    {"changed": changed, "audit_count": model["audit_count"], "model": str(model_path)},
                    ensure_ascii=False,
                )
            )
            return 0
        if args.command == "recommend":
            model_path = args.model or default_model_path(args.project_root)
            model = load_model(model_path.expanduser().resolve(), project_root=args.project_root)
            result = build_recommendation(model)
            atomic_json(args.write.expanduser().resolve(), result)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "validate-model":
            model_path = args.model or default_model_path(args.project_root)
            model = load_model(model_path.expanduser().resolve(), project_root=args.project_root)
            errors = validate_model(model, project_root=args.project_root, verify_evidence=False)
            if errors:
                raise AuditError("; ".join(errors))
            invalid = {
                episode_id: audit_training_errors(record)
                for episode_id, record in model["audits"].items()
                if audit_training_errors(record)
            }
            drift = {
                episode_id: audit_evidence_drift(record)
                for episode_id, record in model["audits"].items()
                if audit_evidence_drift(record)
            }
            print(
                f"PASS audit-model audits={model['audit_count']} "
                f"invalid={len(invalid)} drift={len(drift)} "
                f"quarantined={len(model['quarantined_audits'])}"
            )
            return 0
        if args.command == "quarantine-stale":
            model_path = args.model or default_model_path(args.project_root)
            model_path = model_path.expanduser().resolve()
            with file_lock(model_path):
                model = load_model(model_path, project_root=args.project_root)
                moved = quarantine_stale(model)
                if moved:
                    atomic_json(model_path, model)
            print(json.dumps({"quarantined": moved, "model": str(model_path)}))
            return 0
        if args.command == "ack-hook":
            ack_hook(
                args.state,
                read_json(args.episode),
                read_json(args.verdict),
                generation=args.generation,
            )
            print("PASS hook acknowledged")
            return 0
        raise AuditError(f"Unknown command: {args.command}")
    except AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
