#!/usr/bin/env python3
"""Create a sanitized read-back receipt for Process Auditor discovery and hooks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


EVENTS = (
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "UserPromptSubmit",
)
SKILL_ROOT = Path(__file__).resolve().parents[1]
HOOK_SCRIPT = SKILL_ROOT / "scripts" / "process_audit_hook.py"


class InstallationError(RuntimeError):
    """Installation cannot be proven from local configuration."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallationError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise InstallationError(f"{path} must contain a JSON object")
    return payload


def event_commands(payload: dict[str, Any], event: str) -> list[str]:
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return []
    groups = hooks.get(event)
    if not isinstance(groups, list):
        return []
    commands: list[str] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            continue
        for hook in group["hooks"]:
            if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                commands.append(hook["command"])
    return commands


def verify(
    *,
    codex_hooks: Path,
    claude_settings: Path,
    agents_link: Path,
    claude_link: Path,
) -> dict[str, Any]:
    codex = read_json(codex_hooks)
    claude = read_json(claude_settings)
    expected = {
        "codex": f"python3 {HOOK_SCRIPT} --harness codex",
        "claude": f"python3 {HOOK_SCRIPT} --harness claude",
    }
    event_receipts: dict[str, dict[str, bool]] = {}
    for harness, payload in (("codex", codex), ("claude", claude)):
        event_receipts[harness] = {
            event: expected[harness] in event_commands(payload, event) for event in EVENTS
        }
    links = {
        "agents": {
            "path": str(agents_link),
            "is_symlink": agents_link.is_symlink(),
            "target": str(agents_link.resolve()) if agents_link.exists() else None,
        },
        "claude": {
            "path": str(claude_link),
            "is_symlink": claude_link.is_symlink(),
            "target": str(claude_link.resolve()) if claude_link.exists() else None,
        },
    }
    links_ok = all(
        item["is_symlink"] and item["target"] == str(SKILL_ROOT.resolve())
        for item in links.values()
    )
    hooks_ok = all(value for events in event_receipts.values() for value in events.values())
    return {
        "schema": 1,
        "skill_root": str(SKILL_ROOT.resolve()),
        "hooks": event_receipts,
        "discovery_links": links,
        "hooks_complete": hooks_ok,
        "links_complete": links_ok,
        "status": "complete" if hooks_ok and links_ok else "partial",
    }


def main() -> int:
    home = Path.home()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-hooks", type=Path, default=home / ".codex" / "hooks.json")
    parser.add_argument(
        "--claude-settings",
        type=Path,
        default=home / ".claude" / "settings.json",
    )
    parser.add_argument(
        "--agents-link",
        type=Path,
        default=home / ".agents" / "skills" / "process-auditor",
    )
    parser.add_argument(
        "--claude-link",
        type=Path,
        default=home / ".claude" / "skills" / "process-auditor",
    )
    parser.add_argument("--write", type=Path)
    args = parser.parse_args()
    try:
        result = verify(
            codex_hooks=args.codex_hooks.expanduser().resolve(),
            claude_settings=args.claude_settings.expanduser().resolve(),
            agents_link=args.agents_link.expanduser(),
            claude_link=args.claude_link.expanduser(),
        )
        rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.write:
            destination = args.write.expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(destination.suffix + ".tmp")
            temporary.write_text(rendered, encoding="utf-8")
            temporary.replace(destination)
        print(rendered, end="")
        return 0 if result["status"] == "complete" else 2
    except InstallationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
