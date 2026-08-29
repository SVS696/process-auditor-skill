#!/usr/bin/env python3
"""Quiet global hook requiring an independent audit after material workflow work."""

from __future__ import annotations

import ast
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from process_audit import validate_hook_state


STATE_SCHEMA = 1
SKILL_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SCRIPT = SKILL_ROOT / "scripts" / "process_audit.py"
CLI_CALLER_SCRIPT = (
    Path.home() / ".agents" / "skills" / "cli-agents" / "cli_caller.py"
).resolve()
MATERIAL_TOOL_PARTS = (
    "apply_patch",
    "edit",
    "write",
    "create",
    "delete",
    "move",
    "send_message",
    "handoff",
    "spawn_agent",
    "followup_task",
)
NEUTRAL_TOOL_NAMES = {
    "update_plan",
    "functions.update_plan",
    "get_goal",
    "functions.get_goal",
    "list_agents",
    "collaboration.list_agents",
    "list_threads",
    "mcp__codex_app__list_threads",
    "read_thread",
    "mcp__codex_app__read_thread",
    "wait_threads",
    "mcp__codex_app__wait_threads",
    "wait_agent",
    "collaboration.wait_agent",
    "view_image",
    "functions.view_image",
}
SHELL_CAPABLE_TOOL_NAMES = {
    "bash",
    "exec_command",
    "functions.exec_command",
    "shell",
    "write_stdin",
    "functions.write_stdin",
}
WRITE_STDIN_POLL_FIELDS = {"session_id", "chars", "yield_time_ms", "max_output_tokens"}
MUTATING_COMMAND_RE = re.compile(
    r"(?:^|[\n;&|]\s*)(?:(?:sudo|env)\s+)?(?:[a-z_][a-z0-9_]*=\S+\s+)*(?:"
    r"apply_patch\b|"
    r"git\s+(?:add|commit|push|merge|rebase|stash|cherry-pick|revert|reset|clean|"
    r"restore|worktree\s+(?:add|remove|move|prune)|switch\s+-c|checkout\s+-b|"
    r"branch\s+(?:-[dD]|--delete)|tag\s+(?:-[dD]|--delete))\b|"
    r"(?:cp|mv|rm|mkdir|touch|chmod|ln|truncate|install|patch|dd)\b|"
    r"sed\s+(?:-[A-Za-z]*i[A-Za-z]*|--in-place)\b|"
    r"perl\s+-[A-Za-z]*i[A-Za-z]*\b|"
    r"tee\b)"
)
GH_MUTATION_RE = re.compile(
    r"(?:^|[\n;&|]\s*)(?:(?:sudo|env)\s+)?(?:[a-z_][a-z0-9_]*=\S+\s+)*gh\s+"
    r"(?:(?:pr|issue|release|repo|gist|project|variable|secret)\s+"
    r"(?:create|merge|close|comment|edit|delete|reopen)|workflow\s+run|api\b[^\n]*"
    r"(?:-X|--method)\s*(?:POST|PUT|PATCH|DELETE))\b",
    re.IGNORECASE,
)
HTTP_MUTATION_RE = re.compile(
    r"(?:^|[\n;&|]\s*)(?:(?:sudo|env)\s+)?(?:[a-z_][a-z0-9_]*=\S+\s+)*(?:"
    r"curl\b[^\n]*(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b|"
    r"https?\b\s+(?:POST|PUT|PATCH|DELETE)\b)",
    re.IGNORECASE,
)
JS_CMD_LITERAL_RE = re.compile(
    r"\bcmd\s*:\s*(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
    re.DOTALL,
)
NESTED_TOOL_CALL_RE = re.compile(r"\btools\.([A-Za-z0-9_]+)\s*\(")
JS_IDENTIFIER_ESCAPE_RE = re.compile(
    r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]{1,6}\})|\\x[0-9a-fA-F]{2}"
)
DYNAMIC_JS_DISPATCH_RE = re.compile(
    r"\bglobalThis\b|\bReflect\s*\.|\beval\s*\(|\bFunction\s*\(|\.constructor\b"
)
READ_ONLY_TOOL_NAMES = {
    "glob",
    "grep",
    "get_goal",
    "functions.get_goal",
    "list_agents",
    "collaboration.list_agents",
    "list_archived_threads",
    "mcp__codex_app__list_archived_threads",
    "list_mcp_resource_templates",
    "functions.list_mcp_resource_templates",
    "list_mcp_resources",
    "functions.list_mcp_resources",
    "list_projects",
    "mcp__codex_app__list_projects",
    "list_threads",
    "mcp__codex_app__list_threads",
    "read",
    "read_mcp_resource",
    "functions.read_mcp_resource",
    "read_thread",
    "mcp__codex_app__read_thread",
    "read_thread_terminal",
    "mcp__codex_app__read_thread_terminal",
    "update_plan",
    "functions.update_plan",
    "view_image",
    "functions.view_image",
    "wait_agent",
    "collaboration.wait_agent",
    "wait_threads",
    "mcp__codex_app__wait_threads",
    "web__run",
    "web.run",
    "webfetch",
    "websearch",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_root() -> Path:
    configured = os.environ.get("PROCESS_AUDITOR_STATE_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path.home().resolve() / ".local" / "state" / "process-auditor" / "hooks"


def safe_component(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:24]


def event_cwd(event: Mapping[str, Any]) -> str:
    value = event.get("cwd") or event.get("working_directory") or os.getcwd()
    return str(Path(str(value)).expanduser().resolve())


def session_identity(event: Mapping[str, Any]) -> str:
    return str(
        event.get("session_id")
        or event.get("conversation_id")
        or event.get("transcript_path")
        or "unknown-session"
    )


def state_path(event: Mapping[str, Any], harness: str) -> Path:
    return state_root() / f"{safe_component('|'.join((harness, session_identity(event))))}.json"


@contextlib.contextmanager
def state_lock(path: Path) -> Iterable[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.with_suffix(".lock")
    descriptor = os.open(str(lock), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def empty_state(event: Mapping[str, Any], harness: str) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "harness": harness,
        "session_identity": session_identity(event),
        "session_identity_sha256": hashlib.sha256(
            session_identity(event).encode("utf-8", "replace")
        ).hexdigest(),
        "session_cwd": event_cwd(event),
        "prompt_generation": 1 if event.get("hook_event_name") == "UserPromptSubmit" else 0,
        "material_generation": 0,
        "audited_generation": 0,
        "material_reasons": [],
        "interruption_status": "none",
        "manual_stop_observed_at": None,
        "stop_gate_blocked": False,
        "stop_hook_bypass": False,
        "audit_receipt": None,
        "updated_at": now_utc(),
    }


def load_state(
    path: Path,
    event: Mapping[str, Any],
    harness: str,
) -> tuple[dict[str, Any], str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not valid_state(payload):
            raise ValueError("invalid state")
        return payload, "ok"
    except FileNotFoundError:
        return empty_state(event, harness), "missing"
    except (OSError, ValueError, json.JSONDecodeError):
        return empty_state(event, harness), "invalid"


def valid_state(payload: Any) -> bool:
    return not validate_hook_state(payload)


def save_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from strings(nested)


def tool_name(event: Mapping[str, Any]) -> str:
    for key in ("tool_name", "tool", "name"):
        value = event.get(key)
        if isinstance(value, str):
            return value.lower()
    return ""


def neutral_tool(name: str) -> bool:
    return name in NEUTRAL_TOOL_NAMES


def material_reason(event: Mapping[str, Any]) -> str | None:
    event_name = str(event.get("hook_event_name") or "")
    if event_name in {"SubagentStart", "SubagentStop", "AgentStart", "AgentStop"}:
        return "independent_or_delegated_run"
    if event_name not in {"PostToolUse", "PostToolUseFailure"}:
        return None
    name = tool_name(event)
    input_value = event.get("tool_input") or event.get("input") or {}
    exact_write_poll = tool_operation(name) == "write_stdin"
    if exact_write_poll and not write_stdin_poll_is_read_only(input_value):
        return "material_command"
    if neutral_tool(name):
        return None
    joined_raw = "\n".join(strings(input_value))
    joined = joined_raw.lower()
    if opaque_code_is_material(event):
        return "material_command"
    if not exact_write_poll and any(part in name for part in MATERIAL_TOOL_PARTS):
        return f"material_tool:{name or 'unknown'}"
    if "tools.apply_patch" in joined or "apply_patch(" in joined:
        return "material_command"
    if (
        MUTATING_COMMAND_RE.search(joined)
        or write_redirection(joined)
        or GH_MUTATION_RE.search(joined)
        or HTTP_MUTATION_RE.search(joined)
        or interpreter_mutation(joined_raw)
    ):
        return "material_command"
    commands, parse_complete = shell_command_texts(event, name)
    if not parse_complete and not exact_write_poll:
        return "material_command"
    if commands and any(not read_only_shell_command(command) for command in commands):
        return "material_command"
    if "exec_command" in joined and not commands:
        return "material_command"
    nested_names = nested_tool_names(event)
    if any(tool_operation(name) == "write_stdin" for name in nested_names) and nested_write_is_material(
        event
    ):
        return "material_command"
    if any(
        not shell_capable_tool(name)
        and not read_only_tool_name(name)
        for name in nested_names
    ):
        return "material_tool:nested"
    if shell_capable_tool(name) or name == "functions.exec":
        return None
    if not read_only_tool_name(name):
        return f"material_tool:{name or 'unknown'}"
    return None


def nested_tool_names(event: Mapping[str, Any]) -> list[str]:
    input_value = event.get("tool_input") or event.get("input") or {}
    names: list[str] = []
    for source in strings(input_value):
        names.extend(NESTED_TOOL_CALL_RE.findall(source))
    return list(dict.fromkeys(names))


def event_code_sources(event: Mapping[str, Any]) -> list[str]:
    input_value = event.get("tool_input") or event.get("input") or {}
    found: list[str] = []

    def collect(value: Any, *, field: str | None = None) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if isinstance(nested, str):
                    normalized = normalize_js_identifier_escapes(nested)
                    if key not in {"cmd", "command"} and (
                        re.search(r"\btools\b", normalized)
                        or DYNAMIC_JS_DISPATCH_RE.search(normalized)
                    ):
                        found.append(nested)
                else:
                    collect(nested, field=str(key))
        elif isinstance(value, list):
            for nested in value:
                collect(nested, field=field)
        elif isinstance(value, str) and field not in {"cmd", "command"}:
            normalized = normalize_js_identifier_escapes(value)
            if re.search(r"\btools\b", normalized) or DYNAMIC_JS_DISPATCH_RE.search(
                normalized
            ):
                found.append(value)

    collect(input_value)
    return list(dict.fromkeys(found))


def normalize_js_identifier_escapes(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.startswith("\\u{"):
            value = int(token[3:-1], 16)
        else:
            value = int(token[2:], 16)
        character = chr(value)
        if character.isascii() and (character.isalnum() or character in {"_", "$"}):
            return character
        return token

    return JS_IDENTIFIER_ESCAPE_RE.sub(replace, source)


def opaque_code_is_material(event: Mapping[str, Any]) -> bool:
    alias_patterns = (
        r"\btools\s*\[",
        r"\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*tools\b",
        r"\b(?:const|let|var)\s*\{[^}]+\}\s*=\s*tools\b",
    )
    for source in event_code_sources(event):
        normalized = normalize_js_identifier_escapes(source)
        if normalized != source and re.search(r"\btools\b", normalized):
            return True
        if DYNAMIC_JS_DISPATCH_RE.search(normalized):
            return True
        tool_references = len(re.findall(r"\btools\b", normalized))
        direct_calls = len(NESTED_TOOL_CALL_RE.findall(normalized))
        if tool_references != direct_calls:
            return True
        if any(re.search(pattern, normalized, re.DOTALL) for pattern in alias_patterns):
            return True
        references = len(re.findall(r"\bwrite_stdin\b", normalized))
        exact = len(re.findall(r"\btools\.write_stdin\b", normalized))
        if references != exact:
            return True
    return False


def mapping_values(value: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, Mapping):
        for current_key, nested in value.items():
            if current_key == key:
                found.append(nested)
            else:
                found.extend(mapping_values(nested, key))
    elif isinstance(value, list):
        for nested in value:
            found.extend(mapping_values(nested, key))
    return found


def write_stdin_poll_is_read_only(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if set(value) - WRITE_STDIN_POLL_FIELDS:
        return False
    chars_values = mapping_values(value, "chars")
    return len(chars_values) == 1 and chars_values[0] == ""


def js_call_arguments(source: str, function_name: str) -> list[str] | None:
    marker = f"tools.{function_name}"
    calls: list[str] = []
    offset = 0
    while True:
        start = source.find(marker, offset)
        if start < 0:
            return calls
        cursor = start + len(marker)
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != "(":
            return None
        argument_start = cursor + 1
        depth = 1
        quote: str | None = None
        escaped = False
        cursor += 1
        while cursor < len(source):
            character = source[cursor]
            if quote is not None:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
            elif character in {"'", '"', "`"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    calls.append(source[argument_start:cursor])
                    offset = cursor + 1
                    break
            cursor += 1
        else:
            return None


def nested_write_is_material(event: Mapping[str, Any]) -> bool:
    input_value = event.get("tool_input") or event.get("input") or {}
    for source in strings(input_value):
        if "write_stdin" not in source:
            continue
        calls = js_call_arguments(source, "write_stdin")
        if calls is None or not calls:
            return True
        for call in calls:
            stripped = call.strip()
            if not (stripped.startswith("{") and stripped.endswith("}")) or "..." in stripped:
                return True
            labels = len(re.findall(r"\bchars\s*:", call))
            if labels != 1:
                return True
            chars = re.search(
                r"\bchars\s*:\s*(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
                call,
                re.DOTALL,
            )
            if chars is None:
                return True
            remainder = call[chars.end() :].lstrip()
            if not remainder.startswith((",", "}")):
                return True
            try:
                value = ast.literal_eval(chars.group(1))
            except (SyntaxError, ValueError):
                return True
            if value:
                return True
    return False


def read_only_tool_name(name: str) -> bool:
    return name in READ_ONLY_TOOL_NAMES


def tool_operation(name: str) -> str:
    return name.split("__")[-1].split(".")[-1]


def shell_capable_tool(name: str) -> bool:
    return name in SHELL_CAPABLE_TOOL_NAMES


def shell_command_texts(event: Mapping[str, Any], name: str) -> tuple[list[str], bool]:
    found: list[str] = []
    parse_complete = True

    def collect(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if key in {"cmd", "command"} and isinstance(nested, str):
                    found.append(nested)
                else:
                    collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)

    tool_input = event.get("tool_input") or event.get("input") or {}
    collect(tool_input)

    for source in event_code_sources(event):
        if "exec_command" not in source:
            continue
        labels = len(re.findall(r"\bcmd\s*:", source))
        matches = list(JS_CMD_LITERAL_RE.finditer(source))
        if labels != len(matches) or labels == 0:
            parse_complete = False
        for match in matches:
            try:
                literal = ast.literal_eval(match.group(1))
            except (SyntaxError, ValueError):
                parse_complete = False
                continue
            if isinstance(literal, str):
                found.append(literal)
    if not found and shell_capable_tool(name):
        parse_complete = False
    return list(dict.fromkeys(found)), parse_complete


def shell_segments(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>\n\r")
        lexer.whitespace = " \t"
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [command]
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token and all(character in ";&|\n\r" for character in token):
            if segments[-1]:
                segments.append([])
            continue
        segments[-1].append(token)
    return [" ".join(segment) for segment in segments if segment]


def write_redirection(command: str) -> bool:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>\n\r")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return ">" in command
    for index, token in enumerate(tokens):
        if ">" not in token or any(character not in ";&|<>\n\r" for character in token):
            continue
        target = tokens[index + 1] if index + 1 < len(tokens) else ""
        if target == "/dev/null":
            continue
        if token.endswith(">&") and target in {"1", "2"}:
            continue
        return True
    return False


def process_auditor_meta_cli_is_read_only(segment: str) -> bool:
    try:
        tokens = shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return False
    if not tokens or tokens[0] != "PROCESS_AUDITOR_META=1":
        return False
    if len(tokens) < 3 or Path(tokens[1]).name.lower() not in {"python", "python3"}:
        return False
    if Path(tokens[2]).expanduser().resolve() != CLI_CALLER_SCRIPT:
        return False
    options_with_value = {
        "--model",
        "--provider-model",
        "--prompt",
        "--systemprompt",
        "--timeout",
        "--idle-timeout",
        "--session",
        "--cwd",
        "--access",
    }
    flag_options = {"--stream", "--info"}
    access_values: list[str] = []
    index = 3
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--access="):
            access_values.append(token.split("=", 1)[1])
            index += 1
            continue
        if token in options_with_value:
            if index + 1 >= len(tokens):
                return False
            if token == "--access":
                access_values.append(tokens[index + 1])
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in options_with_value):
            index += 1
            continue
        if token in flag_options:
            index += 1
            continue
        return False
    return access_values == ["read-only"]


def interpreter_segment_mutation(segment: str) -> bool:
    tokens = command_tokens(segment)
    if not tokens or Path(tokens[0]).name.lower() not in {
        "python",
        "python3",
        "node",
        "ruby",
        "perl",
        "osascript",
    }:
        return False
    executable = Path(tokens[0]).name.lower()
    arguments = tokens[1:]
    read_only_modules = {"pytest", "unittest", "mypy", "pyright", "json.tool"}
    if (
        executable in {"python", "python3"}
        and len(arguments) >= 2
        and arguments[0] == "-m"
        and arguments[1] in read_only_modules
    ):
        if arguments[1] == "json.tool":
            return json_tool_writes_output(arguments[2:])
        return False
    if not arguments or arguments[0] in {"-c", "-m"}:
        return True
    option_only = {"-B", "-E", "-I", "-O", "-OO", "-q", "-s", "-S", "-u", "-v", "-V", "-x"}
    index = 0
    while index < len(arguments) and arguments[index] in option_only:
        index += 1
    executed_script = arguments[index] if index < len(arguments) else None
    if (
        executable in {"python", "python3"}
        and executed_script
        and Path(executed_script).name == "process_audit.py"
    ):
        return False
    if executable in {"python", "python3"} and process_auditor_meta_cli_is_read_only(
        segment
    ):
        return False
    if (
        executable in {"python", "python3"}
        and executed_script
        and Path(executed_script).suffix == ".py"
        and (
            Path(executed_script).name.startswith("test_")
            or Path(executed_script).name.endswith("_test.py")
        )
    ):
        return False
    return True


def json_tool_writes_output(arguments: list[str]) -> bool:
    positionals: list[str] = []
    index = 0
    flags = {
        "--sort-keys",
        "--no-ensure-ascii",
        "--json-lines",
        "--tab",
        "--no-indent",
        "--compact",
    }
    while index < len(arguments):
        token = arguments[index]
        if token == "--indent":
            if index + 1 >= len(arguments):
                return True
            index += 2
            continue
        if token.startswith("--indent=") or token in flags:
            index += 1
            continue
        if token == "--":
            positionals.extend(arguments[index + 1 :])
            break
        if token.startswith("-") and token != "-":
            return True
        positionals.append(token)
        index += 1
    return len(positionals) > 1


def interpreter_mutation(command: str) -> bool:
    return any(interpreter_segment_mutation(segment) for segment in shell_segments(command))


def command_tokens(segment: str) -> list[str]:
    try:
        tokens = shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return []
    while tokens and (
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0])
        or tokens[0] in {"env", "sudo", "command"}
    ):
        tokens.pop(0)
    return tokens


def git_subcommand(tokens: list[str]) -> tuple[str | None, list[str]]:
    index = 1
    options_with_value = {"-C", "--git-dir", "--work-tree", "-c"}
    while index < len(tokens) and tokens[index].startswith("-"):
        raw_option = tokens[index]
        option = raw_option.split("=", 1)[0]
        index += 2 if option in options_with_value and "=" not in raw_option else 1
    if index >= len(tokens):
        return None, []
    return tokens[index], tokens[index + 1 :]


def sort_writes_output(tokens: list[str]) -> bool:
    options_with_attached_value = {"k", "S", "T", "t"}
    for token in tokens[1:]:
        if token in {"-o", "--output"} or token.startswith("--output="):
            return True
        if not token.startswith("-") or token.startswith("--"):
            continue
        for option in token[1:]:
            if option == "o":
                return True
            if option in options_with_attached_value:
                break
    return False


def sed_scripts(tokens: list[str]) -> list[str] | None:
    scripts: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-e", "--expression"}:
            if index + 1 >= len(tokens):
                return None
            scripts.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--expression="):
            scripts.append(token.split("=", 1)[1])
            index += 1
            continue
        if token.startswith("-e") and token != "-e":
            scripts.append(token[2:])
            index += 1
            continue
        if token in {"-f", "--file"} or token.startswith("--file="):
            return None
        if token.startswith("-"):
            index += 1
            continue
        if not scripts:
            scripts.append(token)
        break
    return scripts


def sed_script_may_mutate(script: str) -> bool:
    commands = re.split(r"[;\n{}]", script)
    for command in commands:
        stripped = command.strip()
        if stripped in {"w", "e"}:
            return True
        if re.search(r"(?:^|[/,\s])w\s+\S", stripped):
            return True
        if re.search(r"(?:^|[/,\s])e(?:\s|$)", stripped):
            return True
    return False


def rg_may_execute_preprocessor(tokens: list[str]) -> bool:
    return any(
        token in {"--pre", "--pre-glob"}
        or token.startswith("--pre=")
        or token.startswith("--pre-glob=")
        for token in tokens[1:]
    )


def read_only_shell_segment(segment: str) -> bool:
    tokens = command_tokens(segment)
    if not tokens:
        return False
    executable = Path(tokens[0]).name.lower()
    if executable in {"python", "python3", "node", "ruby", "perl", "osascript"}:
        return not interpreter_segment_mutation(segment)
    if executable == "git":
        subcommand, rest = git_subcommand(tokens)
        if any(token == "--output" or token.startswith("--output=") for token in rest):
            return False
        if subcommand in {
            "status",
            "diff",
            "log",
            "show",
            "rev-parse",
            "ls-files",
            "ls-tree",
            "cat-file",
        }:
            return True
        if subcommand == "branch":
            return any(flag in rest for flag in {"--show-current", "--list", "-a", "-r"})
        if subcommand == "remote":
            return rest in (["-v"], ["--verbose"])
        return False
    if executable == "find":
        return not any(
            flag in tokens
            for flag in {
                "-delete",
                "-exec",
                "-execdir",
                "-ok",
                "-okdir",
                "-fprint",
                "-fprintf",
                "-fls",
            }
        )
    if executable == "sed":
        if any(
            token == "--in-place" or re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*", token)
            for token in tokens[1:]
        ):
            return False
        scripts = sed_scripts(tokens)
        return scripts is not None and not any(sed_script_may_mutate(script) for script in scripts)
    if executable == "ruff":
        if len(tokens) < 2 or tokens[1] not in {"check", "help", "version", "--version"}:
            return False
        return not any(
            token in {"--fix", "--fix-only", "--unsafe-fixes"}
            or token.startswith("--fix=")
            for token in tokens[1:]
        )
    if executable == "rg":
        return not rg_may_execute_preprocessor(tokens)
    if executable == "sort":
        return not sort_writes_output(tokens)
    return executable in {
        "[",
        "cat",
        "cd",
        "cut",
        "date",
        "df",
        "du",
        "echo",
        "file",
        "grep",
        "head",
        "jq",
        "ls",
        "mypy",
        "pgrep",
        "printf",
        "ps",
        "pwd",
        "pyright",
        "pytest",
        "readlink",
        "realpath",
        "rg",
        "sort",
        "stat",
        "sw_vers",
        "tail",
        "test",
        "true",
        "uname",
        "uniq",
        "wc",
        "which",
    }


def read_only_shell_command(command: str) -> bool:
    if any(marker in command for marker in ("$(", "`", "<(", ">(")):
        return False
    if write_redirection(command):
        return False
    segments = shell_segments(command)
    return bool(segments) and all(read_only_shell_segment(segment) for segment in segments)


def pending(state: Mapping[str, Any]) -> bool:
    material = state.get("material_generation")
    audited = state.get("audited_generation")
    return isinstance(material, int) and isinstance(audited, int) and material > audited


def prompt_context(path: Path, state: Mapping[str, Any]) -> dict[str, Any]:
    status = state.get("interruption_status")
    if status == "user_stopped":
        stop_kind = "user_stopped"
        boundary = "Ручная остановка не разрешает автоматически возобновлять исходную работу."
    else:
        stop_kind = "blocked_or_evidence_gap"
        boundary = (
            "Причина незакрытого аудита не доказана как ручная остановка; не фабрикуй "
            "user_stopped и не возобновляй исходную работу без разбора."
        )
    text = (
        "Есть незакрытый независимый process audit предыдущего material workflow. "
        f"Предварительный outcome={stop_kind}. {boundary} "
        "Сначала используй $process-auditor, затем выполни "
        f"ack-hook для state {path}."
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": text,
        }
    }


def stop_block(path: Path, state: Mapping[str, Any]) -> dict[str, str]:
    outcome = (
        "user_stopped"
        if state.get("interruption_status") == "user_stopped"
        else "completed|blocked|evidence_gap"
    )
    reason = (
        "Перед финальным ответом обязателен независимый $process-auditor для material workflow. "
        f"Зафиксируй episode с outcome={outcome}; при user_stopped сохрани "
        "resume_authority=user_only и не продолжай исходную работу. Получи evidence-only verdict "
        "от reviewer, который не участвовал в прогоне, проверь его и последним tool-call выполни: "
        f"python3 '{AUDIT_SCRIPT}' ack-hook --state '{path}' --episode '<episode.json>' "
        f"--verdict '<verdict.json>' --generation {state.get('material_generation')}. "
        "Episode author_run_id должен совпадать с session_identity "
        f"{state.get('session_identity')!r}, project_root — с session_cwd "
        f"{state.get('session_cwd')!r}. KEEP/no-change является допустимым результатом."
    )
    return {"decision": "block", "reason": reason}


def process_event(event: Mapping[str, Any], harness: str) -> dict[str, Any] | None:
    path = state_path(event, harness)
    with state_lock(path):
        state, state_status = load_state(path, event, harness)
        event_name = str(event.get("hook_event_name") or "")
        if event_name == "UserPromptSubmit":
            if state_status == "invalid":
                state["material_generation"] = 1
                state["material_reasons"] = ["state_integrity_unknown"]
                state["interruption_status"] = "state_integrity_unknown"
                state["updated_at"] = now_utc()
                save_state(path, state)
                return prompt_context(path, state)
            if state_status == "missing":
                save_state(path, state)
                return None
            if pending(state):
                if state.get("stop_gate_blocked") or state.get("stop_hook_bypass"):
                    state["interruption_status"] = "audit_unclosed"
                else:
                    state["interruption_status"] = "user_stopped"
                    state["manual_stop_observed_at"] = now_utc()
                state["prompt_generation"] = int(state.get("prompt_generation", 0)) + 1
                state["updated_at"] = now_utc()
                save_state(path, state)
                return prompt_context(path, state)
            if not pending(state):
                state = empty_state(event, harness)
                save_state(path, state)
            return None
        reason = material_reason(event)
        if reason:
            state["material_generation"] = int(state.get("material_generation", 0)) + 1
            reasons = list(state.get("material_reasons") or [])
            if reason not in reasons:
                reasons.append(reason)
            state["material_reasons"] = reasons
            state["audit_receipt"] = None
            state["updated_at"] = now_utc()
            save_state(path, state)
            return None
        if event_name in {"Stop", "SessionEnd"}:
            if event.get("stop_hook_active"):
                if pending(state):
                    state["stop_hook_bypass"] = True
                    state["updated_at"] = now_utc()
                    save_state(path, state)
                return None
            if state_status in {"missing", "invalid"}:
                state["material_generation"] = 1
                state["material_reasons"] = [f"state_{state_status}"]
                state["interruption_status"] = "state_integrity_unknown"
                state["updated_at"] = now_utc()
                save_state(path, state)
                return stop_block(path, state)
            if pending(state):
                state["stop_gate_blocked"] = True
                state["updated_at"] = now_utc()
                save_state(path, state)
                return stop_block(path, state)
        return None


def main(argv: list[str] | None = None) -> int:
    harness = "codex"
    if argv:
        for index, item in enumerate(argv):
            if item == "--harness" and index + 1 < len(argv):
                harness = argv[index + 1]
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input must be an object")
        result = process_event(event, harness)
        if result is not None:
            sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Process Auditor hook: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
