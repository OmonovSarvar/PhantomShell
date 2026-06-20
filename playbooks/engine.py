"""PhantomShell v5.2 — YAML Playbook Engine

Executes sequential automation workflows defined in YAML.
Supports variable substitution, conditionals, loops, and step output storage.
"""

import json
import logging
import os
import re
import time
import yaml

log = logging.getLogger("phantom.playbook")


class PlaybookEngine:
    """Parse and execute YAML playbooks against an active agent session."""

    def __init__(self, session, dispatcher):
        self.session = session
        self.dispatcher = dispatcher
        self.variables = {}
        self.results = []

    def load(self, path: str) -> dict:
        with open(path) as f:
            playbook = yaml.safe_load(f)
        self._validate(playbook)
        return playbook

    def run(self, playbook: dict) -> list[dict]:
        name = playbook.get("name", "unnamed")
        log.info(f"Running playbook: {name}")
        self.variables = dict(playbook.get("vars", {}))
        self.variables["session_id"] = getattr(self.session, "session_id", "local")
        self.results = []

        for i, step in enumerate(playbook.get("steps", [])):
            step_name = step.get("name", f"step_{i}")
            log.info(f"[{i+1}/{len(playbook['steps'])}] {step_name}")

            if not self._check_condition(step.get("when")):
                log.info(f"  Skipped (condition not met)")
                self.results.append({"step": step_name, "status": "skipped"})
                continue

            loop_items = self._resolve_loop(step.get("loop"))
            if loop_items:
                for item in loop_items:
                    self.variables["item"] = item
                    result = self._execute_step(step)
                    self.results.append(result)
            else:
                result = self._execute_step(step)
                self.results.append(result)

            if step.get("store"):
                self.variables[step["store"]] = result.get("data", result.get("output", ""))

            if result.get("status") == "error" and step.get("fail_fast", True):
                log.error(f"  Step failed, aborting playbook")
                break

            if step.get("delay"):
                time.sleep(float(step["delay"]))

        return self.results

    def _execute_step(self, step: dict) -> dict:
        command = self._interpolate(step["command"])
        args = {}
        for k, v in step.get("args", {}).items():
            args[k] = self._interpolate(v) if isinstance(v, str) else v

        try:
            if self.dispatcher and self.dispatcher.has_command(command):
                result = self.dispatcher.dispatch(command, args)
            else:
                from core.executor import Executor
                ex = Executor()
                cmd_str = command + " " + " ".join(f"{v}" for v in args.values())
                stdout, stderr, code = ex.execute(cmd_str, timeout=step.get("timeout", 30))
                result = {"status": "ok" if code == 0 else "error", "output": stdout, "error": stderr}

            return {"step": step.get("name", ""), "status": result.get("status", "ok"), **result}
        except Exception as e:
            return {"step": step.get("name", ""), "status": "error", "output": str(e)}

    def _interpolate(self, value) -> str:
        if not isinstance(value, str):
            return value
        def replacer(match):
            expr = match.group(1).strip()
            parts = expr.split(".")
            obj = self.variables.get(parts[0])
            for part in parts[1:]:
                if isinstance(obj, dict):
                    obj = obj.get(part)
                elif isinstance(obj, list) and part.isdigit():
                    obj = obj[int(part)]
                else:
                    return match.group(0)
            return str(obj) if obj is not None else match.group(0)
        return re.sub(r"\{\{\s*(.+?)\s*\}\}", replacer, value)

    def _check_condition(self, condition) -> bool:
        if condition is None:
            return True
        expr = self._interpolate(condition)
        try:
            return bool(eval(expr, {"__builtins__": {}}, self.variables))
        except Exception:
            return False

    def _resolve_loop(self, loop_expr):
        if loop_expr is None:
            return None
        if isinstance(loop_expr, list):
            return loop_expr
        if isinstance(loop_expr, str):
            resolved = self._interpolate(loop_expr)
            val = self.variables.get(resolved.strip("{}").strip())
            if isinstance(val, list):
                return val
        return None

    def _validate(self, playbook: dict):
        if "steps" not in playbook:
            raise ValueError("Playbook must have 'steps'")
        for i, step in enumerate(playbook["steps"]):
            if "command" not in step:
                raise ValueError(f"Step {i} missing 'command'")

    def to_report(self) -> str:
        lines = ["# Playbook Execution Report", ""]
        for r in self.results:
            status_icon = "[+]" if r.get("status") == "ok" else "[-]" if r.get("status") == "error" else "[*]"
            lines.append(f"{status_icon} {r.get('step', 'unknown')}: {r.get('status', 'unknown')}")
            if r.get("output"):
                preview = str(r["output"])[:200]
                lines.append(f"    {preview}")
        return "\n".join(lines)
