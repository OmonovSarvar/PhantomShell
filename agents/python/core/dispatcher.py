import logging

log = logging.getLogger("phantom.core.dispatcher")


class Dispatcher:
    """Routes commands to registered module handlers."""

    def __init__(self):
        self._commands: dict[str, dict] = {}
        self._modules: dict[str, object] = {}

    def register_module(self, module) -> int:
        """Register a module's commands. Returns number of commands registered."""
        name = getattr(module, "NAME", "unknown")
        commands = getattr(module, "COMMANDS", {})
        count = 0
        for cmd_name, cmd_info in commands.items():
            self._commands[cmd_name] = {
                "handler": cmd_info["handler"],
                "description": cmd_info.get("description", ""),
                "module": name,
            }
            count += 1
        self._modules[name] = module
        log.debug(f"Registered module '{name}' with {count} commands")
        return count

    def dispatch(self, command: str, args: dict | None = None) -> dict:
        """Route command to handler. Returns structured response."""
        if command not in self._commands:
            return {"status": "error", "error_code": 1, "output": f"Unknown command: {command}"}
        try:
            handler = self._commands[command]["handler"]
            result = handler(**(args or {}))
            if isinstance(result, dict):
                return {"status": "ok", "data": result}
            return {"status": "ok", "output": str(result)}
        except TypeError as e:
            return {"status": "error", "error_code": 2, "output": f"Invalid arguments: {e}"}
        except PermissionError as e:
            return {"status": "error", "error_code": 3, "output": f"Permission denied: {e}"}
        except Exception as e:
            return {"status": "error", "error_code": 5, "output": f"Execution failed: {e}"}

    def list_commands(self) -> dict[str, str]:
        """Return {command: description} for all registered commands."""
        return {name: info["description"] for name, info in self._commands.items()}

    def has_command(self, command: str) -> bool:
        return command in self._commands

    @property
    def modules(self) -> list[str]:
        return list(self._modules.keys())
