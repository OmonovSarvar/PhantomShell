import os
import subprocess
import logging

log = logging.getLogger("phantom.core.executor")


class Executor:
    """Command execution engine with working directory tracking."""

    def __init__(self):
        self.cwd = os.getcwd()

    def execute(self, cmd: str, timeout: int = 30) -> tuple[str, str, int]:
        """Run a shell command. Returns (stdout, stderr, exit_code)."""
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=os.environ.copy()
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return "", "Command timed out", -1
        except Exception as e:
            log.error(f"Execution failed: {e}")
            return "", str(e), -1

    def cd(self, path: str) -> tuple[str, bool]:
        """Change working directory."""
        target = os.path.join(self.cwd, path) if not os.path.isabs(path) else path
        target = os.path.realpath(target)
        if os.path.isdir(target):
            self.cwd = target
            return target, True
        return f"Directory not found: {path}", False
