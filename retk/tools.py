"""Subprocess + optional-tool helpers.

Every external tool is optional: if it's missing, the pipeline notes the gap
in the report and keeps going instead of crashing. This is what lets retk
run on a bare install and still produce useful output.
"""
import shutil
import subprocess


def which(name: str) -> str | None:
    return shutil.which(name)


def have(name: str) -> bool:
    return which(name) is not None


def run(cmd: list[str], timeout: int = 120) -> dict:
    """Run a command, always returning a dict instead of raising.

    Callers can rely on ["ok"] rather than wrapping every call in try/except.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "cmd": cmd,
        }
    except FileNotFoundError:
        return {"ok": False, "error": f"'{cmd[0]}' not installed", "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"'{cmd[0]}' timed out after {timeout}s", "cmd": cmd}


def missing_tools_note(required: list[str]) -> list[str]:
    """Return a list of human-readable notes for any tool in `required` that's absent."""
    notes = []
    for tool in required:
        if not have(tool):
            notes.append(f"'{tool}' not found on PATH — see setup.sh / README for install instructions.")
    return notes
