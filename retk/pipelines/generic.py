"""Fallback pipeline for anything we couldn't confidently classify
(scripts, unrecognized binaries, JARs, etc.) — plain strings + URL/secret
scan so the tool still produces *something* useful instead of refusing."""
import re
from pathlib import Path

from .. import tools

_URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,300}")
_SECRET_RE = re.compile(
    rb"(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{4,100}[\"']",
    re.IGNORECASE,
)


def run(path: str) -> dict:
    p = Path(path)
    evidence: dict = {"pipeline": "generic_fallback", "notes": [
        "File type wasn't recognized as PE/ELF/Mach-O/APK/IPA/JS. Ran a generic "
        "strings + URL/secret scan. For a real analysis, inspect the file manually "
        "(e.g. `file`, `strings`, or open it in a hex editor / disassembler)."
    ]}

    data = p.read_bytes()
    evidence["size_bytes"] = len(data)
    evidence["urls"] = sorted(set(m.decode(errors="replace") for m in _URL_RE.findall(data)))[:50]
    evidence["possible_secrets"] = [m.decode(errors="replace") for m in _SECRET_RE.findall(data)][:30]

    strings_out = tools.run(["strings", "-n", "6", str(p)], timeout=60)
    if strings_out.get("ok"):
        evidence["string_sample"] = strings_out["stdout"].splitlines()[:60]

    return evidence
