"""Static pipeline for JavaScript / web-client bundles.

Beautifies minified/bundled JS and pulls out API endpoints, hardcoded
secrets-looking strings, and a rough obfuscation-style guess. This is static
text analysis only — nothing here is ever eval'd or executed.
"""
import re
from pathlib import Path

_URL_RE = re.compile(r"""https?://[^\s"'<>\\]{4,300}""")
_ENDPOINT_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-/{}.]{3,100})["']""")
_SECRET_RE = re.compile(
    r"""(api[_-]?key|secret|token|bearer|password|aws_access_key_id|private_key)\s*[:=]\s*["'][^"']{4,100}["']""",
    re.IGNORECASE,
)

_OBFUSCATION_HINTS = [
    (re.compile(r"_0x[0-9a-f]{4,}"), "hex-named identifiers (common JS-obfuscator output)"),
    (re.compile(r"\\x[0-9a-f]{2}"), "hex-escaped string literals"),
    (re.compile(r"eval\s*\("), "use of eval()"),
    (re.compile(r"String\.fromCharCode"), "String.fromCharCode-based string reconstruction"),
    (re.compile(r"webpackJsonp|__webpack_require__"), "webpack bundle"),
]


def _beautify(src: str) -> tuple[str, list[str]]:
    notes = []
    try:
        import jsbeautifier
        beautified = jsbeautifier.beautify(src)
        return beautified, notes
    except ImportError:
        notes.append("jsbeautifier not installed (pip install -r requirements.txt) — showing raw source.")
        return src, notes


def run(path: str) -> dict:
    p = Path(path)
    src = p.read_text(errors="replace")
    evidence: dict = {"pipeline": "web_js", "notes": [], "size_bytes": len(src.encode())}

    avg_line_len = (len(src) / max(src.count("\n"), 1))
    evidence["likely_minified"] = avg_line_len > 300

    beautified, notes = _beautify(src)
    evidence["notes"].extend(notes)

    evidence["urls"] = sorted(set(_URL_RE.findall(beautified)))[:80]
    evidence["possible_api_endpoints"] = sorted(set(_ENDPOINT_RE.findall(beautified)))[:80]
    evidence["possible_secrets"] = _SECRET_RE.findall(beautified)[:30]
    evidence["note_on_secrets"] = ("Keyword/pattern matches only, not verified secrets — "
                                   "confirm manually before treating as real credentials.")

    hints = [desc for pattern, desc in _OBFUSCATION_HINTS if pattern.search(src)]
    evidence["obfuscation_indicators"] = hints

    evidence["beautified_preview"] = beautified[:4000]

    return evidence
