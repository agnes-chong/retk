"""Static-analysis pipeline for Android APKs.

Uses androguard (pure Python, no JDK/apktool/jadx required) so this works
out of the box. If `jadx` or `apktool` are on PATH, their output is also
pulled in since it's often more readable for manual follow-up.
"""
import re
from pathlib import Path

from .. import tools

_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,200}")
_SECRET_HINTS = re.compile(
    r"(api[_-]?key|secret|token|password|aws_access_key|private_key)",
    re.IGNORECASE,
)

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS", "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
}


def _androguard_info(path: Path) -> dict:
    try:
        from androguard.core.apk import APK
    except ImportError:
        return {"error": "androguard not installed (pip install -r requirements.txt)"}

    try:
        apk = APK(str(path))
    except Exception as e:
        return {"error": f"androguard failed to parse APK: {e}"}

    try:
        return _androguard_extract(apk)
    except Exception as e:
        return {"error": f"androguard parsed the APK container but failed reading its contents "
                          f"(often a sign of a corrupt/unusual manifest or a deliberately malformed "
                          f"APK): {e}"}


def _androguard_extract(apk) -> dict:
    perms = apk.get_permissions()
    dangerous = sorted(set(perms) & DANGEROUS_PERMISSIONS)

    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()

    strings_blob = []
    try:
        for dex in apk.get_all_dex():
            strings_blob.append(dex.decode(errors="ignore"))
    except Exception:
        pass
    joined = "\n".join(strings_blob)
    urls = sorted(set(_URL_RE.findall(joined)))[:50]
    secret_hits = sorted(set(m.group(0) for m in _SECRET_HINTS.finditer(joined)))[:30]

    return {
        "package": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "permissions": sorted(perms),
        "dangerous_permissions": dangerous,
        "activities": activities[:100],
        "services": services[:100],
        "receivers": receivers[:100],
        "is_signed": apk.is_signed_v1() or apk.is_signed_v2() or apk.is_signed_v3(),
        "urls_in_dex_strings": urls,
        "possible_secret_hints": secret_hits,
        "note_on_secret_hints": "These are string matches on keyword patterns (e.g. 'api_key'), "
                                 "not confirmed secrets, verify manually before treating as real.",
    }


def _jadx_decompile(path: Path, outdir: Path) -> dict:
    if not tools.have("jadx"):
        return {"note": "'jadx' not found, skipping Java-source decompile "
                         "(androguard output above still covers manifest/permissions/strings)."}
    jadx_out = outdir / "jadx"
    result = tools.run(["jadx", "-d", str(jadx_out), "--no-res", str(path)], timeout=180)
    return {
        "ok": result.get("ok", False),
        "output_dir": str(jadx_out) if result.get("ok") else None,
        "stderr_tail": (result.get("stderr") or "")[-1000:],
    }


def run(path: str, outdir: Path) -> dict:
    p = Path(path)
    evidence: dict = {"pipeline": "android", "notes": []}
    evidence["notes"].extend(tools.missing_tools_note(["jadx"]))

    evidence["manifest_and_strings"] = _androguard_info(p)
    evidence["jadx_decompile"] = _jadx_decompile(p, outdir)

    return evidence
