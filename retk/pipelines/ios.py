"""Best-effort static pipeline for iOS .ipa files.

Full Mach-O decompilation (class-dump, otool -ObjC, Hopper/Ghidra with the
right loaders) really wants macOS tooling. On Linux/WSL/Windows we can still
pull a lot of useful signal straight out of the zip/plist/strings, which is
what this module does — it's explicitly a reduced-fidelity pipeline, not a
full decompile, and says so in its own output.
"""
import plistlib
import re
import zipfile
from pathlib import Path

_URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,200}")


def _find_info_plist(zf: zipfile.ZipFile) -> str | None:
    for name in zf.namelist():
        if name.startswith("Payload/") and name.endswith(".app/Info.plist"):
            return name
    return None


def run(path: str) -> dict:
    p = Path(path)
    evidence: dict = {
        "pipeline": "ios",
        "notes": [
            "Full Mach-O decompilation (class-dump / otool -ObjC) needs macOS tooling and "
            "is not available on this platform. This pipeline extracts what it can from the "
            "IPA's zip/plist structure and raw strings instead — treat it as reconnaissance, "
            "not a full reverse engineering of the binary's logic."
        ],
    }

    try:
        with zipfile.ZipFile(p) as zf:
            plist_name = _find_info_plist(zf)
            if not plist_name:
                evidence["error"] = "No Payload/*.app/Info.plist found — not a valid IPA?"
                return evidence

            with zf.open(plist_name) as fh:
                try:
                    info = plistlib.load(fh)
                except Exception as e:
                    evidence["error"] = f"Failed to parse Info.plist: {e}"
                    info = {}

            app_dir = plist_name.rsplit("/", 1)[0]
            binary_name = info.get("CFBundleExecutable")
            binary_data = b""
            if binary_name:
                binary_path = f"{app_dir}/{binary_name}"
                if binary_path in zf.namelist():
                    binary_data = zf.read(binary_path)

            urls = sorted(set(m.decode(errors="replace") for m in _URL_RE.findall(binary_data)))

            evidence["bundle_id"] = info.get("CFBundleIdentifier")
            evidence["app_name"] = info.get("CFBundleDisplayName") or info.get("CFBundleName")
            evidence["version"] = info.get("CFBundleShortVersionString")
            evidence["min_ios_version"] = info.get("MinimumOSVersion")
            evidence["permissions_usage_strings"] = {
                k: v for k, v in info.items() if k.endswith("UsageDescription")
            }
            evidence["urls_in_binary_strings"] = urls[:50]
            evidence["all_zip_entries_sample"] = zf.namelist()[:50]
    except zipfile.BadZipFile:
        evidence["error"] = "Not a valid zip/IPA file."

    return evidence
