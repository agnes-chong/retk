"""Figure out what kind of thing we were handed, and which pipeline should run."""
import zipfile
from pathlib import Path

from . import tools

KIND_NATIVE_PE = "native_pe"
KIND_NATIVE_ELF = "native_elf"
KIND_NATIVE_MACHO = "native_macho"
KIND_ANDROID_APK = "android_apk"
KIND_IOS_IPA = "ios_ipa"
KIND_JAVA_JAR = "java_jar"
KIND_WEB_JS = "web_js"
KIND_SCRIPT = "script"
KIND_UNKNOWN = "unknown"

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # 64-bit
}


def _zip_kind(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return KIND_UNKNOWN

    if "AndroidManifest.xml" in names:
        return KIND_ANDROID_APK
    if any(n.startswith("Payload/") and n.endswith(".app/Info.plist") for n in names):
        return KIND_IOS_IPA
    if "META-INF/MANIFEST.MF" in names:
        return KIND_JAVA_JAR
    return KIND_UNKNOWN


def identify(path: str) -> dict:
    p = Path(path)
    result = {"path": str(p), "kind": KIND_UNKNOWN, "file_magic": None}

    if not p.is_file():
        result["kind"] = KIND_UNKNOWN
        result["error"] = "not a regular file"
        return result

    if tools.have("file"):
        out = tools.run(["file", "-b", str(p)])
        if out["ok"]:
            result["file_magic"] = out["stdout"].strip()

    head = p.open("rb").read(8)

    if head[:2] == b"MZ":
        result["kind"] = KIND_NATIVE_PE
    elif head[:4] == b"\x7fELF":
        result["kind"] = KIND_NATIVE_ELF
    elif head[:4] in _MACHO_MAGICS or head[:4] == b"\xca\xfe\xba\xbe":
        # 0xcafebabe is shared between Mach-O fat binaries and Java .class files;
        # Java class files are not zip-wrapped so zip detection below won't catch them,
        # but they're rare as standalone "applications" so we just call it Mach-O here.
        result["kind"] = KIND_NATIVE_MACHO
    elif head[:2] == b"PK":
        result["kind"] = _zip_kind(p)
    elif p.suffix.lower() in (".js", ".mjs", ".cjs"):
        result["kind"] = KIND_WEB_JS
    elif p.suffix.lower() in (".py", ".sh", ".ps1", ".rb", ".pl"):
        result["kind"] = KIND_SCRIPT

    return result
