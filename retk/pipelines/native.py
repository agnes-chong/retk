"""Static-analysis pipeline for native PE / ELF / Mach-O binaries.

Everything here is read-only / static analysis — nothing in this module
executes the target binary.
"""
import math
import re
from collections import Counter
from pathlib import Path

from .. import tools

_URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,200}")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_WINPATH_RE = re.compile(rb"[A-Za-z]:\\\\[^\s\"'<>]{3,200}")
_SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
    "URLDownloadToFile", "WinExec", "ShellExecute", "CryptEncrypt", "CryptDecrypt",
    "RegSetValue", "InternetOpen", "socket", "connect", "ptrace", "fork", "execve",
    "dlopen", "mmap", "memfd_create",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_strings(path: Path, min_len: int = 6, limit: int = 20000) -> list[bytes]:
    out = tools.run(["strings", "-n", str(min_len), str(path)], timeout=60)
    if out.get("ok"):
        return [line.encode() for line in out["stdout"].splitlines()[:limit]]
    # Pure-Python fallback if the `strings` binary isn't available.
    data = path.read_bytes()
    found, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                found.append(bytes(cur))
            cur = bytearray()
    return found[:limit]


def _categorize_strings(strs: list[bytes]) -> dict:
    blob = b"\n".join(strs)
    urls = sorted(set(m.decode(errors="replace") for m in _URL_RE.findall(blob)))
    ips = sorted(set(m.decode(errors="replace") for m in _IP_RE.findall(blob)))
    winpaths = sorted(set(m.decode(errors="replace") for m in _WINPATH_RE.findall(blob)))
    apis_seen = sorted({s.decode(errors="replace") for s in strs
                         if s.decode(errors="replace") in _SUSPICIOUS_APIS})
    return {"urls": urls[:50], "ips": ips[:50], "windows_paths": winpaths[:50],
            "suspicious_api_strings": apis_seen}


def _pe_info(path: Path) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed (pip install -r requirements.txt)"}

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except Exception as e:  # pefile raises bare PEFormatError etc.
        return {"error": f"pefile failed to parse: {e}"}

    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
            imports.append(f"{dll}!{name}")

    exports = []
    exp_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp_dir:
        for sym in exp_dir.symbols:
            if sym.name:
                exports.append(sym.name.decode(errors="replace"))

    characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    mitigations = {
        "ASLR (DYNAMIC_BASE)": bool(characteristics & 0x0040),
        "DEP (NX_COMPAT)": bool(characteristics & 0x0100),
        "SafeSEH / no_seh": bool(characteristics & 0x0400),
        "CFG (Control Flow Guard)": bool(characteristics & 0x4000),
    }

    sections = []
    for s in pe.sections:
        data = s.get_data()
        sections.append({
            "name": s.Name.decode(errors="replace").strip("\x00"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(_entropy(data), 2),
        })

    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "imports": sorted(set(imports))[:300],
        "exports": sorted(set(exports))[:300],
        "mitigations": mitigations,
        "sections": sections,
        "likely_packed": any(s["entropy"] > 7.2 for s in sections),
    }


def _elf_info(path: Path) -> dict:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools not installed (pip install -r requirements.txt)"}

    info: dict = {"imports": [], "sections": [], "dynamic_symbols": []}
    with path.open("rb") as f:
        elf = ELFFile(f)
        info["entry_point"] = hex(elf.header["e_entry"])
        info["machine"] = elf.header["e_machine"]
        info["elf_type"] = elf.header["e_type"]

        for section in elf.iter_sections():
            data = section.data()
            info["sections"].append({
                "name": section.name,
                "size": section["sh_size"],
                "entropy": round(_entropy(data), 2) if data else 0.0,
            })

        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is not None:
            for sym in dynsym.iter_symbols():
                if sym.name:
                    info["dynamic_symbols"].append(sym.name)
        info["dynamic_symbols"] = sorted(set(info["dynamic_symbols"]))[:300]
        info["likely_packed"] = any(s["entropy"] > 7.2 for s in info["sections"])

    checksec = tools.run(["checksec", "--file=" + str(path)], timeout=30)
    if checksec.get("ok"):
        # checksec writes its report to stderr, not stdout.
        info["checksec"] = (checksec["stdout"] + checksec["stderr"]).strip()

    return info


def _radare2_summary(path: Path) -> dict:
    if not tools.have("r2"):
        return {"note": "radare2 ('r2') not found, skipping disassembly/function listing."}

    functions = tools.run(["r2", "-q", "-c", "e scr.color=0; aaa; afl", str(path)], timeout=90)
    entry_disasm = tools.run(["r2", "-q", "-c", "e scr.color=0; aaa; pd 40 @ entry0", str(path)], timeout=90)

    return {
        "function_list": functions["stdout"].strip() if functions.get("ok") else functions.get("error"),
        "entry_point_disassembly": entry_disasm["stdout"].strip() if entry_disasm.get("ok") else entry_disasm.get("error"),
    }


def run(path: str, kind: str) -> dict:
    p = Path(path)
    evidence: dict = {"pipeline": "native", "notes": []}

    evidence["notes"].extend(tools.missing_tools_note(["strings", "r2"]))

    raw_strings = _extract_strings(p)
    evidence["strings"] = _categorize_strings(raw_strings)
    evidence["string_sample"] = [s.decode(errors="replace") for s in raw_strings[:60]]

    if kind == "native_pe":
        evidence["pe"] = _pe_info(p)
    elif kind == "native_elf":
        evidence["elf"] = _elf_info(p)
    else:
        evidence["notes"].append("Mach-O detected. Detailed header parsing needs macOS tooling "
                                  "(otool/class-dump); only strings + radare2 output are available here.")

    evidence["radare2"] = _radare2_summary(p)

    return evidence
