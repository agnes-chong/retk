"""Turns raw pipeline evidence into a human-readable report.

Two layers of "explain how it works":
1. A rule-based heuristic summary (always available, no API key needed).
2. An optional LLM-written summary if `ANTHROPIC_API_KEY` is set and the
   `anthropic` package is installed — richer prose, entirely optional.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from . import ai


def heuristic_summary(identify_result: dict, evidence: dict, malware_evidence: dict | None) -> str:
    lines = []
    kind = identify_result.get("kind", "unknown")
    lines.append(f"This file was identified as **{kind}** ({identify_result.get('file_magic') or 'no file-magic available'}).")

    pe = evidence.get("pe") or {}
    elf = evidence.get("elf") or {}
    strings = evidence.get("strings") or {}

    if pe:
        mitig = pe.get("mitigations", {})
        on = [k for k, v in mitig.items() if v]
        off = [k for k, v in mitig.items() if not v]
        if on:
            lines.append(f"Security mitigations enabled: {', '.join(on)}.")
        if off:
            lines.append(f"Security mitigations NOT enabled: {', '.join(off)}.")
        if pe.get("likely_packed"):
            lines.append("At least one section has high entropy (>7.2). This binary may be packed or "
                          "encrypted, which will make imports/strings look sparse until unpacked.")
        imports = pe.get("imports", [])
        net_apis = [i for i in imports if any(h in i for h in
                    ("Internet", "socket", "WinHttp", "URLDownload", "connect", "send", "recv"))]
        proc_apis = [i for i in imports if any(h in i for h in
                     ("CreateProcess", "WinExec", "ShellExecute", "CreateRemoteThread", "WriteProcessMemory"))]
        if net_apis:
            lines.append(f"Imports network-capable APIs: {', '.join(net_apis[:8])}. "
                         "This program likely talks to the network.")
        if proc_apis:
            lines.append(f"Imports process-manipulation APIs: {', '.join(proc_apis[:8])}. "
                         "This program can spawn or inject into other processes.")

    if elf:
        if elf.get("likely_packed"):
            lines.append("At least one ELF section has high entropy, possibly packed/encrypted.")
        syms = elf.get("dynamic_symbols", [])
        net_syms = [s for s in syms if s in ("socket", "connect", "send", "recv", "getaddrinfo")]
        if net_syms:
            lines.append(f"Links network syscalls: {', '.join(net_syms)}. This program likely talks to the network.")

    if strings.get("urls"):
        lines.append(f"Found {len(strings['urls'])} URL-like string(s), e.g. {strings['urls'][0]!r}. "
                     "Worth checking where these point.")
    if strings.get("ips"):
        lines.append(f"Found hardcoded IP address string(s): {', '.join(strings['ips'][:5])}.")

    android = evidence.get("manifest_and_strings")
    if android and "error" not in android:
        lines.append(f"Android package `{android.get('package')}` (targets SDK {android.get('target_sdk')}).")
        if android.get("dangerous_permissions"):
            lines.append(f"Requests sensitive permissions: {', '.join(android['dangerous_permissions'])}.")
        if android.get("urls_in_dex_strings"):
            lines.append(f"App code references {len(android['urls_in_dex_strings'])} URL(s).")

    web = evidence if evidence.get("pipeline") == "web_js" else None
    if web:
        if web.get("likely_minified"):
            lines.append("Source looks minified/bundled; a beautified preview is included below.")
        if web.get("obfuscation_indicators"):
            lines.append(f"Possible obfuscation indicators: {', '.join(web['obfuscation_indicators'])}.")
        if web.get("possible_api_endpoints"):
            lines.append(f"References {len(web['possible_api_endpoints'])} possible API endpoint path(s).")

    ios = evidence if evidence.get("pipeline") == "ios" else None
    if ios and "error" not in ios:
        lines.append(f"iOS app bundle `{ios.get('bundle_id')}` version {ios.get('version')}.")

    if malware_evidence:
        y = malware_evidence.get("yara", {})
        matches = y.get("matches", [])
        if matches:
            rule_names = ", ".join(m["rule"] for m in matches)
            lines.append(f"**YARA triage hits**: {rule_names}. These are indicators worth human review, "
                         "not a verdict; legitimate software can trip these too.")
        capa = malware_evidence.get("capa", {})
        if capa.get("capability_count"):
            lines.append(f"capa identified {capa['capability_count']} capability/ies "
                         "(see the capa section for the MITRE ATT&CK mapping).")

    if len(lines) == 1:
        lines.append("No strong behavioral signal was found by the automated heuristics above. "
                     "Read the raw evidence sections (strings, imports, disassembly) for manual review.")

    return "\n\n".join(lines)


def build(identify_result: dict, evidence: dict, outdir: Path, malware_evidence: dict | None = None) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)

    bundle = {"identify": identify_result, "evidence": evidence, "malware_triage": malware_evidence}
    (outdir / "evidence.json").write_text(json.dumps(bundle, indent=2, default=str))

    heuristic = heuristic_summary(identify_result, evidence, malware_evidence)
    llm = ai.summarize(bundle)

    md = []
    md.append(f"# retk analysis report: {Path(identify_result['path']).name}")
    md.append(f"_Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}_\n")

    md.append("## File identification")
    md.append(f"- **Path**: `{identify_result['path']}`")
    md.append(f"- **Detected kind**: `{identify_result['kind']}`")
    md.append(f"- **file(1) magic**: {identify_result.get('file_magic') or 'n/a'}\n")

    md.append("## How this program works (heuristic summary)")
    md.append(heuristic + "\n")

    if llm:
        md.append("## How this program works (LLM-assisted summary)")
        md.append(llm + "\n")
    else:
        md.append("## How this program works (LLM-assisted summary)")
        md.append("_Not generated. Set `ANTHROPIC_API_KEY` and `pip install anthropic` to enable this, "
                  "or paste `evidence.json` into an LLM of your choice for a deeper narrative explanation._\n")

    if malware_evidence:
        md.append("## Malware triage (static only)")
        md.append(f"> {malware_evidence['safety_banner']}\n")
        y = malware_evidence.get("yara", {})
        if y.get("matches"):
            for m in y["matches"]:
                md.append(f"- **{m['rule']}**: {m['description']} (strings: {', '.join(m['matched_strings'])})")
        elif y.get("error"):
            md.append(f"- YARA: {y['error']}")
        else:
            md.append("- YARA: no rule matches.")
        capa = malware_evidence.get("capa", {})
        if capa.get("capabilities"):
            md.append("\n**capa capabilities:**")
            for c in capa["capabilities"][:40]:
                attack = f" ({'; '.join(c['attack'])})" if c.get("attack") else ""
                md.append(f"- {c['capability']}{attack}")
        md.append("")

    md.append("## Notes / tool gaps")
    for note in evidence.get("notes", []):
        md.append(f"- {note}")
    md.append("")

    md.append("## Raw evidence")
    md.append("Full machine-readable evidence (imports, full string list, disassembly, manifest, etc.) "
              f"is in `evidence.json` next to this report. Key excerpts:\n")
    md.append("```json")
    md.append(json.dumps(evidence, indent=2, default=str)[:8000])
    md.append("```")

    report_path = outdir / "report.md"
    report_path.write_text("\n".join(md))
    return report_path
