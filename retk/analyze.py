"""Shared analysis entry point used by both the CLI and the GUI, so there's
exactly one place that wires identify -> pipeline -> report together."""
from datetime import datetime
from pathlib import Path

from . import identify as identify_mod
from . import report as report_mod
from .pipelines import native, android, ios, web_js, malware as malware_mod, generic


def run_pipeline(kind: str, path: str, outdir: Path) -> dict:
    if kind in (identify_mod.KIND_NATIVE_PE, identify_mod.KIND_NATIVE_ELF, identify_mod.KIND_NATIVE_MACHO):
        return native.run(path, kind)
    if kind == identify_mod.KIND_ANDROID_APK:
        return android.run(path, outdir)
    if kind == identify_mod.KIND_IOS_IPA:
        return ios.run(path)
    if kind == identify_mod.KIND_WEB_JS:
        return web_js.run(path)
    return generic.run(path)


def analyze_file(target: str, out: str | None = None, malware: bool = False,
                  yara_rules: str | None = None) -> dict:
    """Run the full pipeline against `target`. Returns a dict with identify_result,
    evidence, malware_evidence, outdir, report_path — everything a caller needs."""
    p = Path(target)
    if not p.is_file():
        raise FileNotFoundError(f"{target} is not a file")

    identify_result = identify_mod.identify(str(p))
    outdir = Path(out) if out else Path("output") / f"{p.stem}_{datetime.now():%Y%m%d_%H%M%S}"

    evidence = run_pipeline(identify_result["kind"], str(p), outdir)

    malware_evidence = None
    if malware:
        malware_evidence = malware_mod.run(str(p), extra_yara_rules=yara_rules)

    report_path = report_mod.build(identify_result, evidence, outdir, malware_evidence)

    return {
        "identify_result": identify_result,
        "evidence": evidence,
        "malware_evidence": malware_evidence,
        "outdir": outdir,
        "report_path": report_path,
    }
