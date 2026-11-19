#!/usr/bin/env python3
"""retk — drop in almost any application/binary, get a static reverse-engineering
report explaining what it is and how it likely works.

    python retk_cli.py analyze path/to/target [--out DIR] [--malware] [--yara-rules FILE]

See README.md for installation, supported targets, and the legal/ethical
usage disclaimer (read it before pointing this at anything you don't own).
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from retk import identify as identify_mod
from retk import report as report_mod
from retk.pipelines import native, android, ios, web_js, malware as malware_mod, generic


def _run_pipeline(kind: str, path: str, outdir: Path) -> dict:
    if kind in (identify_mod.KIND_NATIVE_PE, identify_mod.KIND_NATIVE_ELF, identify_mod.KIND_NATIVE_MACHO):
        return native.run(path, kind)
    if kind == identify_mod.KIND_ANDROID_APK:
        return android.run(path, outdir)
    if kind == identify_mod.KIND_IOS_IPA:
        return ios.run(path)
    if kind == identify_mod.KIND_WEB_JS:
        return web_js.run(path)
    return generic.run(path)


def cmd_analyze(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"error: {target} is not a file", file=sys.stderr)
        return 1

    identify_result = identify_mod.identify(str(target))
    print(f"[retk] identified as: {identify_result['kind']} ({identify_result.get('file_magic') or 'n/a'})")

    outdir = Path(args.out) if args.out else Path("output") / f"{target.stem}_{datetime.now():%Y%m%d_%H%M%S}"

    print("[retk] running static analysis pipeline...")
    evidence = _run_pipeline(identify_result["kind"], str(target), outdir)

    malware_evidence = None
    if args.malware:
        print("[retk] running malware triage layer (static only, nothing is executed)...")
        malware_evidence = malware_mod.run(str(target), extra_yara_rules=args.yara_rules)

    print("[retk] writing report...")
    report_path = report_mod.build(identify_result, evidence, outdir, malware_evidence)

    print(f"\n[retk] done. Report: {report_path}")
    print(f"[retk] raw evidence: {outdir / 'evidence.json'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="retk", description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Run the static RE pipeline against a file")
    p_analyze.add_argument("target", help="Path to the file to analyze")
    p_analyze.add_argument("--out", help="Output directory (default: output/<name>_<timestamp>)")
    p_analyze.add_argument("--malware", action="store_true",
                           help="Also run static malware triage (YARA + capa). Never executes the sample.")
    p_analyze.add_argument("--yara-rules", help="Path to an additional .yar rules file")
    p_analyze.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
