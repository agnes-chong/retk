#!/usr/bin/env python3
"""retk — drop in almost any application/binary, get a static reverse-engineering
report explaining what it is and how it likely works.

    python retk_cli.py analyze path/to/target [--out DIR] [--malware] [--yara-rules FILE]
    python retk_cli.py gui [--host 127.0.0.1] [--port 5000]

See README.md for installation, supported targets, and the legal/ethical
usage disclaimer (read it before pointing this at anything you don't own).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from retk.analyze import analyze_file


def cmd_analyze(args: argparse.Namespace) -> int:
    print(f"[retk] running static analysis on {args.target} ...")
    try:
        result = analyze_file(args.target, out=args.out, malware=args.malware, yara_rules=args.yara_rules)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"[retk] identified as: {result['identify_result']['kind']} "
          f"({result['identify_result'].get('file_magic') or 'n/a'})")
    print(f"\n[retk] done. Report: {result['report_path']}")
    print(f"[retk] raw evidence: {result['outdir'] / 'evidence.json'}")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from retk.webapp import create_app
    app = create_app()
    print(f"[retk] GUI running at http://{args.host}:{args.port} (local only, do not expose this port)")
    app.run(host=args.host, port=args.port, debug=False)
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

    p_gui = sub.add_parser("gui", help="Launch the local web GUI")
    p_gui.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1, keep it local)")
    p_gui.add_argument("--port", type=int, default=5000)
    p_gui.set_defaults(func=cmd_gui)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
