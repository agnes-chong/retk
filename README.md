# retk — Reverse Engineering Toolkit

Drop in almost any application and get a static-analysis report explaining
what it is and how it likely works: native Windows/Linux binaries (PE/ELF,
best-effort Mach-O), Android APKs, iOS IPAs (reduced fidelity, see below),
JavaScript/web bundles, and an optional static malware-triage layer (YARA +
[capa](https://github.com/mandiant/capa)) for suspicious samples.

retk is a router + a set of pipelines, each wrapping well-established,
battle-tested tools (radare2, pefile, pyelftools, androguard, YARA, capa,
jsbeautifier) and assembling their output into one readable report instead
of you running each tool by hand and cross-referencing the output yourself.

## ⚠️ Legal / ethical use

This is a dual-use security tool. Only point it at:
- software you own or wrote yourself,
- software you have explicit authorization to analyze (a pentest/bug-bounty
  engagement, a CTF, a security research program),
- malware samples you're handling as part of legitimate defensive/research
  work, in an environment you can afford to lose.

retk performs **static analysis only** — it never executes, unpacks-and-runs,
or detonates the target. That said, static analysis of hostile input is not
zero-risk (decompression bombs, parser crashes, decompiler exploits), so
still run it in a disposable VM/container when the sample's trust level is
unknown. You are responsible for complying with the laws and terms of
service that apply to whatever you analyze with this.

## What you get

For every target, a `report.md` + `evidence.json` under `output/<name>_<timestamp>/`:
- File identification (type, magic).
- A **heuristic, plain-English summary** of what the program likely does —
  no API key needed, generated from the extracted evidence (imports,
  permissions, strings, mitigations, etc.).
- An optional **LLM-written summary** (richer prose) if you set
  `ANTHROPIC_API_KEY` and `pip install anthropic` — purely additive, the
  heuristic summary always runs regardless.
- The full raw evidence: strings (categorized into URLs/IPs/paths/suspicious
  API names), imports/exports, section entropy (packer hint), security
  mitigations (ASLR/DEP/CFG/RELRO/canary/PIE), disassembly + function list
  (radare2), Android manifest/permissions/components, decompiled Java
  (if `jadx` is installed), beautified JS with endpoint/secret-pattern/
  obfuscation indicators, or iOS bundle metadata.
- With `--malware`: YARA matches against a bundled generic indicator
  ruleset (packer, anti-debug, ransomware/C2/credential-theft string
  patterns) plus capa's MITRE ATT&CK-mapped capability extraction.

Every external tool is optional. If something isn't installed, the report
says so and keeps going with whatever evidence it could gather — it never
just fails outright.

## Install

```bash
git clone <this-repo-url> retk
cd retk
./setup.sh                  # Debian/Ubuntu/WSL: installs apt + pip deps
source .venv/bin/activate
```

Windows users: run this inside WSL (the pipelines shell out to Linux tools
like radare2/strings/checksec). `setup.sh` also fetches capa's rule pack for
the `--malware` capability-extraction step.

See `setup.sh`'s own output for optional extras (`jadx`, `apktool`, Ghidra)
it won't install for you.

## Usage

```bash
python retk_cli.py analyze /path/to/target
python retk_cli.py analyze suspicious.exe --malware
python retk_cli.py analyze app.apk --out my_report_dir
python retk_cli.py analyze payload.bin --malware --yara-rules my_extra_rules.yar
```

Then open `output/<...>/report.md`.

## Architecture

```
retk_cli.py              CLI entry point: identify -> dispatch -> report
retk/identify.py         Magic-byte + zip-content based file-type router
retk/tools.py            subprocess + "is this tool installed" helpers
retk/pipelines/
    native.py             PE / ELF / Mach-O: strings, imports, mitigations,
                           entropy/packer check, radare2 disasm+funclist
    android.py             APK: androguard manifest/permissions/components,
                           dex-string URL/secret-pattern scan, jadx decompile
    ios.py                 IPA: Info.plist + bundled-binary strings
                           (best-effort — no macOS tooling available)
    web_js.py               JS: beautify, URL/endpoint/secret patterns,
                           obfuscation heuristics
    malware.py              Static-only YARA + capa layer, opt-in via --malware
    generic.py             Fallback: strings + URL/secret scan for anything
                           else
retk/report.py           Builds report.md + evidence.json; heuristic +
                           optional LLM-written summary
retk/rules/generic.yar   Bundled low-confidence triage rules
```

## Known limitations

- **iOS**: without macOS, there's no `class-dump`/`otool -ObjC`, so Objective-C/
  Swift class and method names aren't recoverable — the ios pipeline gives
  you plist metadata, permission-usage strings, and raw binary strings only.
- **capa** needs its rule pack (`setup.sh` fetches it to `.capa-rules/`); without
  it, capa reports an error instead of capabilities.
- **Packed/obfuscated** binaries will show sparse imports/strings until
  manually unpacked — `likely_packed`/section-entropy flags this, it doesn't
  unpack it for you.
- The heuristic summary is intentionally conservative pattern-matching, not
  a full program-understanding engine — treat it (and the YARA/capa hits) as
  a triage pointer, verify manually before drawing conclusions.

## License

MIT — see `LICENSE`.
