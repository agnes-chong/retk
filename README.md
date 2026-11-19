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

### CLI

```bash
python retk_cli.py analyze /path/to/target
python retk_cli.py analyze suspicious.exe --malware
python retk_cli.py analyze app.apk --out my_report_dir
python retk_cli.py analyze payload.bin --malware --yara-rules my_extra_rules.yar
```

Then open `output/<...>/report.md`.

### GUI

```bash
python retk_cli.py gui                 # http://127.0.0.1:5000, local only
python retk_cli.py gui --port 8080
```

Upload a file, optionally tick "run static malware triage," and you get the
same report rendered in the browser — heuristic summary, AI summary (if
configured, see below), raw evidence, and a chat box to ask follow-up
questions about that specific analysis. The server binds to `127.0.0.1` by
default; don't change `--host` to expose it on a network — it accepts file
uploads and was not hardened for that.

### AI-assisted summary + chat (optional)

Off by default; everything else works without it. To enable:

```bash
.venv/bin/pip install -r requirements-ai.txt
export ANTHROPIC_API_KEY=sk-...
```

With that set, every report gets a second, richer "how this works" summary
written by an LLM from the same evidence bundle (never from the raw file —
only the extracted static evidence is sent), and the GUI's chat box answers
follow-up questions about the specific analysis you're looking at. The
heuristic (non-AI) summary always runs regardless, so results are still
useful with zero API usage.

## Architecture

```
retk_cli.py              CLI entry point (analyze / gui subcommands)
retk/analyze.py          Shared identify -> pipeline -> report wiring,
                           used by both the CLI and the GUI
retk/webapp.py           Local-only Flask GUI (upload, report view, AI chat)
retk/templates/          GUI HTML templates
retk/ai.py               Optional Anthropic-API layer (summary + chat),
                           no-ops cleanly if ANTHROPIC_API_KEY isn't set
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
