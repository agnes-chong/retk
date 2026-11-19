"""Local-only GUI for retk. Binds to 127.0.0.1 by default — this is meant to
run on your own machine against your own files, not to be exposed on a
network. Uploaded files are untrusted input, so they're only ever read
statically (strings/disasm/manifest parsing etc.) by the same pipelines the
CLI uses — nothing here executes an uploaded file either.
"""
import json
import re
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory
from markupsafe import Markup, escape
from werkzeug.utils import secure_filename

from . import ai, report
from .analyze import analyze_file

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB — plenty for CTF/APK-sized samples, not a media server
OUTPUT_ROOT = Path("output").resolve()

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _render_summary(text: str) -> Markup:
    """Turn our own light markdown (**bold**, blank-line paragraphs) into HTML.

    Escapes the raw text FIRST, then only substitutes patterns on the already-escaped
    string — this matters because `text` can embed strings extracted from an untrusted
    analyzed file (URLs, permissions, etc.); escaping first means any `<`/`>`/`&` those
    strings contain can never turn into live HTML, no matter what the file contains.
    """
    if not text:
        return Markup("")
    safe = str(escape(text))
    safe = _BOLD_RE.sub(r"<strong>\1</strong>", safe)
    safe = safe.replace("\n\n", "<br><br>")
    return Markup(safe)


def _outdir_for(analysis_id: str) -> Path:
    """Resolve an analysis id to its output dir, refusing anything that would escape output/."""
    candidate = (OUTPUT_ROOT / analysis_id).resolve()
    if OUTPUT_ROOT not in candidate.parents and candidate != OUTPUT_ROOT:
        abort(404)
    if not candidate.is_dir():
        abort(404)
    return candidate


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.jinja_env.filters["render_summary"] = _render_summary
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return render_template("index.html", ai_available=ai.available())

    @app.post("/analyze")
    def do_analyze():
        f = request.files.get("file")
        if not f or not f.filename:
            return render_template("index.html", ai_available=ai.available(),
                                   error="No file selected."), 400

        analysis_id = f"{uuid.uuid4().hex[:10]}_{secure_filename(f.filename) or 'upload'}"
        outdir = OUTPUT_ROOT / analysis_id
        upload_dir = outdir / "upload"
        upload_dir.mkdir(parents=True, exist_ok=True)

        saved_path = upload_dir / (secure_filename(f.filename) or "upload.bin")
        f.save(saved_path)

        run_malware = request.form.get("malware") == "on"
        try:
            analyze_file(str(saved_path), out=str(outdir), malware=run_malware)
        except Exception as e:
            return render_template("index.html", ai_available=ai.available(),
                                   error=f"Analysis failed: {e}"), 500

        return redirect(f"/report/{analysis_id}")

    @app.get("/report/<analysis_id>")
    def view_report(analysis_id):
        outdir = _outdir_for(analysis_id)
        bundle = json.loads((outdir / "evidence.json").read_text())
        identify_result = bundle["identify"]
        evidence = bundle["evidence"]
        malware_evidence = bundle.get("malware_triage")

        heuristic = report.heuristic_summary(identify_result, evidence, malware_evidence)
        llm = ai.summarize(bundle) if ai.available() else None

        return render_template(
            "result.html",
            analysis_id=analysis_id,
            filename=Path(identify_result["path"]).name,
            identify_result=identify_result,
            evidence=evidence,
            malware_evidence=malware_evidence,
            heuristic=heuristic,
            llm=llm,
            ai_available=ai.available(),
            evidence_pretty=json.dumps(evidence, indent=2, default=str),
            malware_pretty=json.dumps(malware_evidence, indent=2, default=str) if malware_evidence else None,
        )

    @app.post("/ask/<analysis_id>")
    def ask(analysis_id):
        outdir = _outdir_for(analysis_id)
        bundle = json.loads((outdir / "evidence.json").read_text())
        body = request.get_json(silent=True) or {}
        question = (body.get("question") or "").strip()
        history = body.get("history") or []
        if not question:
            return jsonify({"answer": "(empty question)"}), 400
        answer = ai.ask(bundle, question, history=history)
        return jsonify({"answer": answer})

    @app.get("/download/<analysis_id>/<fname>")
    def download(analysis_id, fname):
        outdir = _outdir_for(analysis_id)
        if fname not in ("report.md", "evidence.json"):
            abort(404)
        return send_from_directory(outdir, fname, as_attachment=True)

    return app
