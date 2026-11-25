"""Optional LLM layer. Entirely best-effort: every function here returns
None/a friendly error string instead of raising when `anthropic` isn't
installed or `ANTHROPIC_API_KEY` isn't set — nothing else in retk depends
on this module being usable.
"""
import json
import os

_MODEL = "claude-sonnet-5-5"
_SYSTEM = (
    "You are a reverse-engineering assistant. You are given a static-analysis "
    "evidence bundle (strings, imports, disassembly, permissions, YARA/capa hits, "
    "etc.) produced by an automated tool called retk. Be precise about what's "
    "confirmed by the evidence vs. speculative. If the evidence suggests malicious "
    "capability, say so plainly and note it's an indicator, not a verdict. Never "
    "claim to have executed or dynamically analyzed the sample: everything you "
    "see is static evidence. Write in plain prose, short sentences, no em dashes."
)


def available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def _client():
    import anthropic
    return anthropic.Anthropic()


def summarize(evidence_bundle: dict) -> str | None:
    """Richer narrative explanation of what the analyzed program does. None if unavailable."""
    if not available():
        return None
    try:
        client = _client()
        evidence_text = json.dumps(evidence_bundle, indent=2, default=str)[:60000]
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=1200,
            system=_SYSTEM,
            messages=[{
                "role": "user",
                "content": "Write a clear, plain-English explanation of what this program most "
                           "likely does and how it works, based on this evidence:\n\n" + evidence_text,
            }],
        )
        return "".join(block.text for block in msg.content if hasattr(block, "text"))
    except Exception as e:
        return f"(LLM summary requested but failed: {e})"


def ask(evidence_bundle: dict, question: str, history: list[dict] | None = None) -> str:
    """Answer a follow-up question about a specific analysis. `history` is a list of
    {"role": "user"|"assistant", "content": str} from earlier turns in the same chat."""
    if not available():
        return ("AI chat isn't configured. Set the ANTHROPIC_API_KEY environment variable "
                "and `pip install anthropic`, then restart the GUI.")
    try:
        client = _client()
        evidence_text = json.dumps(evidence_bundle, indent=2, default=str)[:60000]
        messages = [{
            "role": "user",
            "content": "Here is the static-analysis evidence bundle for the file being discussed:\n\n"
                       + evidence_text,
        }, {
            "role": "assistant",
            "content": "Understood — I have the evidence. Ask me anything about it.",
        }]
        messages.extend(history or [])
        messages.append({"role": "user", "content": question})

        msg = client.messages.create(model=_MODEL, max_tokens=800, system=_SYSTEM, messages=messages)
        return "".join(block.text for block in msg.content if hasattr(block, "text"))
    except Exception as e:
        return f"(request failed: {e})"
