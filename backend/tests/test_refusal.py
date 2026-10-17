"""Streaming refusals: stop_reason "refusal" (HTTP 200) must reset partial text and fall back to another model."""

from __future__ import annotations

from types import SimpleNamespace as NS

from app.llm import ClaudeLLM, FakeLLM, Usage
from app.pipeline import REFUSAL_MESSAGE, answer_events
from tests.test_phase1 import retriever  # noqa: F401


class Refuser(FakeLLM):
    """Streams some text, then ends with a refusal, like a safety classifier cutting a stream."""

    def __init__(self, model="claude-sonnet-5-5"):
        super().__init__(model)

    def stream(self, system, user, max_tokens=1024):
        self.stop_reason = None
        yield "Adversaries who are an administrative user can harvest credential material from LSASS and then "
        yield "dump the process memory for offline analysis using a range of tools that "
        self.stop_reason, self.stop_category = "refusal", "cyber"
        self._usage = Usage(1000, 40)


class Answerer(FakeLLM):
    def __init__(self, model="claude-haiku-5-5"):
        super().__init__(model)

    def stream(self, system, user, max_tokens=1024):
        self.stop_reason = None
        yield "Detect LSASS access with process access auditing and restrict debug privileges [1]."
        self.stop_reason = "end_turn"
        self._usage = Usage(1000, 30)


def _run(retriever, llm, fallback):  # noqa: F811
    return list(answer_events("How do adversaries dump credentials from LSASS memory?", retriever, llm, fallback_llm=fallback))


def test_refusal_resets_and_falls_back(retriever):  # noqa: F811
    events = _run(retriever, Refuser(), Answerer())
    names = [e for e, _ in events]
    assert "reset" in names
    after_reset = names[names.index("reset") + 1 :]
    assert "token" in after_reset and names[-1] == "done"
    final_text = "".join(d["text"] for e, d in events[names.index("reset") :] if e == "token")
    assert final_text.startswith("Detect LSASS")
    done = events[-1][1]
    assert done["fallback_from"] == "claude-sonnet-5-5" and done["model"] == "claude-haiku-5-5"
    assert done["cited"] == [1] and not done["blocked"]
    # both attempts are paid for, so both are counted
    assert done["cost_usd"] > Usage(1000, 30).cost_usd("claude-haiku-5-5")


def test_refusal_by_both_models_returns_clear_message(retriever):  # noqa: F811
    events = _run(retriever, Refuser(), Refuser("claude-haiku-5-5"))
    names = [e for e, _ in events]
    assert names.count("reset") == 2
    assert ("error", {"message": REFUSAL_MESSAGE}) in events
    assert events[-1][1]["refused"] is True and events[-1][1]["blocked"] is True


def test_refusal_without_fallback_still_clears_partial_text(retriever):  # noqa: F811
    events = _run(retriever, Refuser(), None)
    names = [e for e, _ in events]
    assert "reset" in names and events[-1][1]["refused"] is True


def test_claude_client_reads_refusal_from_stream_events(monkeypatch):
    """Parse the SDK's event shapes: text deltas, then message_delta with stop_reason and stop_details."""
    events = [
        NS(type="message_start"),
        NS(type="content_block_delta", delta=NS(type="text_delta", text="Partial ")),
        NS(type="content_block_delta", delta=NS(type="text_delta", text="answer")),
        NS(type="message_delta", delta=NS(stop_reason="refusal", stop_details=NS(type="refusal", category="cyber"))),
        NS(type="message_stop"),
    ]
    final = NS(stop_reason="refusal", usage=NS(input_tokens=900, output_tokens=12))

    class FakeStream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            return iter(events)

        def get_final_message(self):
            return final

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    llm = ClaudeLLM("claude-sonnet-5-5")
    monkeypatch.setattr(llm._client.messages, "stream", lambda **kw: FakeStream())
    text = "".join(llm.stream("sys", "user"))
    assert text == "Partial answer"
    assert llm.stop_reason == "refusal" and llm.stop_category == "cyber"
    assert llm.usage.input_tokens == 900
