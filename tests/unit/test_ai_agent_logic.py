"""AI Agent: intent-classification hardening, with the LLM call replaced by fixtures."""
import pytest

from collectors.aws.scanner import ai_agent_handler as ai

pytestmark = [pytest.mark.flow("E2E-AI-001"), pytest.mark.severity("P1")]


def _classify(monkeypatch, llm_output, **kw):
    monkeypatch.setattr(ai, "_call_groq", lambda prompt, max_tokens=0: llm_output)
    return ai._classify_intent("q", **kw)


def test_valid_json_is_accepted(monkeypatch):
    assert _classify(monkeypatch, '{"intent": "highest_risks", "framework_code": null}') == ("highest_risks", None)


def test_json_inside_a_code_fence_is_accepted(monkeypatch):
    out = _classify(monkeypatch, '```json\n{"intent": "executive_summary", "framework_code": null}\n```')
    assert out[0] == "executive_summary"


def test_garbage_output_degrades_to_unsupported(monkeypatch):
    assert _classify(monkeypatch, "I think you should look at IAM")[0] == "unsupported"


def test_invented_intent_is_rejected(monkeypatch):
    assert _classify(monkeypatch, '{"intent": "delete_everything", "framework_code": null}')[0] == "unsupported"


def test_invented_framework_code_is_dropped_but_real_one_kept(monkeypatch):
    code = next(iter(ai.FRAMEWORK_LABELS))
    assert _classify(monkeypatch, '{"intent": "framework_status", "framework_code": "MADE_UP"}')[1] is None
    assert _classify(monkeypatch, '{"intent": "framework_status", "framework_code": "%s"}' % code)[1] == code


def test_page_context_and_history_reach_the_classifier(monkeypatch):
    seen = {}

    def fake(prompt, max_tokens=0):
        seen["p"] = prompt
        return '{"intent": "unsupported", "framework_code": null}'

    monkeypatch.setattr(ai, "_call_groq", fake)
    ai._classify_intent("which one is newest?", has_page_context=True, previous_question="show medium findings")
    assert "show medium findings" in seen["p"] and "currently looking at a specific dashboard page" in seen["p"]


def test_uuid_validation_rejects_injection_and_garbage():
    assert ai._is_uuid("cbb94e43-4e42-4fac-997e-8f931131bde7")
    for bad in (None, "", "null", "1; DROP TABLE findings", "cbb94e43"):
        assert not ai._is_uuid(bad)


def test_tokenizer_drops_stopwords_and_short_words():
    toks = ai._tokenize("What is our RPO for the database?")
    assert "rpo" in toks and "database" in toks and "the" not in toks


def test_intents_are_a_fixed_allowlist():
    assert "unsupported" in ai.INTENTS and "general_data_question" in ai.INTENTS
