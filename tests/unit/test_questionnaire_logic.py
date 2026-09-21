"""Questionnaire Automation: parsing, evidence confidence, and upload validation."""
import base64

import pytest

from collectors.aws.scanner import questionnaire_handler as qh

pytestmark = [pytest.mark.flow("E2E-QST-002"), pytest.mark.severity("P1")]


def test_csv_with_question_header_and_answer_column():
    rows = qh._parse_csv("Question,Answer\nDo you use MFA?,Yes\nBackups?,\n")
    assert rows == [("Do you use MFA?", "Yes"), ("Backups?", None)]


def test_csv_without_header_treats_first_column_as_questions():
    assert [q for q, _ in qh._parse_csv("First question\nSecond question\n")] == ["First question", "Second question"]


def test_csv_skips_blank_rows_and_empty_questions():
    assert qh._parse_csv("Question\n\n  \nReal one\n,\n") == [("Real one", None)]


def test_empty_csv_returns_no_questions():
    assert qh._parse_csv("") == []


def test_confidence_reflects_number_of_independent_evidence_sources():
    assert qh._confidence([], []) == "low"
    assert qh._confidence(["c"], []) == "medium"
    assert qh._confidence(["c"], ["d"]) == "high"
    assert qh._confidence([], [], ["v"]) == "medium"
    assert qh._confidence(["c"], [], ["v"]) == "high"


@pytest.mark.parametrize("filename", ["old.xls", "old.doc"])
def test_legacy_office_formats_are_rejected_with_a_clear_error(filename):
    with pytest.raises(ValueError, match="aren't supported"):
        qh._parse_uploaded_file(filename, base64.b64encode(b"x").decode())


def test_unknown_extension_is_treated_as_csv_text_by_design():
    rows = qh._parse_uploaded_file("questions.txt", base64.b64encode(b"Do you encrypt data at rest?\n").decode())
    assert rows == [("Do you encrypt data at rest?", None)]


def test_corrupt_pdf_is_rejected_not_crashed():
    with pytest.raises(Exception):
        qh._parse_pdf(b"%PDF-1.4 this is not a real pdf")


def test_tokenizer_keeps_meaningful_words_and_drops_stopwords():
    toks = qh._tokenize("Is encryption at rest enabled for the database?")
    assert "encryption" in toks and "database" in toks and "the" not in toks
