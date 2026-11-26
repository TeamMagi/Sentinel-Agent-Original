"""Engellenen-yazma kapsam uyarılarının Markdown/HTML raporlarında görünmesi."""
from pentestai.models.llm_refusal import LlmRefusalNote
from pentestai.report.render_html import HtmlReporter
from pentestai.report.render_md import MarkdownReporter

LINE = "POST /api/orders test edilemedi (idor): destructive_tests kapalı — izin vermek için ekleyin."
XSS_LINE = "PUT /<script>alert(1)</script> test edilemedi (bfla): destructive_tests kapalı"


def test_md_shows_blocked_write_lines():
    md = MarkdownReporter().render([], target="http://x", coverage_warnings=[LINE])
    assert "Kapsam uyarıları" in md and LINE in md


def test_html_shows_blocked_write_lines():
    out = HtmlReporter().render([], target="http://x", coverage_warnings=[LINE])
    assert 'id="coverageWarnings"' in out and "POST /api/orders test edilemedi" in out


def test_no_warnings_no_section():
    assert "Kapsam uyarıları" not in MarkdownReporter().render([], target="http://x")
    assert "coverageWarnings" not in HtmlReporter().render([], target="http://x")


def test_html_escapes_script_in_path():
    out = HtmlReporter().render([], target="http://x", coverage_warnings=[XSS_LINE])
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


def test_refusal_and_blocked_write_together():
    note = LlmRefusalNote(stage="hypothesis", provider="p", message="ret", count=2)
    md = MarkdownReporter().render([], llm_refusals=[note], coverage_warnings=[LINE])
    assert "2 kez reddetti" in md and LINE in md
