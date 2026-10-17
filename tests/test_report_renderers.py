"""Report renderer testleri -- JSON, HTML, Markdown ve ExecSummary reporter'lari dogrulanir."""
import json

from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report import ExecSummaryReporter, HtmlReporter, JsonReporter, MarkdownReporter


def _make_finding(fid="F-001", vtype="idor", verdict="CONFIRMED", endpoint="/api/orders/{id}",
                  method="GET", param="id", leaked=None):
    ev = Evidence(
        attack_request=CapturedRequest(method=method, url="http://target" + endpoint),
        attack_response=NormalizedResponse(status=200, body_text='{"ok":true}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=leaked or [],
    )
    return Finding(id=fid, type=vtype, endpoint=endpoint, method=method, parameter=param,
                   verdict=verdict, confidence="high", severity="High", cwe="CWE-639",
                   owasp="API1:2023", evidence=ev)


def _sample_findings():
    return [
        _make_finding("F-001", "idor", "CONFIRMED"),
        _make_finding("F-002", "bfla", "REJECTED", endpoint="/api/admin/users", param=""),
        _make_finding("F-003", "csrf", "LIKELY", endpoint="/api/transfer", method="POST"),
    ]


# --- JsonReporter ---

def test_json_renders_valid_json():
    output = JsonReporter().render(_sample_findings(), target="http://target")
    data = json.loads(output)
    assert isinstance(data, list)
    assert len(data) == 3


def test_json_contains_finding_fields():
    output = JsonReporter().render(_sample_findings())
    data = json.loads(output)
    assert data[0]["type"] == "idor"
    assert data[0]["verdict"] == "CONFIRMED"


def test_json_empty_findings():
    output = JsonReporter().render([])
    data = json.loads(output)
    assert data == []


def test_json_redacts_sensitive_data():
    f = _make_finding(leaked=["alice@example.com"])
    output = JsonReporter().render([f])
    assert "alice@example.com" not in output


# --- HtmlReporter ---

def test_html_renders_with_default_template():
    output = HtmlReporter().render(_sample_findings(), target="http://target")
    assert "<html" in output.lower() or "<!doctype" in output.lower()


def test_html_embeds_finding_data():
    output = HtmlReporter().render(_sample_findings(), target="http://target")
    assert "idor" in output
    assert "CONFIRMED" in output


def test_html_custom_template(tmp_path):
    template = tmp_path / "test_template.html"
    template.write_text('<html><body>__REPORT_DATA__</body></html>', encoding="utf-8")
    output = HtmlReporter(template_path=template).render(_sample_findings())
    data_str = output.replace("<html><body>", "").replace("</body></html>", "")
    parsed = json.loads(data_str)
    assert "findings" in parsed
    assert len(parsed["findings"]) == 3


def test_html_redacts_pii():
    f = _make_finding(leaked=["user@secret.internal"])
    output = HtmlReporter().render([f])
    assert "user@secret.internal" not in output


def test_html_empty_findings():
    output = HtmlReporter().render([], target="http://target")
    assert "__REPORT_DATA__" not in output


# --- MarkdownReporter ---

def test_markdown_has_header():
    output = MarkdownReporter().render(_sample_findings(), target="http://target")
    assert "# Sentinel-Agent" in output


def test_markdown_contains_findings():
    output = MarkdownReporter().render(_sample_findings(), target="http://target")
    assert "IDOR" in output
    assert "CONFIRMED" in output
    assert "/api/orders/{id}" in output


def test_markdown_shows_target():
    output = MarkdownReporter().render(_sample_findings(), target="https://example.com")
    assert "https://example.com" in output


def test_markdown_empty_findings():
    output = MarkdownReporter().render([], target="http://target")
    assert "**Findings:** 0" in output


def test_markdown_redacts_pii():
    f = _make_finding(leaked=["admin@corp.internal"])
    output = MarkdownReporter().render([f])
    assert "admin@corp.internal" not in output


# --- ExecSummaryReporter ---

def test_exec_renders_html():
    output = ExecSummaryReporter().render(_sample_findings(), target="http://target")
    assert "<!doctype html>" in output.lower()
    assert "Sentinel-Agent" in output


def test_exec_contains_verdict_chips():
    output = ExecSummaryReporter().render(_sample_findings())
    assert "CONFIRMED" in output
    assert "LIKELY" in output


def test_exec_shows_target():
    output = ExecSummaryReporter().render(_sample_findings(), target="https://app.test")
    assert "app.test" in output


def test_exec_empty_findings():
    output = ExecSummaryReporter().render([])
    assert "bulgu yok" in output.lower()


def test_exec_redacts_pii():
    f = _make_finding(leaked=["victim@example.org"])
    output = ExecSummaryReporter().render([f])
    assert "victim@example.org" not in output
