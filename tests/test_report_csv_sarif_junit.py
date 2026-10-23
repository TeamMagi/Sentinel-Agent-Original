"""CSV, SARIF ve JUnit reporter testleri."""
import csv
import io
import json
import xml.etree.ElementTree as ET

from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report.render_csv import CsvReporter
from pentestai.report.render_sarif import SarifReporter, fingerprint_of
from pentestai.report.render_junit import JUnitReporter


def _make_finding(fid="F-001", vtype="idor", verdict="CONFIRMED", endpoint="/api/orders/{id}",
                  method="GET", param="id", leaked=None, confidence="high", severity="High"):
    ev = Evidence(
        attack_request=CapturedRequest(method=method, url="http://target" + endpoint),
        attack_response=NormalizedResponse(status=200, body_text='{"ok":true}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=leaked or [],
    )
    return Finding(id=fid, type=vtype, endpoint=endpoint, method=method, parameter=param,
                   verdict=verdict, confidence=confidence, severity=severity, cwe="CWE-639",
                   owasp="API1:2023", evidence=ev)


def _sample_findings():
    return [
        _make_finding("F-001", "idor", "CONFIRMED"),
        _make_finding("F-002", "bfla", "REJECTED", endpoint="/api/admin/users", param=""),
        _make_finding("F-003", "csrf", "LIKELY", endpoint="/api/transfer", method="POST"),
    ]


# ===================== CsvReporter =====================

def test_csv_valid_output():
    output = CsvReporter().render(_sample_findings(), target="http://target")
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 3

def test_csv_has_expected_columns():
    output = CsvReporter().render(_sample_findings())
    reader = csv.DictReader(io.StringIO(output))
    expected = {"id", "type", "verdict", "confidence", "severity", "cwe", "owasp",
                "method", "endpoint", "parameter", "resource", "attacker", "victim",
                "found_as", "leaked_field_count", "baseline_status"}
    assert set(reader.fieldnames) == expected

def test_csv_finding_values():
    output = CsvReporter().render([_make_finding()])
    reader = csv.DictReader(io.StringIO(output))
    row = next(reader)
    assert row["id"] == "F-001"
    assert row["type"] == "idor"
    assert row["verdict"] == "CONFIRMED"
    assert row["method"] == "GET"

def test_csv_empty_findings():
    output = CsvReporter().render([])
    lines = output.strip().split("\n")
    assert len(lines) == 1  # header only

def test_csv_redacts_sensitive():
    f = _make_finding(leaked=["alice@example.com"])
    output = CsvReporter().render([f])
    assert "alice@example.com" not in output

def test_csv_leaked_count():
    f = _make_finding(leaked=["m1", "m2", "m3"])
    output = CsvReporter().render([f])
    reader = csv.DictReader(io.StringIO(output))
    row = next(reader)
    assert row["leaked_field_count"] == "3"


# ===================== SarifReporter =====================

def test_sarif_valid_json():
    output = SarifReporter().render(_sample_findings(), target="http://target")
    doc = json.loads(output)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc

def test_sarif_excludes_rejected_by_default():
    output = SarifReporter().render(_sample_findings())
    doc = json.loads(output)
    results = doc["runs"][0]["results"]
    verdicts = {r["properties"]["verdict"] for r in results}
    assert "REJECTED" not in verdicts

def test_sarif_includes_rejected_when_asked():
    output = SarifReporter(include_rejected=True).render(_sample_findings())
    doc = json.loads(output)
    results = doc["runs"][0]["results"]
    verdicts = {r["properties"]["verdict"] for r in results}
    assert "REJECTED" in verdicts

def test_sarif_rules_match_types():
    findings = _sample_findings()
    output = SarifReporter(include_rejected=True).render(findings)
    doc = json.loads(output)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert {"idor", "bfla", "csrf"} == rule_ids

def test_sarif_fingerprint_stable():
    f = _make_finding()
    fp1 = fingerprint_of(f)
    fp2 = fingerprint_of(f)
    assert fp1 == fp2
    assert len(fp1) == 16

def test_sarif_fingerprint_differs_for_different_endpoint():
    f1 = _make_finding(endpoint="/api/a")
    f2 = _make_finding(endpoint="/api/b")
    assert fingerprint_of(f1) != fingerprint_of(f2)

def test_sarif_empty_findings():
    output = SarifReporter().render([])
    doc = json.loads(output)
    assert doc["runs"][0]["results"] == []

def test_sarif_confirmed_is_error_level():
    output = SarifReporter().render([_make_finding(verdict="CONFIRMED", severity="High")])
    doc = json.loads(output)
    assert doc["runs"][0]["results"][0]["level"] == "error"

def test_sarif_target_in_uri_base():
    output = SarifReporter().render(_sample_findings(), target="http://target")
    doc = json.loads(output)
    assert "originalUriBaseIds" in doc["runs"][0]

def test_sarif_redacts_pii():
    f = _make_finding(leaked=["secret@corp.com"])
    output = SarifReporter().render([f])
    assert "secret@corp.com" not in output


# ===================== JUnitReporter =====================

def test_junit_valid_xml():
    output = JUnitReporter().render(_sample_findings(), target="http://target")
    root = ET.fromstring(output)
    assert root.tag == "testsuites"

def test_junit_counts():
    output = JUnitReporter().render(_sample_findings())
    root = ET.fromstring(output)
    suite = root.find("testsuite")
    assert suite.get("tests") == "3"
    assert suite.get("failures") == "2"  # CONFIRMED + LIKELY
    assert suite.get("skipped") == "0"

def test_junit_confirmed_is_failure():
    output = JUnitReporter().render([_make_finding(verdict="CONFIRMED")])
    root = ET.fromstring(output)
    case = root.find(".//testcase")
    assert case.find("failure") is not None

def test_junit_rejected_is_pass():
    output = JUnitReporter().render([_make_finding(verdict="REJECTED")])
    root = ET.fromstring(output)
    case = root.find(".//testcase")
    assert case.find("failure") is None
    assert case.find("skipped") is None

def test_junit_inconclusive_is_skipped():
    output = JUnitReporter().render([_make_finding(verdict="INCONCLUSIVE")])
    root = ET.fromstring(output)
    case = root.find(".//testcase")
    assert case.find("skipped") is not None

def test_junit_empty_findings():
    output = JUnitReporter().render([])
    root = ET.fromstring(output)
    assert root.find("testsuite").get("tests") == "0"

def test_junit_target_property():
    output = JUnitReporter().render(_sample_findings(), target="http://target")
    root = ET.fromstring(output)
    prop = root.find(".//property[@name='target']")
    assert prop is not None

def test_junit_custom_suite_name():
    output = JUnitReporter(suite_name="my-suite").render([_make_finding()])
    root = ET.fromstring(output)
    assert root.find("testsuite").get("name") == "my-suite"

def test_junit_redacts_pii():
    f = _make_finding(leaked=["root@internal.net"])
    output = JUnitReporter().render([f])
    assert "root@internal.net" not in output

def test_junit_xml_declaration():
    output = JUnitReporter().render([_make_finding()])
    assert output.startswith('<?xml version="1.0"')
