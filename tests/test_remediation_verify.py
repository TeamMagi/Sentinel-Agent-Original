"""RemediationVerifier testleri — fix-verification (düzeltme doğrulama)."""
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report.remediation_verify import RemediationVerifier


def _make_finding(fid="F-001", vtype="idor", verdict="CONFIRMED", endpoint="/api/orders/{id}",
                  method="GET", param="id"):
    ev = Evidence(
        attack_request=CapturedRequest(method=method, url="http://target" + endpoint),
        attack_response=NormalizedResponse(status=200, body_text='{"ok":true}'),
        positive_control=True, negative_control=True, baseline_stable=True,
    )
    return Finding(id=fid, type=vtype, endpoint=endpoint, method=method, parameter=param,
                   verdict=verdict, confidence="high", severity="High", evidence=ev)


def test_fixed_when_confirmed_disappears():
    prev = [_make_finding(verdict="CONFIRMED")]
    curr = [_make_finding(verdict="REJECTED")]
    result = RemediationVerifier().verify(prev, curr)
    assert len(result.fixed) == 1
    assert result.clean is True

def test_fixed_when_finding_gone():
    prev = [_make_finding(verdict="CONFIRMED")]
    curr = []
    result = RemediationVerifier().verify(prev, curr)
    assert len(result.fixed) == 1
    assert result.clean is True

def test_failed_repair():
    prev = [_make_finding(verdict="CONFIRMED")]
    curr = [_make_finding(verdict="CONFIRMED")]
    result = RemediationVerifier().verify(prev, curr)
    assert len(result.failed_repair) == 1
    assert result.clean is False

def test_regressed():
    prev = []
    curr = [_make_finding(verdict="CONFIRMED")]
    result = RemediationVerifier().verify(prev, curr)
    assert len(result.regressed) == 1
    assert result.clean is False

def test_empty_both():
    result = RemediationVerifier().verify([], [])
    assert result.clean is True
    assert len(result.outcomes) == 0

def test_rejected_not_tracked():
    prev = [_make_finding(verdict="REJECTED")]
    curr = [_make_finding(verdict="CONFIRMED")]
    result = RemediationVerifier().verify(prev, curr)
    assert len(result.regressed) == 1
    assert len(result.fixed) == 0

def test_markdown_output():
    prev = [_make_finding(verdict="CONFIRMED")]
    curr = [_make_finding(verdict="REJECTED")]
    result = RemediationVerifier().verify(prev, curr)
    md = result.to_markdown()
    assert "fixed" in md.lower()
    assert "Sentinel-Agent" in md

def test_mixed_outcomes():
    f1 = _make_finding("F-001", "idor", "CONFIRMED", "/api/a")
    f2 = _make_finding("F-002", "bfla", "CONFIRMED", "/api/b")
    f3 = _make_finding("F-003", "csrf", "REJECTED", "/api/c", method="POST")
    prev = [f1, f2, f3]
    curr_f1 = _make_finding("F-001", "idor", "REJECTED", "/api/a")
    curr_f2 = _make_finding("F-002", "bfla", "CONFIRMED", "/api/b")
    curr_f4 = _make_finding("F-004", "xxe", "CONFIRMED", "/api/d")
    curr = [curr_f1, curr_f2, curr_f4]
    result = RemediationVerifier().verify(prev, curr)
    assert len(result.fixed) == 1
    assert len(result.failed_repair) == 1
    assert len(result.regressed) == 1
    assert result.clean is False
