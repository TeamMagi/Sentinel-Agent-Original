"""EvidenceStore ve redact fonksiyonu testleri -- guvenlik-kritik redaction."""
import json
import re

from pentestai.evidence.store import EvidenceStore, redact, new_run_id


def test_redact_empty_string():
    assert redact("") == ""


def test_redact_bearer_token():
    text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
    result = redact(text)
    assert "eyJ" not in result
    assert "<REDACTED>" in result


def test_redact_auth_header_json():
    text = json.dumps({"authorization": "secret-token-123"})
    result = redact(text)
    assert "secret-token-123" not in result
    assert "<REDACTED>" in result


def test_redact_cookie_header():
    text = json.dumps({"cookie": "session=abc123"})
    result = redact(text)
    assert "abc123" not in result


def test_redact_x_api_key():
    text = json.dumps({"x-api-key": "my-secret-api-key"})
    result = redact(text)
    assert "my-secret-api-key" not in result


def test_redact_pii_key_email():
    text = json.dumps({"email": "user@example.com"})
    result = redact(text)
    assert "user@example.com" not in result


def test_redact_pii_key_password():
    text = json.dumps({"password": "hunter2"})
    result = redact(text)
    assert "hunter2" not in result


def test_redact_pii_key_case_insensitive():
    text = json.dumps({"Password": "secret123"})
    result = redact(text)
    assert "secret123" not in result


def test_redact_pii_key_apikey():
    text = json.dumps({"apikey": "sk-12345"})
    result = redact(text)
    assert "sk-12345" not in result


def test_redact_escaped_pii_key():
    inner = json.dumps({"email": "user@test.com"})
    outer = json.dumps({"body": inner})
    result = redact(outer)
    assert "user@test.com" not in result


def test_redact_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dummysig123abc"
    text = f"token is {jwt}"
    result = redact(text)
    assert "eyJ" not in result


def test_redact_bcrypt():
    bcrypt_hash = "$2b$12$LJ3m4ys3Lz0Y3x5Y1Z2W3eFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    text = f"hash: {bcrypt_hash}"
    result = redact(text)
    assert "$2b$" not in result


def test_redact_email_in_body():
    text = "Contact admin@example.org for details"
    result = redact(text)
    assert "admin@example.org" not in result
    assert "<REDACTED>" in result


def test_redact_iban():
    text = "IBAN: TR330006100519786457841326"
    result = redact(text)
    assert "TR330006100519786457841326" not in result


def test_redact_ssn():
    text = "SSN: 123-45-6789"
    result = redact(text)
    assert "123-45-6789" not in result


def test_redact_grouped_card():
    text = "Card: 4111 1111 1111 1111"
    result = redact(text)
    assert "4111" not in result


def test_redact_plain_card_valid_luhn():
    text = "card 4111111111111111 here"
    result = redact(text)
    assert "4111111111111111" not in result


def test_redact_plain_number_invalid_luhn_preserved():
    text = "id 1234567890123 ref"
    result = redact(text)
    assert "1234567890123" in result


def test_redact_tckn_valid_preserved_or_redacted():
    valid_tckn = "10000000146"
    text = f"tckn {valid_tckn} end"
    result = redact(text)
    assert valid_tckn not in result


def test_redact_tckn_invalid_checksum_preserved():
    invalid_tckn = "12345678901"
    text = f"id {invalid_tckn} end"
    result = redact(text)
    assert invalid_tckn in result


def test_redact_hex_hash():
    sha256 = "a" * 64
    text = f"hash: {sha256}"
    result = redact(text)
    assert sha256 not in result


def test_redact_preserves_normal_text():
    text = "This is a normal log message with no secrets"
    assert redact(text) == text


def test_redact_multiple_patterns():
    text = json.dumps({
        "authorization": "Bearer abc123",
        "email": "test@test.com",
        "data": "safe content",
    })
    result = redact(text)
    assert "abc123" not in result
    assert "test@test.com" not in result
    assert "safe content" in result


def test_new_run_id_format():
    rid = new_run_id()
    assert rid.startswith("run-")
    assert re.match(r"run-\d{8}-\d{6}-[0-9a-f]{6}", rid)


def test_new_run_id_unique():
    ids = {new_run_id() for _ in range(10)}
    assert len(ids) == 10


def test_evidence_store_redact_delegates():
    assert EvidenceStore.redact("Bearer xyz123") == redact("Bearer xyz123")


def test_evidence_store_new_run_id():
    rid = EvidenceStore.new_run_id()
    assert rid.startswith("run-")


def test_save_run_creates_directory(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    root = store.save_run(rid, [])
    assert root.exists()
    assert (root / "findings.json").exists()
    findings = json.loads((root / "findings.json").read_text(encoding="utf-8"))
    assert findings == []


def test_save_run_writes_reports(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    root = store.save_run(
        rid, [],
        report_md="# Report",
        report_html="<html></html>",
    )
    assert (root / "report.md").exists()
    assert (root / "report.html").exists()


def test_save_run_config_snapshot(tmp_path):
    store = EvidenceStore(out_dir=str(tmp_path))
    rid = store.new_run_id()
    config = {"target": "http://localhost", "scan_mode": "full"}
    root = store.save_run(rid, [], config_snapshot=config)
    saved = json.loads((root / "config.snapshot.json").read_text(encoding="utf-8"))
    assert saved["target"] == "http://localhost"
