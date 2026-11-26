"""Erişim-kontrolü kategori matrisi testleri — durum önceliği, eşleme, Markdown ve JSON çıktıları."""
import json

from pentestai.models import Finding
from pentestai.report import JsonReporter, MarkdownReporter
from pentestai.report.access_control_matrix import AccessControlMatrix

KEYS = [
    "object_level_auth", "mass_assignment", "field_allow_listing", "client_side_auth",
    "server_side_auth", "rbac", "race_condition", "atomic_operation", "rls_misconfig",
    "deny_by_default", "least_privilege",
]


def _f(fid: str, vtype: str, verdict: str, parameter: str = "id") -> Finding:
    return Finding(id=fid, type=vtype, endpoint="/api/x", verdict=verdict, parameter=parameter)


def _by_key(findings: list[Finding]) -> dict:
    return {st.category.key: st for st in AccessControlMatrix().build(findings)}


def test_empty_findings_yield_11_untested_rows_in_order():
    rows = AccessControlMatrix().build([])
    assert [r.category.key for r in rows] == KEYS
    assert all(r.status == "TEST EDİLMEDİ" and r.finding_ids == [] for r in rows)


def test_confirmed_beats_rejected():
    st = _by_key([_f("F-1", "idor", "REJECTED"), _f("F-2", "idor", "CONFIRMED")])["object_level_auth"]
    assert st.status == "AÇIK"
    assert st.counts == {"REJECTED": 1, "CONFIRMED": 1}


def test_likely_beats_rejected():
    assert _by_key([_f("F-1", "idor", "REJECTED"), _f("F-2", "idor", "LIKELY")])[
        "object_level_auth"].status == "ŞÜPHELİ"


def test_only_rejected_is_clean():
    assert _by_key([_f("F-1", "idor", "REJECTED")])["object_level_auth"].status == "TEMİZ"


def test_only_inconclusive_is_inconclusive():
    assert _by_key([_f("F-1", "idor", "INCONCLUSIVE")])["object_level_auth"].status == "SONUÇSUZ"


def test_rbac_default_matches_deny_by_default_not_least_privilege():
    got = _by_key([_f("F-1", "rbac_violation", "CONFIRMED", "(rbac:default)")])
    assert got["deny_by_default"].status == "AÇIK"
    assert got["rbac"].status == "AÇIK"
    assert got["server_side_auth"].status == "AÇIK"
    assert got["least_privilege"].status == "TEST EDİLMEDİ"


def test_rbac_explicit_matches_least_privilege_not_deny_by_default():
    got = _by_key([_f("F-1", "rbac_violation", "CONFIRMED", "(rbac:explicit)")])
    assert got["least_privilege"].status == "AÇIK"
    assert got["deny_by_default"].status == "TEST EDİLMEDİ"


def test_race_atomic_split():
    atomic = _by_key([_f("F-1", "race_condition", "CONFIRMED", "(concurrency:atomic)")])
    assert atomic["atomic_operation"].status == "AÇIK"
    assert atomic["race_condition"].status == "TEST EDİLMEDİ"
    plain = _by_key([_f("F-2", "race_condition", "CONFIRMED", "(concurrency)")])
    assert plain["race_condition"].status == "AÇIK"
    assert plain["atomic_operation"].status == "TEST EDİLMEDİ"


def test_mass_assignment_matches_field_allow_listing_too():
    got = _by_key([_f("F-1", "mass_assignment", "REJECTED")])
    assert got["mass_assignment"].status == "TEMİZ"
    assert got["field_allow_listing"].status == "TEMİZ"


def test_markdown_section_rows_icons_and_notes():
    md = MarkdownReporter().render([
        _f("F-001", "idor", "CONFIRMED"), _f("F-002", "idor", "REJECTED"),
        _f("F-003", "mass_assignment", "LIKELY"), _f("F-004", "rls_misconfig", "INCONCLUSIVE"),
        _f("F-005", "bfla", "REJECTED"),
    ])
    assert "## Erişim Kontrolü Kategori Kapsamı" in md
    assert "| 1 | Nesne seviyesi yetkilendirme (BOLA/IDOR) | 🔴 AÇIK | F-001, F-002 | " \
           "CONFIRMED 1 · REJECTED 1 |" in md
    assert "🟠 ŞÜPHELİ" in md and "🟢 TEMİZ" in md and "🟡 SONUÇSUZ" in md
    assert "| 4 | İstemci tarafı yetkilendirme | ⚪ TEST EDİLMEDİ | — | " \
           "--client-side-scan (admin rolünde aktör gerekir) |" in md


def test_markdown_section_present_when_no_findings():
    md = MarkdownReporter().render([])
    assert "## Erişim Kontrolü Kategori Kapsamı" in md
    assert md.count("⚪ TEST EDİLMEDİ") == 11
    assert "--rbac config/rbac.yaml" in md


def test_markdown_truncates_more_than_five_ids():
    findings = [_f(f"F-{i}", "idor", "CONFIRMED") for i in range(1, 8)]
    md = MarkdownReporter().render(findings)
    assert "F-1, F-2, F-3, F-4, F-5, …" in md
    assert "F-1, F-2, F-3, F-4, F-5, F-6 |" not in md.split("## Erişim Kontrolü")[1].split("---")[0]


def test_json_access_control_categories():
    out = json.loads(JsonReporter().render_access_control([_f("F-1", "idor", "CONFIRMED")]))
    rows = out["access_control_categories"]
    assert [r["key"] for r in rows] == KEYS
    first = rows[0]
    assert set(first) == {"key", "title", "status", "finding_ids", "counts", "how_to_enable"}
    assert first["status"] == "AÇIK" and first["finding_ids"] == ["F-1"]
    assert first["counts"] == {"CONFIRMED": 1}
    assert rows[3]["status"] == "TEST EDİLMEDİ"


def test_json_findings_output_stays_flat_list():
    assert json.loads(JsonReporter().render([_f("F-1", "idor", "CONFIRMED")]))[0]["id"] == "F-1"
