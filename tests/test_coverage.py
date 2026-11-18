"""Kapsam matrisi testleri — ağsız. Drift-guard + durum hesabı + markdown."""
from __future__ import annotations

import json

from pentestai.classify import PROVEN_TYPES, TYPE_META, TypeMeta
from pentestai.coverage import BOSLUK, DENEYSEL, KANITLI, CoverageMatrix


def test_every_type_is_mapped_or_exempt() -> None:
    assert CoverageMatrix().unmapped_types() == []


def test_proven_count_consistent() -> None:
    s = CoverageMatrix().summary()
    real_proven = {t for t in PROVEN_TYPES if t in TYPE_META and t != "generic"}
    assert s["proven"] == len(real_proven)
    assert s["proven"] + s["experimental"] == s["total_types"]
    assert s["total_types"] == len([t for t in TYPE_META if t != "generic"])


def test_unmapped_type_is_reported_not_dropped() -> None:
    m = CoverageMatrix(type_meta={"foo": TypeMeta("CWE-1", "ZZ99", "Low")},
                       proven_types=frozenset(), catalogs={"c": {"A01": "x"}})
    assert m.unmapped_types() == ["foo"]
    assert m.summary()["unmapped_types"] == ["foo"]


def test_status_kanitli_deneysel_bosluk() -> None:
    meta = {
        "p": TypeMeta("CWE-1", "A01", "High"),
        "e": TypeMeta("CWE-2", "A02", "High"),
    }
    m = CoverageMatrix(type_meta=meta, proven_types=frozenset({"p"}),
                       catalogs={"cat": {"A01": "bir", "A02": "iki", "A03": "üç"}},
                       extra_map={}, gap_families=())
    rows = {r["id"]: r for r in m.category_rows()["cat"]}
    assert rows["A01"]["status"] == KANITLI and rows["A01"]["proven"] == 1
    assert rows["A02"]["status"] == DENEYSEL and rows["A02"]["experimental"] == 1
    assert rows["A03"]["status"] == BOSLUK and rows["A03"]["types"] == []
    gaps = m.gap_analysis()
    assert [g["id"] for g in gaps["empty_categories"]] == ["A03"]


def test_gap_family_counterpart_detected() -> None:
    from pentestai.coverage import GapFamily
    g = (GapFamily("x", ("A01",), ("foo",), "n"), GapFamily("y", ("A01",), ("yok",), "n"))
    m = CoverageMatrix(type_meta={"foo": TypeMeta("CWE-1", "A01", "Low")},
                       proven_types=frozenset(), catalogs={"c": {"A01": "x"}}, gap_families=g)
    fams = {f["name"]: f for f in m.gap_analysis()["missing_families"]}
    assert fams["x"]["has_counterpart"] and not fams["y"]["has_counterpart"]


def test_markdown_and_json() -> None:
    m = CoverageMatrix()
    md = m.to_markdown()
    for h in ("# Kapsam Matrisi", "## Genel özet", "## Boşluk analizi",
              "OWASP Top 10 2021", "API Security Top 10 2023", "LLM Apps 2025"):
        assert h in md
    d = m.to_dict()
    assert json.loads(json.dumps(d, ensure_ascii=False)) == d
