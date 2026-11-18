"""İş mantığı twin'leri: vulnerable→CONFIRMED, hardened/near-miss→CONFIRMED değil."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.business_logic import TWINS, cases


def test_vaka_adlari_ve_sayisi():
    names = [c.name for c in cases()]
    assert len(names) == 9
    for prefix in ("biz-negative-amount", "biz-coupon-reuse", "biz-workflow-bypass"):
        for suffix in ("vulnerable", "hardened", "near-miss"):
            assert f"{prefix}:{suffix}" in names
    assert {t.vuln_type for t in TWINS} == {"negative_amount", "coupon_reuse", "workflow_bypass"}


@pytest.mark.parametrize("case", cases(), ids=lambda c: c.name)
async def test_twin_vakasi(case):
    finding = await case.run()
    assert finding.type == case.vuln_type
    if case.expected == "CONFIRMED":
        assert finding.verdict == "CONFIRMED", finding.triage_note
        assert finding.evidence.leaked_markers
    else:
        assert finding.verdict != "CONFIRMED"
