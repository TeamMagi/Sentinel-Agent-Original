"""SQLi gelişmiş twin'leri: vulnerable=CONFIRMED, hardened/near-miss≠CONFIRMED (GERÇEK oracle, ağsız)."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb import sqli_advanced
from pentestai.oracle.base import CONFIRMED

CASES = sqli_advanced.cases()


def test_names_unique_and_prefixed() -> None:
    names = [c.name for c in CASES]
    assert len(names) == len(set(names))
    assert {n.split(":", 1)[0] for n in names} == {
        "sqli-boolean-blind", "sqli-union", "sqli-second-order"}
    assert {c.vuln_type for c in CASES} == {"sqli"}
    for t in sqli_advanced.TWINS:
        cats = {c.category for c in CASES if c.name.startswith(t.name + ":")}
        assert cats == {"positive", "negative", "near_miss"}


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
async def test_case(case) -> None:
    finding = await case.run()
    if case.expected == "CONFIRMED":
        assert finding.verdict == CONFIRMED, finding
    else:
        assert case.expected == "not:CONFIRMED"
        assert finding.verdict != CONFIRMED, finding
