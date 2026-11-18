"""Ajan ek twin'leri: vulnerable=CONFIRMED, hardened/near-miss≠CONFIRMED (GERÇEK oracle, ağsız)."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb import agent_extra
from pentestai.oracle.base import CONFIRMED

CASES = agent_extra.cases()


def test_names_unique_and_consistent() -> None:
    names = [c.name for c in CASES]
    assert len(names) == len(set(names))
    prefixes = {t.name for t in agent_extra.TWINS}
    assert {n.rsplit(":", 1)[0] for n in names} == prefixes
    assert len(CASES) == 3 * len(agent_extra.TWINS)
    assert {c.vuln_type for c in CASES} == {t.vuln_type for t in agent_extra.TWINS}


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
async def test_case(case) -> None:
    finding = await case.run()
    if case.expected == "CONFIRMED":
        assert finding.verdict == CONFIRMED, finding
    else:
        assert case.expected == "not:CONFIRMED"
        assert finding.verdict != CONFIRMED, finding
