"""LLM07 twin'i: vulnerable=CONFIRMED, hardened/near-miss≠CONFIRMED (GERÇEK oracle, ağsız)."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb import agent_leakage
from pentestai.oracle.base import CONFIRMED

CASES = agent_leakage.cases()


def test_names_unique_and_consistent() -> None:
    names = [c.name for c in CASES]
    assert len(names) == len(set(names))
    assert {n.rsplit(":", 1)[0] for n in names} == {"system-prompt-leakage-canary"}
    assert len(CASES) == 3
    assert {c.vuln_type for c in CASES} == {"system_prompt_leakage"}


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
async def test_case(case) -> None:
    finding = await case.run()
    if case.expected == "CONFIRMED":
        assert finding.verdict == CONFIRMED, finding
    else:
        assert case.expected == "not:CONFIRMED"
        assert finding.verdict != CONFIRMED, finding
