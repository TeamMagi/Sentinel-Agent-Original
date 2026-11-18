"""Server-side twin'leri (prototype pollution, cache, host header, CRLF) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.server_side import TWINS, cases
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln = await twin.vulnerable()
    hard = await twin.hardened()
    near = await twin.near_miss()
    assert vuln.verdict == CONFIRMED
    assert hard.verdict != CONFIRMED
    assert near.verdict != CONFIRMED


async def test_proto_pollution_stores_key_not_confirmed():
    """`__proto__` meşru veri olarak saklanıp aynı nesnede geri veriliyorsa kanıt değildir."""
    twin = next(t for t in TWINS if t.name == "prototype-pollution-merge")
    assert (await twin.stores_key()).verdict != CONFIRMED


async def test_cases_consistent_and_pass():
    cs = cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(TWINS) + 1   # +1: prototype-pollution stores-key
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name
