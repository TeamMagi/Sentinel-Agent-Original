"""Auth-akışı twin'leri (oauth_misconfig, user_enumeration, default_credentials, session_lifecycle) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.auth_flow import TWINS, cases
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln = await twin.one("vuln")
    hard = await twin.one("hardened")
    near = await twin.one("near_miss")
    assert vuln.verdict == CONFIRMED
    assert hard.verdict != CONFIRMED
    assert near.verdict != CONFIRMED


async def test_cases_consistent_and_pass():
    cs = cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(TWINS)
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert f.type == c.vuln_type, c.name
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name
