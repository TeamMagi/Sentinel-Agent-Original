"""Hesap ele geçirme twin'leri (password_reset_abuse, mfa_bypass) — ağsız."""
from __future__ import annotations

import pytest

from pentestai.bench.kolb.account_takeover import TWINS, cases
from pentestai.oracle.base import CONFIRMED


@pytest.mark.parametrize("twin", TWINS, ids=lambda t: t.name)
async def test_twin_verdicts(twin):
    vuln, hard = await twin.run()
    near = await twin.near_miss()
    assert vuln.verdict == CONFIRMED, f"{twin.name}:vulnerable beklenen CONFIRMED, geldi {vuln.verdict}"
    assert hard.verdict != CONFIRMED, f"{twin.name}:hardened CONFIRMED olmamalı"
    assert near.verdict != CONFIRMED, f"{twin.name}:near-miss CONFIRMED olmamalı"


async def test_cases_consistent_and_pass():
    cs = cases()
    names = [c.name for c in cs]
    assert len(names) == len(set(names)) == 3 * len(TWINS)
    assert {c.vuln_type for c in cs} == {t.vuln_type for t in TWINS}
    for c in cs:
        f = await c.run()
        assert f.type == c.vuln_type, c.name
        assert (f.verdict == CONFIRMED) == (c.expected == "CONFIRMED"), c.name


async def test_no_raw_token_in_evidence():
    """Token/OTP SIR'dır — hiçbir twin bulgusunun evidence'ında ham token değeri yazılı olmamalı."""
    from pentestai.bench.kolb.account_takeover import _BOGUS_TOKEN, _VALID_TOKEN

    for twin in TWINS:
        vuln, hard = await twin.run()
        near = await twin.near_miss()
        for f in (vuln, hard, near):
            blob = " ".join(f.evidence.leaked_markers) + (f.triage_note or "")
            assert _VALID_TOKEN not in blob
            assert _BOGUS_TOKEN not in blob
