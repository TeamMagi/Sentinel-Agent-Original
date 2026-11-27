"""Girdi kapsamı raporu — uç başına test edilen parametre sayısı. Faz 3 / T3 (ağsız)."""
from pentestai.models import SurfaceEntry
from pentestai.report.input_coverage import InputCoverageReporter


def test_empty_entries_produce_no_section():
    assert InputCoverageReporter.render_markdown([]) == ""


def test_summary_line_counts_tested_endpoints_and_inputs():
    entries = [
        SurfaceEntry(method="GET", path_template="/a", params=["q", "sort"],
                    tested=True, tests=["injection"], tested_params=["q"]),
        SurfaceEntry(method="GET", path_template="/b", params=["id"],
                    tested=False, tests=[], tested_params=[]),
    ]
    md = InputCoverageReporter.render_markdown(entries)
    assert "## Girdi Kapsamı" in md
    assert "Test edilen uç sayısı:** 1/2" in md
    assert "Toplam test edilen girdi:** 1" in md
    assert "GET /a" in md and "1/2" in md   # tested_params/params tablo satırı


def test_table_limited_to_top_n_by_known_param_count():
    entries = [
        SurfaceEntry(method="GET", path_template=f"/e{i}", params=[f"p{i}"],
                    tested=True, tests=["injection"], tested_params=[f"p{i}"])
        for i in range(15)
    ]
    md = InputCoverageReporter.render_markdown(entries, top_n=10)
    assert md.count("| `GET /e") == 10
