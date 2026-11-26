"""Faz 0 / A2 — keşif (yüzey) metrikleri. Ağsız, saf hesap + CLI çıktısı."""
import json
from pathlib import Path

from pentestai.bench import Benchmark
from pentestai.bench.surface import evaluate_surface, load_surface_entries, load_surface_truth
from pentestai.models import SurfaceEntry
from scripts.benchmark import main as benchmark_main

EXPECTED = """cases:
  - type: idor
    endpoint: /users/{id}
    expect: CONFIRMED
"""

TRUTH = """endpoints:
  - "GET /users/{username}"
  - method: POST
    path: /users/register
    params: [username, password, email]
  - method: GET
    path: /orders/{id}
    params: [id]
  - "GET /admin"
"""

SURFACE = [
    {"method": "GET", "path_template": "/users/{id}", "params": [],
     "sources": ["openapi"], "tested": True, "tests": ["idor"]},
    {"method": "POST", "path_template": "/users/register",
     "params": ["username", "password"], "sources": ["config"], "tested": False, "tests": []},
    {"method": "GET", "path_template": "/missing", "params": [],
     "sources": ["wordlist"], "tested": False, "tests": []},
]


def _write(tmp_path: Path):
    expected = tmp_path / "expected.yaml"
    expected.write_text(EXPECTED, encoding="utf-8")
    truth = tmp_path / "target.surface.yaml"
    truth.write_text(TRUTH, encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text("[]", encoding="utf-8")
    (run_dir / "surface.json").write_text(json.dumps(SURFACE), encoding="utf-8")
    return expected, truth, run_dir


def test_surface_metrics_hand_computed(tmp_path):
    _expected, truth, run_dir = _write(tmp_path)
    metrics = evaluate_surface(
        load_surface_entries(run_dir / "surface.json"), load_surface_truth(truth))

    # 4 gerçek uçtan 2'si bulundu → 0.5; 3 bulunandan 1'i yanlış → 1/3.
    assert metrics.endpoint_recall == 0.5
    assert abs(metrics.false_endpoint_rate - 1 / 3) < 1e-9
    # 4 gerçek uçtan yalnızca 1'i test edilmiş → 0.25.
    assert metrics.test_coverage == 0.25
    # "Eşleşen uçlarda" params paydası: GET users (params yok) + POST register (3) = 3;
    # POST'ta 2 params yakalandı → 2/3. (Eşleşmeyen GET orders paydaya girmez.)
    assert abs(metrics.param_recall - 2 / 3) < 1e-9
    assert metrics.missed == ["GET /admin", "GET /orders/{id}"]
    assert metrics.false_endpoints == ["GET /missing"]
    assert metrics.sources == {"config": 1, "openapi": 1}


def test_normalization_matches_id_and_username_and_trailing_slash(tmp_path):
    truth_path = _write_truth("endpoints:\n  - 'GET /users/{username}/'\n", tmp_path)
    entries = [SurfaceEntry(method="GET", path_template="/users/{id}", tested=True)]
    metrics = evaluate_surface(entries, load_surface_truth(truth_path))
    assert metrics.endpoint_recall == 1.0 and metrics.missed == []


def _write_truth(text: str, tmp_path: Path):
    path = tmp_path / "truth.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_empty_found_has_zero_false_endpoint_rate(tmp_path):
    truth = load_surface_truth(_write_truth(TRUTH, tmp_path))
    metrics = evaluate_surface([], truth)
    assert metrics.endpoint_recall == 0.0
    assert metrics.false_endpoint_rate == 0.0
    assert metrics.test_coverage == 0.0
    assert metrics.param_recall is None


def test_cli_without_surface_keeps_output_identical(tmp_path):
    expected, _truth, run_dir = _write(tmp_path)
    out = tmp_path / "out"
    rc = benchmark_main(["--run", str(run_dir), "--expected", str(expected), "--out", str(out)])
    assert rc == 0
    md = (out / "benchmark.md").read_text(encoding="utf-8")
    payload = json.loads((out / "benchmark.json").read_text(encoding="utf-8"))
    # Eski davranış birebir: yalnız BenchmarkResult render'ı, surface anahtarı YOK.
    assert md == Benchmark.from_yaml(expected).evaluate([], target="").to_markdown()
    assert "Keşif (yüzey)" not in md
    assert "surface" not in payload


def test_cli_missing_surface_json_reports_clear_turkish_error(tmp_path, capsys):
    expected, truth, run_dir = _write(tmp_path)
    (run_dir / "surface.json").unlink()
    rc = benchmark_main(["--run", str(run_dir), "--expected", str(expected),
                         "--surface", str(truth)])
    assert rc == 2
    assert "surface.json yok" in capsys.readouterr().err


def test_cli_with_surface_adds_section_json_and_console_line(tmp_path, capsys):
    expected, truth, run_dir = _write(tmp_path)
    out = tmp_path / "out"
    rc = benchmark_main(["--run", str(run_dir), "--expected", str(expected),
                         "--surface", str(truth), "--out", str(out)])
    assert rc == 0
    md = (out / "benchmark.md").read_text(encoding="utf-8")
    payload = json.loads((out / "benchmark.json").read_text(encoding="utf-8"))
    assert "## Keşif (yüzey) metrikleri" in md
    assert payload["surface"]["endpoint_recall"] == 0.5
    assert payload["surface"]["param_recall"] == 0.6667
    assert "[surface] uç-recall=50.0%" in capsys.readouterr().out


def test_suite_optional_surface_field_is_aggregated(tmp_path, capsys):
    base = tmp_path
    (base / "exp.yaml").write_text(EXPECTED, encoding="utf-8")
    (base / "truth.yaml").write_text(TRUTH, encoding="utf-8")
    run_dir = base / "run"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text("[]", encoding="utf-8")
    (run_dir / "surface.json").write_text(json.dumps(SURFACE), encoding="utf-8")
    suite = base / "suite.yaml"
    suite.write_text(
        "targets:\n"
        "  - name: t1\n"
        "    expected: exp.yaml\n"
        "    findings: run/findings.json\n"
        "    surface: truth.yaml\n",
        encoding="utf-8")
    out = base / "out"
    rc = benchmark_main(["--suite", str(suite), "--out", str(out)])
    assert rc == 0
    md = (out / "benchmark_suite.md").read_text(encoding="utf-8")
    payload = json.loads((out / "benchmark_suite.json").read_text(encoding="utf-8"))
    assert "## Keşif (yüzey) metrikleri" in md
    assert payload["surface"]["endpoint_recall"] == 0.5
    assert "[surface]" in capsys.readouterr().out
