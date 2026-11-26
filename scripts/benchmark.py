"""Sentinel-Agent kalibrasyon CLI — bir koşumu etiketli vaka setine karşı değerlendirir. Q3.

Örnek:
  python -m scripts.benchmark --run runs/run-20260915-120000
  python -m scripts.benchmark --findings runs/.../findings.json \
      --expected benchmarks/juiceshop.expected.yaml --target http://localhost:3000

Çıktı: precision / recall / FP-rate özeti (stdout) + koşum dizinine benchmark.md & benchmark.json.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.bench import Benchmark  # noqa: E402
from pentestai.bench.suite import BenchmarkSuite, load_suite_findings  # noqa: E402
from pentestai.bench.surface import (  # noqa: E402
    combine_surface_metrics,
    console_line,
    evaluate_surface,
    load_surface_entries,
    load_surface_truth,
)

_DEFAULT_EXPECTED = "benchmarks/juiceshop.expected.yaml"


def _surface_for_run(args, findings_path: pathlib.Path):
    """`--surface` verildiyse koşum dizinindeki surface.json ile metrikleri hesaplar."""
    if not args.surface:
        return None
    run_root = pathlib.Path(args.run) if args.run else findings_path.parent
    surface_json = run_root / "surface.json"
    if not surface_json.exists():
        print(f"[benchmark] HATA: {surface_json} yok — tarama bu sürümden önce mi koşuldu?",
              file=sys.stderr)
        return False
    metrics = evaluate_surface(
        load_surface_entries(surface_json), load_surface_truth(args.surface))
    return metrics


def _suite_surface(meta: list[dict], base: pathlib.Path):
    """suite.yaml hedeflerinde opsiyonel `surface:` varsa metrikleri toplar (yoksa atlanır)."""
    metrics = []
    for target in meta:
        surface_yaml = target.get("surface")
        if not surface_yaml:
            continue
        findings = target.get("findings")
        run_root = (base / findings).parent if findings else base
        surface_json = run_root / "surface.json"
        if not surface_json.exists():
            print(f"[suite] UYARI: {target.get('name')} surface.json yok — atlandı",
                  file=sys.stderr)
            continue
        truth_path = pathlib.Path(surface_yaml)
        if not truth_path.is_absolute():
            truth_path = base / truth_path
        metrics.append(evaluate_surface(
            load_surface_entries(surface_json), load_surface_truth(truth_path)))
    return combine_surface_metrics(metrics)


def _run_suite(suite_path: str, out: str | None) -> int:
    """Çok-hedefli değerlendirme (R-A3): suite.yaml → birleşik precision/recall/FP tablosu."""
    base = pathlib.Path(suite_path).parent
    suite, meta = BenchmarkSuite.from_yaml(suite_path)
    findings_by_target = load_suite_findings(meta, base)
    result = suite.evaluate(findings_by_target)
    out_dir = pathlib.Path(out) if out else base
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = result.to_markdown()
    payload = result.to_dict()
    surface = _suite_surface(meta, base)
    if surface is not None:   # opsiyonel alan yoksa çıktı BİREBİR eskisi gibi kalır
        markdown = markdown.rstrip() + "\n\n" + surface.to_markdown()
        payload["surface"] = surface.to_dict()
        print(console_line(surface))
    (out_dir / "benchmark_suite.md").write_text(markdown, encoding="utf-8")
    (out_dir / "benchmark_suite.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    have = sorted(findings_by_target)
    print(f"[suite] {len(suite.targets)} hedef · findings yüklendi: {have or 'yok (tümü FN/TN)'}")
    print(f"[suite] TOPLAM precision={result.precision:.1%} · recall={result.recall:.1%} · "
          f"FP-rate={result.fp_rate:.1%} · {result.cases} vaka")
    if result.has_holdout:   # AS-5: gerçek genelleme yalnızca holdout'ta ölçülür
        c, h = result.calibrated_metrics, result.holdout_metrics
        gap = result.generalization_gap
        print(f"[suite] kalibre ({c.targets} hedef): precision={c.precision:.1%} · "
              f"recall={c.recall:.1%} · FP-rate={c.fp_rate:.1%}")
        print(f"[suite] HOLDOUT ({h.targets} hedef): precision={h.precision:.1%} · "
              f"recall={h.recall:.1%} · FP-rate={h.fp_rate:.1%}")
        print(f"[suite] genelleme farkı (pozitif = holdout'ta daha kötü): "
              f"precision={gap['precision']:+.4f} · recall={gap['recall']:+.4f} · "
              f"FP-rate={gap['fp_rate']:+.4f}")
    else:
        print("[suite] holdout hedef yok → bu metrikler KALİBRASYON metrikleridir "
              "(genelleme ölçülmedi; bkz. benchmarks/suite.yaml 'holdout')")
    print(f"[suite] yazıldı: {out_dir / 'benchmark_suite.md'}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="benchmark",
                                description="Sentinel-Agent kalibrasyon/benchmark (precision/recall/FP)")
    p.add_argument("--expected", default=_DEFAULT_EXPECTED, help="etiketli vaka seti (YAML)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--run", help="koşum dizini (içindeki findings.json okunur; çıktı buraya yazılır)")
    src.add_argument("--findings", help="doğrudan findings.json yolu")
    src.add_argument("--suite", help="çok-hedefli takım (benchmarks/suite.yaml) — R-A3")
    p.add_argument("--target", default="", help="rapora yazılacak hedef etiketi")
    p.add_argument("--surface",
                   help="hedefin GERÇEK uç listesi (benchmarks/<hedef>.surface.yaml) — keşif "
                        "(yüzey) metriklerini de üretir; verilmezse çıktı değişmez")
    p.add_argument("--out", help="benchmark.md/json çıktı dizini (varsayılan: --run dizini)")
    p.add_argument("--min-precision", type=float, default=None,
                   help="regresyon kapısı: precision bu değerin altındaysa çıkış kodu 2")
    p.add_argument("--min-recall", type=float, default=None,
                   help="regresyon kapısı: recall bu değerin altındaysa çıkış kodu 2")
    args = p.parse_args(argv)

    if args.suite:
        return _run_suite(args.suite, args.out)

    run_dir = pathlib.Path(args.run) if args.run else None
    findings_path = pathlib.Path(args.findings) if args.findings else run_dir / "findings.json"
    out_dir = pathlib.Path(args.out) if args.out else (run_dir or findings_path.parent)

    bench = Benchmark.from_yaml(args.expected)
    findings = Benchmark.load_findings(findings_path)
    result = bench.evaluate(findings, target=args.target)

    surface = _surface_for_run(args, findings_path)
    if surface is False:   # --surface verildi ama surface.json yok → anlaşılır hata
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = result.to_markdown()
    payload = result.to_dict()
    if surface is not None:   # --surface yoksa çıktı BİREBİR eskisi gibi kalır
        markdown = markdown.rstrip() + "\n\n" + surface.to_markdown()
        payload["surface"] = surface.to_dict()
    (out_dir / "benchmark.md").write_text(markdown, encoding="utf-8")
    (out_dir / "benchmark.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[benchmark] precision={result.precision:.1%} · recall={result.recall:.1%} · "
          f"FP-rate={result.fp_rate:.1%} · TP/FN/FP/TN={result.tp}/{result.fn}/{result.fp}/{result.tn}")
    if surface is not None:
        print(console_line(surface))
    print(f"[benchmark] yazıldı: {out_dir / 'benchmark.md'}")

    if args.min_precision is not None and result.precision < args.min_precision:
        print(f"[benchmark] precision {result.precision:.1%} < eşik {args.min_precision:.1%}")
        return 2
    if args.min_recall is not None and result.recall < args.min_recall:
        print(f"[benchmark] recall {result.recall:.1%} < eşik {args.min_recall:.1%}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
