"""Kapsam matrisi CLI — OWASP Web/API/LLM kategorilerine göre KANITLI/DENEYSEL/BOŞLUK raporu.

Kullanım:
  python -m scripts.coverage_matrix                                  # markdown → stdout
  python -m scripts.coverage_matrix --out docs/KAPSAM_MATRISI.md     # dosyaya yaz
  python -m scripts.coverage_matrix --json runs/coverage.json        # JSON de yaz
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.coverage import CoverageMatrix  # noqa: E402

_HEADER = (
    "<!-- Bu dosya `python -m scripts.coverage_matrix --out docs/KAPSAM_MATRISI.md` ile "
    "üretilir; elle düzenleme. -->\n\n"
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OWASP kapsam matrisi üret")
    ap.add_argument("--out", help="markdown çıktı dosyası (varsayılan: stdout)")
    ap.add_argument("--json", help="JSON çıktı dosyası")
    args = ap.parse_args(argv)

    matrix = CoverageMatrix()
    md = matrix.to_markdown()

    if args.out:
        out = pathlib.Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_HEADER + md, encoding="utf-8", newline="\n")
        print(f"[kapsam] yazıldı: {out}")
    else:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        print(md)

    if args.json:
        jp = pathlib.Path(args.json)
        jp.parent.mkdir(parents=True, exist_ok=True)
        jp.write_text(json.dumps(matrix.to_dict(), ensure_ascii=False, indent=2),
                      encoding="utf-8", newline="\n")
        print(f"[kapsam] yazıldı: {jp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
