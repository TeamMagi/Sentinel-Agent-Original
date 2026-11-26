<!-- T4 — GERÇEK koşum sonucu. Elle YAZILMAZ; aşağıdaki komutla yeniden üretilir.
     Bu dosya, README'deki rakamın tek kaynağıdır (runs/ git-ignore'lu olduğu için
     koşum artefaktı repoda tutulamaz; sonuç burada sabitlenir). -->

# Juice Shop — gerçek koşum sonucu (T4)

| | |
|---|---|
| **Tarih** | 2026-11-26 (önceki: 2026-09-18, `8caeec0`) |
| **Hedef** | OWASP Juice Shop @ `http://localhost:3000` |
| **Kod sürümü** | `633a328` |
| **LLM** | `--llm none` — **hiç LLM kullanılmadı** |
| **Vaka seti** | [`juiceshop.expected.yaml`](juiceshop.expected.yaml) — 8 etiketli vaka (4 pozitif / 4 negatif — `crlf_injection @ /redirect` FP kapanı eklendi) |

## Yeniden üretme

```bash
python -m scripts.bootstrap_demo --base-url http://localhost:3000 --out /tmp/js   # hesap + config
# /tmp/js/endpoints.yaml'ı 8 vakayı kapsayacak şekilde genişlet (basket/{id}, products/search?q,
# api/products, rest/user/login, redirect?to) ve scope budget'ını ~2000 isteğe çıkar
python -m scripts.run_scan --scope /tmp/js/scope.yaml --actors /tmp/js/actors.yaml \
    --endpoints /tmp/js/endpoints.yaml --mode active --llm none --out runs/juiceshop/
python -m scripts.benchmark --run runs/juiceshop/run-* \
    --expected benchmarks/juiceshop.expected.yaml --target "OWASP Juice Shop"
```

---


**Hedef:** `OWASP Juice Shop (--llm none)`

| Metrik | Değer |
|---|---|
| Precision | **100.0%** |
| Recall | **100.0%** |
| False-positive oranı | **0.0%** |
| F1 | 100.0% |
| TP / FN / FP / TN | 4 / 0 / 0 / 4 |

## Vakalar

| Vaka | Beklenen | Gerçek | Sonuç |
|---|---|---|---|
| `idor @ GET /rest/basket/{id}` | CONFIRMED | CONFIRMED | ✅ TP |
| `sqli @ GET /rest/products/search` | CONFIRMED | CONFIRMED | ✅ TP |
| `jwt @ GET /rest/basket/{id}` | CONFIRMED | CONFIRMED | ✅ TP |
| `info_leak @ GET /rest/products/search` | CONFIRMED | CONFIRMED | ✅ TP |
| `unauthorized_access @ GET /rest/products/search` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /api/products` | not_vulnerable | LIKELY | ✅ TN |
| `idor @ GET /rest/user/login` | not_vulnerable | absent | ✅ TN |
| `crlf_injection @ GET /redirect` | not_vulnerable | absent | ✅ TN |

## Etiketsiz CONFIRMED bulgular (metriklere katılmaz)

- `idor @ GET /api/Users/{id}`
- `info_leak @ GET /api/Users/{id}`
- `info_leak @ GET /rest/basket/{id}`
- `rate_limit @ GET /rest/basket/{id}`

---

## Bu sayı ne demek, ne demek DEĞİL

- **Precision/recall etiketli 8 vaka ÜZERİNDEDİR** — aracın tüm çıktısı üzerinde değil. Koşum
  toplam 84 bulgu üretti; bunların 9'u CONFIRMED, 4'ü etiket setinde yok (yukarıda listeli)
  ve metriklere **katılmaz**.
- **FP-rate %0**, 4 negatif vakanın ("FP kapanı") hiçbirinde yanlış CONFIRMED çıkmadığı anlamına
  gelir; "araç hiç yanlış pozitif üretmez" anlamına **gelmez**.
- Juice Shop **kalibre** bir hedeftir (etiketler ona bakılarak konmuştur) → bu metrikler
  iyimserdir ve **genellemeyi ölçmez**. Genelleme yalnızca holdout hedefte ölçülür (bkz.
  [`suite.yaml`](suite.yaml) ve README'deki holdout notu).
