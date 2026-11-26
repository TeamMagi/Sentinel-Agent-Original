<!-- GERÇEK koşum sonucu (Faz 0 temel çizgisi). Elle YAZILMAZ; aşağıdaki komutlarla yeniden üretilir. -->

# Keşif (yüzey) — URL-only temel çizgi

| | |
|---|---|
| **Tarih** | 2026-11-26 |
| **Mod** | **URL-only**: uç listesi (`--endpoints/--openapi/--har`) VERİLMEDEN; yalnız otomatik keşif (wordlist + GraphQL + provider) · `--llm none` |
| **Yer-gerçeği** | `benchmarks/<hedef>.surface.yaml` (hedefin kendi spec'i / sunucu kodu; araç çıktısından bağımsız) |

## Sonuç

| Hedef | Gerçek uç | Bulunan (doğru) | Uç-recall | Yanlış uç | Test kapsamı | Uçtan uca açık recall |
|---|---|---|---|---|---|---|
| VAmPI | 13 | 2 (`GET /`, `GET /me`) | **%15.4** | %0 | %15.4 | **%0** (0/4) |
| crAPI | 44 | 0 | **%0** | %100 (yalnız `GET /` tohumu) | %0 | **%0** (0/5) |
| Juice Shop | 138 | 0 | **%0** | %100 | %0 | **%0** (0/4) |

Karşılaştırma: aynı hedeflerde uç listesi ELLE verildiğinde açık recall'u %100'dür
(`*.result.md`). Aradaki fark tamamen **keşif** eksikliğidir — Faz 1-4'ün hedefi bu.

## Neden bu kadar düşük (teşhis)

- Wordlist yalnız `/api/`, `/rest/`, `/` öneklerini dener; crAPI'nin servis önekleri
  (`/identity/api/...`, `/community/api/...`, `/workshop/api/...`) hiç denenmez.
- Juice Shop'ta `/api/products` ve `/api/users` bulundu, ama gerçek route'lar `/api/Products` ve
  `/api/Users` (Express büyük/küçük harf duyarsız eşler). Metrik büyük/küçük harf DUYARLI → sayılmadı.
- OpenAPI otomatik bulma, JS bundle → keşif, tarayıcıyla gezinme henüz YOK (Faz 1-2).

## Yeniden üretme

```bash
python -m scripts.run_scan --scope config/<hedef>.scope.yaml --actors config/<hedef>.actors.yaml \
    --mode active --llm none --out runs/url-<hedef>          # --endpoints YOK
python -m scripts.benchmark --run runs/url-<hedef>/run-* --expected benchmarks/<hedef>.expected.yaml \
    --surface benchmarks/<hedef>.surface.yaml --target "<hedef> (URL-only)"
```
