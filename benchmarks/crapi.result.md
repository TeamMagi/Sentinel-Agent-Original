<!-- GERÇEK koşum sonucu. Elle YAZILMAZ; aşağıdaki komutlarla yeniden üretilir.
     Bu dosya, README'deki crAPI rakamının tek kaynağıdır (runs/ git-ignore'lu olduğu için
     koşum artefaktı repoda tutulamaz; sonuç burada sabitlenir). -->

# crAPI — gerçek koşum sonucu

| | |
|---|---|
| **Tarih** | 2026-11-26 |
| **Hedef** | OWASP crAPI (resmi compose yığını) @ `http://127.0.0.1:8888` |
| **Kod sürümü** | `0665c8d` |
| **LLM** | `--llm none` — **kural-only**; hipotezleri deterministik planlayıcı üretir, verdict'i oracle verir |
| **Scope** | `destructive_tests: false` + `safe_write_paths` (validate-coupon, contact_mechanic, login — yalnız POST) |
| **Vaka seti** | [`crapi.expected.yaml`](crapi.expected.yaml) — 12 etiketli vaka (5 pozitif / 7 negatif) |
| **Önceki** | 2026-11-24 `747cbe6`: recall %40 (2/5) |

## Yeniden üretme

```bash
# 1) crAPI'yi kaldır (resmi docker-compose) ve iki hesap kaydet: sentinel_c1 / sentinel_c2.
#    Her hesapla bir topluluk gönderisi oluştur, postId'leri not et.
#    Önce DB'ler (postgres/mongo) ayağa kalksın; community/workshop "healthy" olmadan taramayın.

# 2) config'leri hazırla (parolalar .secrets/ disiplinine göre)
cp config/crapi.scope.example.yaml     config/crapi.scope.yaml   # safe_write_paths dahil
cp config/crapi.actors.example.yaml    config/crapi.actors.yaml
cp config/crapi.endpoints.example.yaml config/crapi.endpoints.yaml
#    actors.own_object_ids.posts → c1/c2'nin postId'leri

# 3) tara (kural-only)
python -m scripts.run_scan --scope config/crapi.scope.yaml --actors config/crapi.actors.yaml     --endpoints config/crapi.endpoints.yaml --mode active --llm none --out runs/crapi

# 4) ölç
python -m scripts.benchmark --run runs/crapi/run-*     --expected benchmarks/crapi.expected.yaml --target "crAPI (--llm none)"
```

---

**Hedef:** `crAPI (--llm none)`

| Metrik | Değer |
|---|---|
| Precision | **100.0%** |
| Recall | **100.0%** |
| False-positive oranı | **0.0%** |
| F1 | 100.0% |
| TP / FN / FP / TN | 5 / 0 / 0 / 7 |

## Vakalar

| Vaka | Beklenen | Gerçek | Sonuç |
|---|---|---|---|
| `ssrf @ POST /workshop/api/merchant/contact_mechanic` | CONFIRMED | CONFIRMED | ✅ TP |
| `nosqli @ POST /community/api/v2/coupon/validate-coupon` | CONFIRMED | CONFIRMED | ✅ TP |
| `excessive_data_exposure @ GET /community/api/v2/community/posts/recent` | CONFIRMED | CONFIRMED | ✅ TP |
| `idor @ GET /community/api/v2/community/posts/{postId}` | CONFIRMED | CONFIRMED | ✅ TP |
| `jwt @ GET /identity/api/v2/user/dashboard` | CONFIRMED | CONFIRMED | ✅ TP |
| `unauthorized_access @ POST /identity/api/auth/login` | not_vulnerable | INCONCLUSIVE | ✅ TN |
| `idor @ POST /identity/api/auth/signup` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ POST /identity/api/auth/v3/check-otp` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /identity/api/v2/user/dashboard` | not_vulnerable | INCONCLUSIVE | ✅ TN |
| `unauthorized_access @ GET /community/api/v2/community/posts/recent` | not_vulnerable | REJECTED | ✅ TN |
| `bfla @ POST /workshop/api/mechanic/mechanic_report` | not_vulnerable | absent | ✅ TN |
| `idor @ GET /workshop/api/mechanic/receive_report` | not_vulnerable | absent | ✅ TN |

## Etiketsiz CONFIRMED bulgular (metriklere katılmaz)

- `rate_limit @ POST /workshop/api/merchant/contact_mechanic`

---

## Bu sayı ne demek, ne demek DEĞİL

- **Precision/recall etiketli 12 vaka ÜZERİNDEDİR.** Koşum toplam 64 bulgu üretti, 8'i CONFIRMED;
  etiket setinde olmayanlar metriklere **katılmaz**.
- **%40 → %100 değişimini getirenler (2026-11-26):**
  - `excessive_data_exposure @ posts/recent` — `ForeignPiiScanner` başka kullanıcıların PII'sini kanıtlıyor.
  - `ssrf @ contact_mechanic` — loopback probu + "could not connect" bağlantı-hatası imzası
    (kontrol değeri imza taşımaz → differential).
  - `nosqli @ validate-coupon` — hata-mesajsız **operatör differential'ı**: `$eq` literal ile aynı
    yanıtı, `$ne` farklı 2xx yanıtı veriyor. crAPI motor hatası basmaz; eski error-based yol bu
    yüzden kaçırıyordu.
  - Asıl engel kapsamdı: `destructive_tests` kapalıyken POST'lar sessizce engelleniyordu. Artık
    operatör `safe_write_paths` ile yalnız POST'u açabiliyor; engellenen uçlar `[kapsam]` uyarısı
    olarak raporlanıyor (bu koşumda: `POST /workshop/api/mechanic/mechanic_report`).
- **FP-rate %0:** 7 negatif vakanın hiçbiri yanlış CONFIRMED almadı.
- crAPI **kalibre** bir hedeftir: düzeltmeler bu hedefteki kaçan vakalara bakılarak yapıldı →
  %100 **genelleme kanıtı DEĞİLDİR**. Genelleme yalnız holdout hedefte ölçülür (bkz. [`suite.yaml`](suite.yaml)).
