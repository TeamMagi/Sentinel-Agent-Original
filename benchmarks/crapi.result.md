<!-- GERÇEK koşum sonucu. Elle YAZILMAZ; aşağıdaki komutlarla yeniden üretilir.
     Bu dosya, README'deki crAPI rakamının tek kaynağıdır (runs/ git-ignore'lu olduğu için
     koşum artefaktı repoda tutulamaz; sonuç burada sabitlenir). -->

# crAPI — gerçek koşum sonucu

| | |
|---|---|
| **Tarih** | 2026-11-24 |
| **Hedef** | OWASP crAPI (resmi compose yığını) @ `http://127.0.0.1:8888` |
| **Kod sürümü** | `747cbe6` |
| **LLM** | `--llm none` — **kural-only**; hipotezleri deterministik planlayıcı üretir, verdict'i oracle verir |
| **Vaka seti** | [`crapi.expected.yaml`](crapi.expected.yaml) — 12 etiketli vaka (5 pozitif / 7 negatif) |
| **Tekrar** | 2026-11-23 kural-only koşumu birebir aynı sonucu verdi (1/4/0/7) |

## Yeniden üretme

```bash
# 1) crAPI'yi kaldır (resmi docker-compose) ve iki hesap kaydet: sentinel_c1 / sentinel_c2.
#    Her hesapla bir topluluk gönderisi oluştur, postId'leri not et.

# 2) config'leri hazırla (parolalar .secrets/ disiplinine göre)
cp config/crapi.scope.example.yaml     config/crapi.scope.yaml
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
| Recall | **20.0%** |
| False-positive oranı | **0.0%** |
| F1 | 33.3% |
| TP / FN / FP / TN | 1 / 4 / 0 / 7 |

## Vakalar

| Vaka | Beklenen | Gerçek | Sonuç |
|---|---|---|---|
| `ssrf @ POST /workshop/api/merchant/contact_mechanic` | CONFIRMED | REJECTED | ❌ FN |
| `nosqli @ POST /community/api/v2/coupon/validate-coupon` | CONFIRMED | absent | ❌ FN |
| `excessive_data_exposure @ GET /community/api/v2/community/posts/recent` | CONFIRMED | REJECTED | ❌ FN |
| `idor @ GET /community/api/v2/community/posts/{postId}` | CONFIRMED | CONFIRMED | ✅ TP |
| `jwt @ GET /identity/api/v2/user/dashboard` | CONFIRMED | absent | ❌ FN |
| `unauthorized_access @ POST /identity/api/auth/login` | not_vulnerable | absent | ✅ TN |
| `idor @ POST /identity/api/auth/signup` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ POST /identity/api/auth/v3/check-otp` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /identity/api/v2/user/dashboard` | not_vulnerable | INCONCLUSIVE | ✅ TN |
| `unauthorized_access @ GET /community/api/v2/community/posts/recent` | not_vulnerable | REJECTED | ✅ TN |
| `bfla @ POST /workshop/api/mechanic/mechanic_report` | not_vulnerable | absent | ✅ TN |
| `idor @ GET /workshop/api/mechanic/receive_report` | not_vulnerable | absent | ✅ TN |

## Etiketsiz CONFIRMED bulgular (metriklere katılmaz)

- `jwt_privilege_escalation @ GET /identity/api/v2/user/dashboard`

---

## Bu sayı ne demek, ne demek DEĞİL

- **Precision/recall etiketli 12 vaka ÜZERİNDEDİR.** Koşum toplam 46 bulgu üretti, bunların 4'ü
  CONFIRMED. Etiket setinde olmayan bulgular metriklere **katılmaz**.
- **FP-rate %0:** 7 negatif vakanın ("FP kapanı") hiçbiri yanlış CONFIRMED almadı. Bunlara
  405 dönen `mechanic_report` BFLA kapanı ve obje erişimi olmayan `receive_report` dahil.
- **TP:** `posts/{postId}` BOLA **iki yönde** kanıtlandı: c2, c1'in gönderisinden c1'in e-postasını
  okuyabiliyor, c1 de c2'ninkinden (R-B1 çift-yönlü matris).
- **Kaçan 4 vaka, nedenleriyle:**
  - `jwt @ dashboard` — **tespit edildi, ama farklı tip adıyla.** Araç aynı endpoint'te alg=none
    imzasız token kabulünü `jwt_privilege_escalation` (CWE-347) olarak iki yönde CONFIRMED verdi
    (yukarıda "etiketsiz" listede). Etiket `jwt` tipini beklediği için eşleşmedi. Puanlama, araç
    çıktısı görüldükten sonra değiştirilmedi (döngüsellik olurdu). Tip eşlemesi ayrı bir karar.
  - `ssrf @ contact_mechanic` — **REJECTED.** In-band prob yalnız bulut metadata adresini
    (`169.254.169.254`) ve imzalarını dener; OOB collector yapılandırılmadığında doğrudan
    REJECTED döner (`detector/oob_probes.py`). crAPI'nin loopback'ten çekip
    `response_from_mechanic_api` ile yansıttığı içerik denenmiyor.
  - `excessive_data_exposure @ posts/recent` — **REJECTED.** BOPLA oracle'ı sır/kimlik bilgisi
    alanlarını (password, secret, apikey…) arar; başka kullanıcıların `author.email`/`vehicleid`
    alanları (PII ama sır değil) bu kümede yok.
  - `nosqli @ validate-coupon` — **denenmedi.** Kural-only planlayıcı bu POST gövdesine
    operatör enjeksiyonu hipotezi üretmedi. Bu koşumda LLM kapalıydı; LLM'li koşum ayrıca ölçülmeli.
- crAPI **kalibre** bir hedeftir (etiketler 2026-09-16'da canlı HTTP ile doğrulandı). Metrikler
  genellemeyi ölçmez; o yalnızca holdout hedefte ölçülür (bkz. [`suite.yaml`](suite.yaml)).
