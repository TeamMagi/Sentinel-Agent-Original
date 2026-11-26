<!-- GERÇEK koşum sonucu — İLK HOLDOUT KOŞUMU (resmi holdout rakamı). Elle YAZILMAZ. -->

# Damn Vulnerable RESTaurant API — HOLDOUT ilk koşum

| | |
|---|---|
| **Tarih** | 2026-11-26 |
| **Hedef** | theowni/Damn-Vulnerable-RESTaurant-API-Game (main) @ `http://127.0.0.1:8091` — ayrıcalıksız, yalnız localhost |
| **Kod sürümü** | `f7a381a` (temiz worktree; bu hedefe özel HİÇBİR ayar yok) |
| **LLM** | `--llm none` |
| **Vaka seti** | [`dvra.expected.yaml`](dvra.expected.yaml) — 12 vaka (7 pozitif / 5 negatif), araç çalıştırılmadan etiketlendi |
| **Yüzey** | [`dvra.surface.yaml`](dvra.surface.yaml) — 21 uç (hedefin kendi /openapi.json'ı) |

## Sonuç

| Koşum | Uç listesi | Sonuç |
|---|---|---|
| (a) | `--openapi` (hedefin spec'i verildi) | **Giriş yapılamadı** — `[auth] HATA: login başarısız (status=422)` |
| (b) | URL-only | **Giriş yapılamadı** — aynı hata |

**Holdout recall: %0 (0/7) · FP: 0 · keşif ölçülemedi (tarama başlamadı).**

## Neden

Hedefin `POST /token` ucu standart **OAuth2 password flow** kullanıyor: `application/x-www-form-urlencoded`
(`username=..&password=..`). `TokenAuthProvider` login'i yalnız JSON gövdeyle gönderiyor → 422.
Bu hedefe özgü bir durum değil; FastAPI/Django REST/Spring'deki OAuth2 password akışlarının çoğu böyledir.
Kalibre üç hedefin (Juice Shop, VAmPI, crAPI) üçü de JSON login kullandığı için bu boşluk hiç görünmemişti
— holdout'un tam olarak yakalaması gereken türden bir genelleme açığı.

## Bundan sonrası (dürüstlük notu)

Form-login desteği eklenip bu hedefte yeniden ölçülürse o rakam **"holdout-sonrası (düzeltme görmüş)"**
olarak ayrı raporlanır; resmi holdout rakamı bu dosyadaki ilk koşumdur. Gerçek genelleme ölçümü için
bir sonraki hiç-bakılmamış hedef ayrılmalıdır.

---

## Holdout-sonrası koşum (form-login eklendikten sonra — resmi holdout rakamı DEĞİL)

| | |
|---|---|
| **Tarih / kod** | 2026-11-26 · `5fcc12e` + OAuth2 form-login (`body_format: auto`, hedefe özel ayar yok) |

| Koşum | Giriş | Uç-recall (21 uç) | Test kapsamı | Açık recall | FP |
|---|---|---|---|---|---|
| (a) `--openapi` | ✅ | **%42.9** (9/21) | %42.9 | **%0** (0/7) | 0 |
| (b) URL-only | ✅ | **%9.5** (2/21) | %9.5 | **%0** (0/7) | 0 |

### Holdout'un ortaya çıkardığı genel boşluklar (kalibre hedeflerde görünmüyordu)
1. **OpenAPI yükleyicisi yalnız GET/HEAD alıyor** (`recon/openapi.py` `READ_METHODS`): spec'teki
   PUT/POST/DELETE/PATCH uçlarının hiçbiri listeye girmedi → 7 açığın 5'i hiç denenmedi. Yazma
   güvenliği zaten scope kapısında (`destructive_tests`/`safe_write_paths`); burada ikinci filtre
   yalnız kapsamı öldürüyor.
2. **JWT yanlış-alarmı (etiketsiz, metriğe girmedi ama GERÇEK FP):** herkese açık `/healthcheck`
   (anonim=200) üzerinde `jwt alg=none/signature/weak-secret` **CONFIRMED** verildi. Token'a hiç
   bakmayan uçta "sahte token kabul edildi" kanıt değildir — anonim kontrol eksik. 0-FP ilkesi
   ihlali; öncelikli düzeltilecek.
3. **`X-Powered-By` sürüm ifşası** `security_headers` LIKELY olarak raporlandı; deterministik
   sürüm dizgisi `info_leak` CONFIRMED kanıtı olmalı.
4. **`idor @ /orders/{order_id}`** LIKELY'de kaldı (sahiplik kanıtı CONFIRMED eşiğine ulaşmadı) — incelenecek.
