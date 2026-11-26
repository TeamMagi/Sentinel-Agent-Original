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
