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

---

# Faz 1 sonrası (8 keşif kaynağı: openapi-auto, robots, js, sourcemap, framework, links, versions, smart-wordlist)

| | |
|---|---|
| **Tarih** | 2026-11-27 |
| **Mod** | **URL-only** (`--endpoints/--openapi/--har` YOK) · `--mode active --llm none` · yer-gerçeği Faz 0 ile aynı (`benchmarks/<hedef>.surface.yaml`, DEĞİŞTİRİLMEDİ) |
| **Not** | crAPI'nin repodaki scope'u `allowed_path_prefixes: ["/identity/", "/workshop/", "/community/"]` olduğundan kök `/` ve `/static/` JS bundle'ı kapsam dışıdır; bu yüzden iki koşum yapıldı: (a) mevcut scope (Faz 0 ile birebir), (b) yalnız önek `["/"]` yapılmış kopya (gerçek "yalnız URL verildi" senaryosu; geri kalan her şey aynı). Juice Shop için de aynı iki varyant koşuldu: (a) `bootstrap_demo` scope'u (`/api/`, `/rest/`), (b) önek `["/"]`. |

## Sonuç

| Hedef | Gerçek uç | Bulunan (doğru) | Uç-recall | Yanlış uç | Test kapsamı | Uçtan uca açık recall |
|---|---|---|---|---|---|---|
| VAmPI | 13 | 13 | **%100** (Faz 0: %15.4) | %13.3 (2/15) | %69.2 | **%50** (2/4) (Faz 0: %0) |
| crAPI (a) mevcut scope | 44 | 0 | **%0** (Faz 0: %0) | %100 (yalnız `GET /` tohumu) | %0 | **%0** (0/5) |
| crAPI (b) kök önek | 44 | 31 | **%70.5** | %39.2 (20/51) | %34.1 | **%40** (2/5) |
| Juice Shop (a) `/api/`+`/rest/` scope | 138 | 0 | **%0** (Faz 0: %0) | %100 (3 bulunan, 0 doğru) | %0 | **%0** (0/4) |
| Juice Shop (b) kök önek | 138 | 46 | **%33.3** | %51.1 (48/94) | %2.9 | **%0** (0/4) |

FP: tüm koşumlarda **0** (expected'daki negatif vakaların hiçbiri CONFIRMED olmadı; VAmPI TN 8/8, crAPI 7/7, Juice 4/4).
Precision her koşumda %100.

## Kaynak dağılımı (doğru eşleşen uç sayısı / bulunan toplam)

| Koşum | Doğru eşleşen kaynaklar | Tüm bulunanlar (kaynak: sayı) |
|---|---|---|
| VAmPI | openapi-auto 12, seed 1 | openapi-auto 13, seed 1, smart-wordlist 1 |
| crAPI (a) | — | seed 1 |
| crAPI (b) kök önek | js 30, versions 1 | js 40, smart-wordlist 8, robots 1, versions 1, seed 1 |
| Juice (a) | — | wordlist 2, seed 1 |
| Juice (b) kök önek | js 45, wordlist 1 | js 48, smart-wordlist 34, links 6, wordlist 3, robots 2, seed 1 |

`sourcemap` ve `framework` kaynakları bu üç hedefte hiç uç üretmedi (hedeflerde açık source map / tanınan framework yok).

## Yanlış uçlar — neden "yanlış" sayıldı

Yer-gerçeğini değiştirmedik; "yanlış" = yer-gerçeğinde olmayan uç.

- **VAmPI (2):** `GET /createdb` (openapi-auto) — spec'te GERÇEKTEN var, ama yer-gerçeğinde yok (seed ucu); scope `*/createdb*` yasakladığı için test edilmedi (`tested: false`, istek atılmadı). `GET /users/v1/admin` (smart-wordlist) — gerçek route `/users/v1/{username}`; `admin` kullanıcısı var olduğu için 200 döner, ayrı bir uç DEĞİL (parametreli route'a düşen sahte uç).
- **crAPI (b) (20):**
  - smart-wordlist 8: `/identity/api/v2/user/videos/{admin,all,count,export,list,me,search}` ve `GET /workshop/api/mechanic/service_request`. İlk yedisi gerçek route `/videos/{video_id}`'a düşer (404 dışı döner) → parametreli route'a düşen sahte uç; CatchAllGuard bunu ayıramıyor. Sonuncusu gerçekten var olabilir (aşağıda "yer-gerçeğinde eksik").
  - js 10: `GET /community/api/v2/community/posts/{id}/comment`, `GET /workshop/api/mechanic/download_report`, `GET /workshop/api/mechanic/service_request/{id}` (+`/comment`), `GET /workshop/api/merchant/service_requests/{id}`, `GET /workshop/api/shop/orders`, `POST /identity/api/auth/{unlock,verify}`, `POST /identity/api/v2/user/{change-phone-number,verify-phone-otp}`. Bunlar crAPI'nin kendi front-end JS'inde geçen çağrılardır; yer-gerçeğinde ya yok ya da method/şablon farklı (ör. yalnız `POST /shop/orders` var; `{id}` ↔ `{postId}` adlandırması — metrik param adını bire bir eşliyor). Yani çoğu "gerçekten var olup yer-gerçeğinde eksik/farklı adlandırılmış" olabilir; tek tek HTTP ile doğrulanmadı.
  - robots 1: `GET /.well-known/jwks.json` (gerçekten var, yer-gerçeğinde yok). seed 1: `GET /` (tohum).
- **Juice (b) (48):** `GET /` (tohum); `/.well-known/security.txt` ve `/ftp` (robots; gerçekten var); `/ftp/*.md|.kdbx|quarantine` (links; gerçekten var, yer-gerçeğinde yok); `GET /api/products` ve `GET /api/users` (wordlist — büyük/küçük harf sorunu, aşağıya bak); smart-wordlist 18 (ör. `/rest/2fa/status/{admin,all,count,list,me,search}`, `/rest/languages/{admin,all,count,list,me}`: parametreli/ön-ek route'una düşen türev sahte uçlar; `/api/Card`, `/rest/2fa/statu`, `/rest/chats`, `/api/admin/Cards` gibi tekil/çoğul/önek tahminleri); js 1 (`/rest/chat`). Çıktı listesi "ve 18 tane daha" diye kesiliyor.

**Büyük/küçük harf:** sorun HÂLÂ var. wordlist küçük harfli `/api/products`, `/api/users` buluyor; yer-gerçeği `/api/Products`, `/api/Users` (Express duyarsız eşler, metrik duyarlı) → yanlış sayılıyor. JS kaynağı doğru yazımı (`/api/Products`) verdiğinden (b)'de 45 uç eşleşti. Metrik DEĞİŞTİRİLMEDİ.

## Teşhis — kalan darboğazlar

1. **Scope önek kısıtı keşfi öldürüyor.** crAPI (a) ve Juice (a)'da kök `/` kapsam dışı olduğundan JS/robots/links çalışamıyor: aynı hedef, yalnız önek `["/"]` olunca crAPI %0 -> %70.5, Juice %0 -> %33.3. "Yalnız URL" kullanımında kökün scope'a alınması gerekir (ya da keşif için ayrı, kök-izinli salt-okunur faz).
2. **Bütçe/süre tavanı.** crAPI (b) `max_total_requests=2000` aşıldı (sonuçlar kısmi; test kapsamı %34.1), Juice (b) `max_wall_clock_sec=300` aşıldı (test kapsamı %2.9: 94 uçtan yalnız 8'i test edildi, 4'ü yer-gerçeğiyle eşleşiyor). Keşif, test bütçesini yiyor; keşif/test bütçelerinin ayrılması ya da öncelik sırası gerekir. Bu yüzden Juice (b) uçtan uca recall %0.
3. **Parametreli route'a düşen sahte uçlar.** smart-wordlist, `/x/{id}` route'u olan yollarda `/x/all`, `/x/me`, `/x/list`... türevlerini "var" sayıyor (CatchAllGuard rastgele hex'ten farklı yanıt görünce yetiniyor). Yanlış uç oranının ana kaynağı: crAPI 8, Juice 18+ uç. `{id}` kardeşi biliniyorsa türevlerin bu route'a düşüp düşmediği (aynı gövde/şema/uzunluk) kontrol edilmeli.
4. **Yazma uçları ve parametreler.** JS'ten bulunan POST/PUT/DELETE uçları gövde/param bilinmediğinden test edilemiyor (crAPI param-recall %0; VAmPI %35.7; PUT/DELETE ayrıca scope methods/destructive kapalı).
5. **crAPI kaçırılan 13 uç** (çoğu yazma: `POST /community/.../comment`, `POST /workshop/api/shop/orders`, `.../products`, `PUT .../orders/{order_id}`, `DELETE .../videos/{video_id}`, `GET /workshop/api/management/users/all` vb.) JS'te geçmiyor. Juice: kalan 92 uç `/api/{Model}` CRUD kümesi ve `/rest/*`; bundle'da yalnız bir kısmı geçiyor.
6. **VAmPI**: OpenAPI otomatik bulundu (`/openapi.json`) → uç keşfi çözüldü. Kalan uçtan uca kayıp: `idor @ /books/v1/{book_title}` INCONCLUSIVE, `mass_assignment @ POST /users/v1/register` test edilmedi (uçlar --endpoints'siz gövde/own_object_ids bilgisinden yoksun).
7. **Yer-gerçeğinde eksik gerçek uçlar** (metrik "yanlış" sayıyor, yer-gerçeği değiştirilmedi): VAmPI `GET /createdb`; crAPI `GET /.well-known/jwks.json` ve yukarıdaki JS çağrılarının bir kısmı; Juice `/.well-known/security.txt`, `/ftp*`. Yer-gerçeklerinin genişletilmesi ayrı iştir.

## Yeniden üretme (Faz 1)

```bash
python -m scripts.run_scan --scope config/<hedef>.scope.yaml --actors config/<hedef>.actors.yaml \
    --mode active --llm none --out runs/f1-<hedef>          # --endpoints YOK
python -m scripts.benchmark --run runs/f1-<hedef>/run-* --expected benchmarks/<hedef>.expected.yaml \
    --surface benchmarks/<hedef>.surface.yaml --target "<hedef> (URL-only, Faz 1)"
# crAPI (b): config/crapi.scope.yaml'ın kopyasında allowed_path_prefixes: ["/"] yapılır (diğer her şey aynı)
# Juice Shop: python -m scripts.bootstrap_demo --base-url http://localhost:3000 --out <dizin>
#   (a) <dizin>/scope.yaml  (b) aynı dosyada allowed_path_prefixes: ["/"]; --endpoints verilmez
```
