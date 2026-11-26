<!-- GERÇEK koşum sonucu. Elle YAZILMAZ; aşağıdaki komutlarla yeniden üretilir.
     Bu dosya, README'deki VAmPI rakamının tek kaynağıdır (runs/ git-ignore'lu olduğu için
     koşum artefaktı repoda tutulamaz; sonuç burada sabitlenir). -->

# VAmPI — gerçek koşum sonucu

| | |
|---|---|
| **Tarih** | 2026-11-26 |
| **Hedef** | erev0s/VAmPI ("vulnerable" mod) @ `http://localhost:5000` |
| **Kod sürümü** | `0665c8d` |
| **LLM** | `--llm none` — **kural-only** |
| **Scope** | `destructive_tests: false` + `safe_write_paths: ["/users/v1/register"]` (test kullanıcısı oluşturur, silinmez) |
| **Vaka seti** | [`vampi.expected.yaml`](vampi.expected.yaml) — 12 etiketli vaka (4 pozitif / 8 negatif) |
| **Önceki** | 2026-09-20 `b13e33c` (Ollama qwen3.8:27b): recall %50 (2/4) |

## Yeniden üretme

VAmPI'nin kitap başlıkları her `/createdb`'de rastgele üretildiği için config, seed'den SONRA
mevcut başlıklar okunarak kurulur (aksi halde IDOR pozitif kontrolü "Book not found" alır).

```bash
# 1) hedefi seed'le (name1/pass1, name2/pass2, admin; her kullanıcıya bir kitap+secret)
curl -s http://localhost:5000/createdb

# 2) scope/actors/endpoints üret — actors.own_object_ids anahtarları HESAPLANAN resource_key
#    ile eşleşmeli: /books/v1/{book_title} -> "books", /users/v1/{username} -> "users".
#    own_object_ids.books = o kullanıcının GÜNCEL kitap başlığı (GET /books/v1'den okunur).
#    token_location: json:auth_token · allowed_methods: GET,HEAD,POST,PUT (DELETE YOK —
#    yıkıcı BFLA testi test kullanıcılarını silebilir) · denied: */createdb*
#    endpoints: /users/v1/_debug, /books/v1/{book_title}, /users/v1/register,
#               /users/v1/{username}, /users/v1, /users/v1/{username}/email (PUT), /books/v1 (POST)

# 3) tara (seed'i TEKRAR çalıştırma — kitap başlıkları değişir)
python -m scripts.run_scan --scope vampi/scope.yaml --actors vampi/actors.yaml \
    --endpoints vampi/endpoints.yaml --mode active --llm none \
    --out runs/vampi/

# 4) ölç
python -m scripts.benchmark --run runs/vampi/run-* \
    --expected benchmarks/vampi.expected.yaml --target "VAmPI (--llm none)"
```

> Hazır örnekler: `config/vampi.*.example.yaml` — register girdisi `body` (`snt_{rand}`) +
> `readback` (`/users/v1/_debug`) taşır; scope `safe_write_paths` register POST'una izin verir.

---

**Hedef:** `VAmPI (--llm none)`

| Metrik | Değer |
|---|---|
| Precision | **100.0%** |
| Recall | **100.0%** |
| False-positive oranı | **0.0%** |
| F1 | 100.0% |
| TP / FN / FP / TN | 4 / 0 / 0 / 8 |

## Vakalar

| Vaka | Beklenen | Gerçek | Sonuç |
|---|---|---|---|
| `excessive_data_exposure @ GET /users/v1/_debug` | CONFIRMED | CONFIRMED | ✅ TP |
| `idor @ GET /books/v1/{book_title}` | CONFIRMED | CONFIRMED | ✅ TP |
| `mass_assignment @ POST /users/v1/register` | CONFIRMED | CONFIRMED | ✅ TP |
| `sqli @ GET /users/v1/{username}` | CONFIRMED | CONFIRMED | ✅ TP |
| `idor @ GET /users/v1/{username}` | not_vulnerable | REJECTED | ✅ TN |
| `state_change_authz @ PUT /users/v1/{username}/email` | not_vulnerable | absent | ✅ TN |
| `bfla @ DELETE /users/v1/{username}` | not_vulnerable | absent | ✅ TN |
| `jwt @ PUT /users/v1/{username}/email` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /users/v1` | not_vulnerable | LIKELY | ✅ TN |
| `idor @ POST /users/v1/login` | not_vulnerable | absent | ✅ TN |
| `unauthorized_access @ GET /` | not_vulnerable | absent | ✅ TN |
| `mass_assignment @ POST /books/v1` | not_vulnerable | absent | ✅ TN |

## Etiketsiz CONFIRMED bulgular (metriklere katılmaz)

- `excessive_data_exposure @ GET /books/v1/{book_title}`
- `excessive_data_exposure @ GET /users/v1`
- `exposure @ GET /openapi.json`
- `info_leak @ GET /`
- `info_leak @ GET /users/v1/{username}`
- `jwt @ GET /users/v1/_debug`
- `rate_limit @ GET /users/v1/_debug`
- `unauthorized_access @ GET /users/v1/{username}`

---

## Bu sayı ne demek, ne demek DEĞİL

- **Precision/recall etiketli 12 vaka ÜZERİNDEDİR.** Koşum toplam 76 bulgu üretti, 17'si CONFIRMED;
  etiket setinde olmayanlar (yukarıda) metriklere **katılmaz**.
- **%50 → %100 değişimini getirenler:**
  - `excessive_data_exposure @ _debug` — id'siz koleksiyon endpoint'lerine edx hipotezi üretiliyor.
  - `mass_assignment @ register` — yeni **create-time** oracle: kontrol kaydı (ayrıcalıksız) ve
    saldırı kaydı (`admin: true` vb.) oluşturulur, readback'te (`_debug`) karşılaştırılır. Kontrol
    kaydı da ayrıcalıklıysa (varsayılan) CONFIRMED **verilmez** — near-miss ikiziyle korunur.
- **FP-rate %0:** 8 negatif vakanın hiçbiri yanlış CONFIRMED almadı (ör. public-by-design
  `/users/v1/{username}` IDOR kapanı REJECTED).
- Kural-only koşum artık eski yerel-LLM koşumundan daha yüksek recall veriyor: hipotez kapsamı
  deterministik planlayıcıya taşındı.
- VAmPI **kalibre** bir hedeftir → %100 **genelleme kanıtı DEĞİLDİR**; bkz. [`suite.yaml`](suite.yaml).
