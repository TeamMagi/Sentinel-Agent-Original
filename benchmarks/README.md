# Benchmarks — gerçek hedeflerde tekrarlanabilir koşum

Bu klasör, "gerçek sistemde çalışıyor" iddiasının kanıtıdır: Sentinel-Agent, Juice Shop dışındaki
**bağımsız, kasıtlı-açıklı** hedeflere (VAmPI, crAPI) karşı koşulur ve çıktısı **önceden, HTTP ile
doğrulanmış yer-gerçeğiyle** (`*.expected.yaml`) karşılaştırılır. Etiketler aracın çıktısına değil
hedefin gerçek davranışına bakılarak konur (döngüsellik yok).

| Dosya | Ne |
|---|---|
| `suite.yaml` | çok-hedefli takım tanımı (hedef → scope/actors/endpoints + beklenen) |
| `*.expected.yaml` | her hedefin HTTP-doğrulanmış yer-gerçeği (pozitif + negatif tuzaklar) |
| `*.result.md` | o hedefin **gerçek koşum** sonucu + yeniden üretme komutları (tek kaynak) |

Koşum artefaktları (`runs/`) git-ignore'ludur; sonuç rakamı `*.result.md`'de sabitlenir.

## Hazır config örnekleri

Her hedef için kopyala-çalıştır örnek config'ler `config/` altında:

```
config/vampi.scope.example.yaml   config/vampi.actors.example.yaml   config/vampi.endpoints.example.yaml
config/crapi.scope.example.yaml   config/crapi.actors.example.yaml   config/crapi.endpoints.example.yaml
```

Gerçek parola/token örneklerde `REDACTED`'tır ve `*.yaml` (örnek olmayan) git-ignore'ludur (§8):
kopyala, kendi test hesaplarının parolalarını `.secrets/` disiplinine uygun doldur.

## VAmPI (Python/Flask) — tekrarlanabilir koşum

```bash
# 1) hedefi kaldır (vulnerable mod) ve seed'le
docker run -d --rm -p 5000:5000 -e vulnerable=1 --name vampi erev0s/vampi:latest
curl -s http://localhost:5000/createdb          # name1/pass1, name2/pass2, admin + kitap+secret

# 2) config'leri hazırla (parolalar + GÜNCEL kitap başlıkları)
cp config/vampi.scope.example.yaml     config/vampi.scope.yaml
cp config/vampi.actors.example.yaml    config/vampi.actors.yaml
cp config/vampi.endpoints.example.yaml config/vampi.endpoints.yaml
curl -s http://localhost:5000/books/v1          # own_object_ids.books'u buradaki güncel başlıklarla doldur

# 3) tara (yerel LLM — hedef verisi buluta çıkmaz)
python -m scripts.run_scan --scope config/vampi.scope.yaml --actors config/vampi.actors.yaml \
    --endpoints config/vampi.endpoints.yaml --mode active --out runs/vampi \
    --llm ollama --llm-model qwen3.8:27b

# 4) yer-gerçeğine karşı değerlendir
python -m scripts.benchmark --findings runs/vampi/findings.json \
    --expected benchmarks/vampi.expected.yaml --target http://localhost:5000
```

## crAPI (OWASP) — tekrarlanabilir koşum

> **Durum:** yer-gerçeği (`crapi.expected.yaml`) HTTP ile doğrulanmıştır; canlı koşum
> (`crapi.result.md`) senin ortamında üretilir — crAPI çok-servisli bir docker-compose yığınıdır
> (identity/community/workshop + Postgres/Mongo/MailHog).

```bash
# 1) crAPI'yi kaldır (resmi compose) ve iki hesap kaydet+doğrula (sentinel_c1 / sentinel_c2)
#    c1 ile bir topluluk gönderisi oluştur, postId'yi not et.

# 2) config'leri hazırla
cp config/crapi.scope.example.yaml     config/crapi.scope.yaml
cp config/crapi.actors.example.yaml    config/crapi.actors.yaml
cp config/crapi.endpoints.example.yaml config/crapi.endpoints.yaml
#    actors.own_object_ids.posts → c1/c2'nin gönderi postId'leri · base_url'i kendi gateway portuna ayarla

# 3) tara
python -m scripts.run_scan --scope config/crapi.scope.yaml --actors config/crapi.actors.yaml \
    --endpoints config/crapi.endpoints.yaml --mode active --out runs/crapi \
    --llm ollama --llm-model qwen3.8:27b

# 4) değerlendir
python -m scripts.benchmark --findings runs/crapi/findings.json \
    --expected benchmarks/crapi.expected.yaml --target http://localhost:8888
```

## Birleşik takım (çok-hedefli tablo)

Her hedefin `runs/<hedef>/findings.json`'u üretildikten sonra:

```bash
python -m scripts.benchmark --suite benchmarks/suite.yaml
```

birleşik precision / recall / FP-rate tablosunu (`benchmark_suite.md/json`) üretir. `suite.yaml`
kalibre↔holdout ayrımını de raporlar: bir sonraki eklenecek hedef **holdout** olarak ayrılmalı
(etiketleri konurken araç çıktısına bakılmaz, araçta ona özel ayar yapılmaz) → gerçek genelleme
orada ölçülür.
