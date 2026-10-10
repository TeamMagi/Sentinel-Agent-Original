# Görev Listesi — Ürünleşme Yol Haritası (2026-10-10)

> Bu dosya, Sentinel-Agent'ı **kişisel araçtan ürüne** taşıma kararını ve önceliklenmiş sırayı
> tutar. Kurallar: **[CLAUDE.md](CLAUDE.md)** (Türkçe/imzasız commit, `pytest -q` yeşil kalmadan
> merge yok) · mimari: **[DESIGN.md](DESIGN.md)** · sözlük: **[docs/sozluk.md](docs/sozluk.md)**.

## ⛔ İhlal edilemez kural

**Verdict tarafına fallback KOYMAYIN.** Oracle emin olamadığında `INCONCLUSIVE` demesi bir eksiklik
değil, projenin **en güçlü tarafıdır**. "Emin olamadım, LIKELY diyeyim" gibi bir gevşeme precision'ı
kaybettirir ve tüm tezi çökertir — CLAUDE.md §5 değişmezlerinin üstünde tutulur. Her yeni yetenek,
mevcut dört-kademeli verdict merdivenini (CONFIRMED/LIKELY/REJECTED/INCONCLUSIVE) **zenginleştirir,
kısayol açmaz.** `CONFIRMED` kararını daima deterministik imza + positive/negative/stability
kontrolleri verir.

---

## 0. Durum tespiti (bu plan neye dayanıyor)

- **Kayıtlı açık tipi (`classify.TYPE_META`): 57** · oracle modülü: 22 · detector: 17 ·
  agent-güvenlik: 4.
- **Benchmark'la (eval twin, 0-FP kapısı) kanıtlanmış: yalnız 18.** Yani katalog geniş ama
  ~%32'si twin ile kurşungeçirmez. **Asıl açık bu uçurum** — tip sayısı değil, kanıt kapsamı.
- Benchmark recall'ü yerel LLM (dış makine, on-prem) ile ~%95. Bu **yeterli**; hedef %100 recall
  DEĞİL. Ürün riski recall değil, (a) 39 kanıtsız tip ve (b) Juice Shop dışı gerçek hedef eksikliği.

### Ürün dört koldan oluşuyor (tek kol değil)

| Kol | Kapsam | Durum | Rol |
|---|---|---|---|
| **A — Access control** | IDOR/BOLA/BFLA/BOPLA/mass-assignment | En derin, en çok twin'li | **Taban** (güven temeli) |
| **B — Injection/web** | sqli/xss/ssti/traversal/crlf… | Geniş ama çoğu sığ imza | Tamamlayıcı (emtia) |
| **C — Altyapı/config** | tls/headers/cve/default-creds/session | Nuclei'nin güçlü alanı | Tamamlayıcı (emtia) |
| **D — Agent/LLM/MCP güvenliği** | exfiltration/confused-deputy/destructive-write/manifest/dangerous-tool | 4 modül, genişlemeye hazır | **Amiral farklılaştırıcı** |

**Mimari tespit:** Aynı kola yeni açık tipi eklemek yeni mimari gerektirmez — `detector-ekleme-zinciri`
(7 dosya) zaten "kola ekleme" mekanizması. Yeni mimari YALNIZCA bir kol HTTP-replay + tek-değişken
diferansiyel omurgasını kırdığında gerekir (ağ/host port tarama, binary/SAST, çok-adımlı stateful
iş-mantığı). Bu karar şimdilik ertelendi.

---

## Öncelik sırası (kararlaştırıldı)

> İlke: **her yönü geliştireceğiz, hiçbir yeri eksik bırakmayacağız** — ama sıra önce *derinlik +
> dürüst konumlandırma*, sonra *yeni kol*. Önce A+D amiral olacak; yeni kol/mimari en sona.

### P0 — Kanıt konsolidasyonu (yeni özellikten ÖNCE)
- [x] **A ve D kollarındaki kayıtlı her tip için eval twin** (`_vuln`/`_hardened`/near-miss + `_one`)
      → amiral kollarda tam kapsam. **(Kol A + Kol D TAM — eval 18→39 vaka, 14 kanıtlı tip)**
  - Kol A twin'li: `idor`, `bola`, `bfla`, `path_traversal` (önceden) ✓
  - [x] `unauthorized_access` — `UnauthorizedAccessTwin` (GET, yönetim-path, anon attacker)
  - [x] `excessive_data_exposure` (BOPLA) — `BoplaTwin` (vuln/hardened/near-miss: tarih-indirme)
  - [x] `method_bypass` — `MethodBypassTwin` (DELETE reddi → POST bypass; destructive scope)
  - [x] `mass_assignment` — `MassAssignmentTwin` (isAdmin bind; durum-bilgili yaz-sonra-oku; destructive scope)
  - [x] `graphql_bola` — `GraphqlBolaTwin` (sahiplik kontrolsüz `order(id:)`; kurban-özel marker sızar)
  - [x] `state_change_authz` — `StateChangeTwin` (BOLA-write; kurbanın objesine kalıcı PUT mutasyonu)
  - Kol A tamam; yalnız `nested_idor` opsiyonel (not: `vuln_type="idor"`, yeni proven tip eklemez — derinlik twin'i)
  - [x] `confused_deputy` — `ConfusedDeputyTwin` (niyet yok + yan-etkili `email.send` → CONFIRMED)
  - [x] `destructive_write` — `DestructiveWriteTwin` (korumalı `secret.txt`'ye yıkıcı çağrı; `destructive_tests=True`)
  - [x] `exfiltration` — `ExfiltrationTwin` (canary sır outbound `http.post` gövdesinde sızar; nedensel zincir)
  - [x] `manifest_deviation` — `ManifestDeviationTwin` (beyan dışı tool; uyumlu+sapan çağrı birlikte)
  - `dangerous_mcp_tool`: **tasarım gereği LIKELY-tavanlı** (sinyal, kanıtlanmış istismar değil) →
    CONFIRMED twin modeline oturmaz, **doğru davranış experimental kalması** (verdict disiplini).
  - Kol D kanıtlanabilir 4 tip TAM; agent twin'leri `AgentTrace` fixture'ı + sync `AgentOracle` sarıcı
    (`finding()`) deseniyle eklendi — HTTP iki-aktör değil.
- [x] B/C'de twin'siz kalan tipleri **"experimental" olarak etiketle** (ürün dürüstlüğü — "57 tip"
      derken azını ispatlayabilme açığını kapat). → `classify.PROVEN_TYPES` + `is_experimental()`;
      eval twin'leriyle senkronu `tests/test_experimental_tag.py` (drift-guard) zorlar.
- [x] Kapıları her adımda koş: `pytest -q`, `eval/evaluate.py` (39 vaka, precision/recall %100,
      FP-rate %0), `scripts.bench_guard` (13 ikiz, 0-FP), `scripts.verify_release`, `ruff check`. ✓

### P1 — Kol D'yi amiral farklılaştırıcı yap (asıl büyüme yönü)
- [ ] `agent/` ailesine yeni `AgentOracle` alt sınıfları ekle (Open/Closed; çekirdek değişmez).
      Gerekçe: Burp/ZAP/Nuclei/Strix/XBOW *hedefteki* AI agent'ı/MCP'yi authz/exfil için test etmiyor
      — 2026'da boş arazi + yükselen talep + mimari bedava.
- [ ] Her yeni predicate için twin (P0 disiplini) + `tests/test_*` (network'süz, `MockTransport`).
- [ ] Ürün anlatısı: "AI çağının access-control + agent güvenlik tarayıcısı".

### P2 — Kol A'yı taban olarak sağlamlaştır (büyütme değil, pekiştir)
- [ ] Benchmark'ı Juice Shop dışına çıkar: **crAPI** ve **VAmPI** (ikisi de authz/BOLA için tasarlı)
      ekle → "gerçek sistemde çalışıyor" iddiasının kanıtı.

### P3 — B (injection) ve C (altyapı): fırsatçı, en sona
- [ ] Emtia alan; önden gitme. "Tamamlayıcı kapsam" olarak konumlandır, çekirdek iddiaya karıştırma.

---

## Agent/scout ölçekleme ilkesi (karar)

`ParallelOrchestrator` scout'ları **endpoint'i** bölüşür (round-robin), **açık-tipini** değil; hepsi
**tek bütçe + tek rate-limiter + tek WorldModel** paylaşır. Dolayısıyla:

- **Scout sayısını yetenek (açık tipi) sayısına orantılama — bu iki dik eksen.** Tip eklemek endpoint
  *başına* derinlik, scout ise endpoint'ler *arası* hızdır.
- Tek hedefte scout tavanı **hedefin RPS'i**, scout sayısı değil (`scout ≈ min(anlamlı endpoint
  dilimi, rps_headroom)` → tipik 3-6). Fazlası israf + 0-FP için cross-contamination riski (§5.3) +
  N× LLM maliyeti.
- **Ürün ölçeği yatay büyür:** çok hedefte **hedef başına bir orchestrator** (her biri kendi
  bütçesiyle, izole world) — tek hedefe daha çok scout değil.
- **Agent çeşidini kol başına uzmanlaştır** (access-control scout / agent-güvenlik scout / injection
  scout), klonlama. Agent sayısı **kol sayısıyla** orantılı büyür (bugün 4 kol → 4 uzman), yetenek
  sayısıyla değil.

## Konumlandırma notu (kaybolmasın)

**On-prem / local-LLM** çalışabilirlik satılabilir farklılaşma: trafiğini/zafiyet verisini bulut
LLM'ine göndermek istemeyen güvenlik-duyarlı müşteriler (finans/savunma/sağlık) için güçlü argüman.
"LLM akıl yürütür, motor kanıtlar" mimarisi bunu zaten mümkün kılıyor.

## Her kol için "bitti" tanımı

Bir kol şu üçü sağlanınca "amiral/olgun" sayılır: (1) kayıtlı her tipi twin ile kanıtlı, (2) FP-rate
%0, (3) Juice Shop + en az bir gerçek hedefte tekrarlanabilir CONFIRMED bulgu.
