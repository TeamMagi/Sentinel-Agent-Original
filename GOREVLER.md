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
      → amiral kollarda tam kapsam. **(Kol A + Kol D TAM — eval 18→49 vaka, 19 kanıtlı tip; +sqli emtia)**
  - Kol A twin'li: `idor`, `bola`, `bfla`, `path_traversal` (önceden) ✓
  - [x] `unauthorized_access` — `UnauthorizedAccessTwin` (GET, yönetim-path, anon attacker)
  - [x] `excessive_data_exposure` (BOPLA) — `BoplaTwin` (vuln/hardened/near-miss: tarih-indirme)
  - [x] `method_bypass` — `MethodBypassTwin` (DELETE reddi → POST bypass; destructive scope)
  - [x] `mass_assignment` — `MassAssignmentTwin` (isAdmin bind; durum-bilgili yaz-sonra-oku; destructive scope)
  - [x] `graphql_bola` — `GraphqlBolaTwin` (sahiplik kontrolsüz `order(id:)`; kurban-özel marker sızar)
  - [x] `state_change_authz` — `StateChangeTwin` (BOLA-write; kurbanın objesine kalıcı PUT mutasyonu)
  - Kol A tamam. Derinlik twin'leri de eklendi (`bench/kolb/access_depth.py`, `vuln_type="idor"`,
    yeni proven tip eklemez): gövde id, UUID, iç-içe gövde, ikinci-el — vulnerable/hardened/near-miss.
  - [x] `confused_deputy` — `ConfusedDeputyTwin` (niyet yok + yan-etkili `email.send` → CONFIRMED)
  - [x] `destructive_write` — `DestructiveWriteTwin` (korumalı `secret.txt`'ye yıkıcı çağrı; `destructive_tests=True`)
  - [x] `exfiltration` — `ExfiltrationTwin` (canary sır outbound `http.post` gövdesinde sızar; nedensel zincir)
  - [x] `manifest_deviation` — `ManifestDeviationTwin` (beyan dışı tool; uyumlu+sapan çağrı birlikte)
  - [x] `untrusted_to_action` — `UntrustedToActionTwin` (AS-3; güvenilmez içerik→ayrıcalıklı aksiyon
        taint zinciri; hardened: kullanıcı aksiyonu açıkça ister → REJECTED). Oracle önceden tam
        test edilmişti ama eval twin'i yoktu → 0-FP kapısına bağlandı, PROVEN'a yükseltildi.
  - `dangerous_mcp_tool`: **tasarım gereği LIKELY-tavanlı** (sinyal, kanıtlanmış istismar değil) →
    CONFIRMED twin modeline oturmaz, **doğru davranış experimental kalması** (verdict disiplini).
  - Kol D kanıtlanabilir 4 tip TAM; agent twin'leri `AgentTrace` fixture'ı + sync `AgentOracle` sarıcı
    (`finding()`) deseniyle eklendi — HTTP iki-aktör değil.
- [x] B/C'de twin'siz kalan tipleri **"experimental" olarak etiketle** (ürün dürüstlüğü — "57 tip"
      derken azını ispatlayabilme açığını kapat). → `classify.PROVEN_TYPES` + `is_experimental()`;
      eval twin'leriyle senkronu `tests/test_experimental_tag.py` (drift-guard) zorlar.
- [x] Kapıları her adımda koş: `pytest -q` (1811 test), `eval/evaluate.py` (217 vaka, precision/recall
      %100, FP-rate %0), `scripts.bench_guard` (71 ikiz, 0-FP), `scripts.verify_release`, `ruff`. ✓
      *(2026-11-24 itibarıyla; P1.5/P2.5'teki sayılar o maddenin kapandığı anın görüntüsüdür.)*

### P1 — Kol D'yi amiral farklılaştırıcı yap (asıl büyüme yönü) — BAŞLADI
- [~] `agent/` ailesine yeni `AgentOracle` alt sınıfları ekle (Open/Closed; çekirdek değişmez).
      Gerekçe: Burp/ZAP/Nuclei/Strix/XBOW *hedefteki* AI agent'ı/MCP'yi authz/exfil için test etmiyor
      — 2026'da boş arazi + yükselen talep + mimari bedava.
  - [x] `memory_poisoning` — `MemoryPoisoningOracle` (turlar-arası kalıcılık: güvenilmez içerik
        belleğe → geri-okuma → yan-etki tetiği; üç-adımlı nedensel zincir).
  - [x] `insecure_output_handling` — `InsecureOutputHandlingOracle` (LLM02; arıtılmamış tool çıktısı
        → exec-sink `shell.exec`/`sql.query`; yürütülebilir token ayırt edici kontrol).
  - [x] `excessive_agency` — `ExcessiveAgencyOracle` (LLM06; sınırsız blast-radius: joker `*`/
        where'siz DML/`recursive` bayrağı; kullanıcı toplu kapsamı yetkilendirmediyse). **18 kanıtlı tip.**
  - Kol D şu an 8 kanıtlı tip; OWASP LLM Top-10 agentic kapsamı genişliyor.
- [x] Her yeni predicate için twin (P0 disiplini) + `tests/test_*` (network'süz).
      memory_poisoning ✓ · insecure_output_handling ✓ · excessive_agency ✓
- [x] Ürün anlatısı: "AI çağının access-control + agent güvenlik tarayıcısı".
      → README'ye dört-kol konumlandırması + Kol D'nin 8 predicate'i + on-prem argümanı eklendi.

### P2 — Kol A'yı taban olarak sağlamlaştır (büyütme değil, pekiştir)
- [~] Benchmark'ı Juice Shop dışına çıkar: **crAPI** ve **VAmPI** (ikisi de authz/BOLA için tasarlı).
  - [x] **VAmPI** koşuldu + belgelendi (`vampi.result.md`, 2026-09-20; README %100 precision / %50 recall / %0 FP).
  - [x] Her iki hedef için commit'li config örnekleri (`config/{crapi,vampi}.*.example.yaml`) + runbook
        (`benchmarks/README.md`) + HTTP-doğrulanmış yer-gerçeği (`*.expected.yaml`) + suite.
  - [x] **crAPI canlı koşum** (`benchmarks/crapi.result.md`, 2026-11-24, `--llm none`): precision %100,
        recall %20, FP %0 (1/4/0/7) — 2026-11-23 koşumuyla birebir aynı. FN'ler ve nedenleri dosyada.

### P3 — B (injection) ve C (altyapı): fırsatçı, en sona
- [~] Emtia alan; önden gitme. "Tamamlayıcı kapsam" olarak konumlandır, çekirdek iddiaya karıştırma.
  - [x] `sqli` (error-based differential) — `SqliTwin` ile kanıtlı (VAmPI'nin SQLi FN'ini kapatır).
        İlk emtia kanıtlı tip; gerisi fırsatçı eklenecek (çoğu imza/LIKELY-tavanlı dedektör experimental kalır).

---

### P1.5 — Agentic döngü sağlamlaştırması · TAM
- [x] **ActionRanker** (`orchestrator/ranker.py`): `HeuristicRanker` + `LLMRanker`; her turda
      aksiyonları nedensel öncelikle sıralar, agent trace'inde "sıra N/M" olarak görünür.
- [x] **CONFIRMED → pivot** (`orchestrator/agent.py` + `HypothesisExpander`): CONFIRMED bulgunun
      cevabındaki obje referansları yeni hipotezlere dönüşür ve ikinci endpoint'e taşınır
      (Juice Shop: basket → `/api/Users/{id}`). `tests/test_agent_pivot.py`.
- [x] **RunDetector + SeedTargetDetector** (`orchestrator/actions.py`, `executor.py`): hedef-seviyesi
      dedektörler döngü başında bir kez seed edilir; `run_detector` aksiyonu tipli çalışır, tekrar
      eden dedektör koşusu yok. `tests/test_run_detector.py`.
- [x] Kapılar: 1764 test, eval 205 vaka FP-rate %0, bench-guard 67 ikiz / 0 yanlış CONFIRMED.

### P2.5 — R-B3 sahiplik çıkarımı (own_object_ids'siz bootstrap) · TAM (2026-11-24)
- [x] Tekil/çoğul + harf duyarsız kaynak anahtarı (`models.canonical_resource_key`):
      `/api/Users/{id}` ('users') ↔ JWT/whoami'den gelen 'user' aynı kaynağa düşer.
- [x] Bearer JWT gövdesinden kimlik (`idtools.jwt_payload`): Juice Shop whoami'si Bearer ile boş
      döner (cookie tabanlı) → kullanıcı id'si JWT `data.id`'den. Yalnız bootstrap; verdict değil.
- [x] FP korumaları: kimlik koleksiyonu (`/api/Users`) crawl edilmez; aktörlerde aynı çıkan
      ortak ilk id düşer; config daima öncelikli.
- [x] `IdorOracle`: kurbanın kendi baseline'ı 200 değilse INCONCLUSIVE (önceden yanlış/var olmayan
      own-id'de iki aynı 404 "kararlı" sayılıp REJECTED — sahte "güvenli" — dönüyordu).
- [x] Canlı kabul: `own_object_ids` silinmiş config ile Juice Shop'ta `/api/Users/{id}` IDOR iki
      yönde CONFIRMED.
- [x] Login yanıtından own-id: `auth.own_ids_from` ipucu (`basket: json:authentication.bid`) →
      `AuthState.login_ids` → feedback bootstrap. Canlı: `own_object_ids`'siz sepet IDOR CONFIRMED.
- [x] Kapılar: 1803 test, eval 205 vaka FP-rate %0, bench-guard 67 ikiz / 0 yanlış CONFIRMED,
      verify_release + ruff temiz.

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

Bir kol şu üçü sağlanınca "amiral/olgun" sayılır: (1) kayıtlı her tipi twin ile kanıtlı, (2) FP-rate
%0, (3) Juice Shop + en az bir gerçek hedefte tekrarlanabilir CONFIRMED bulgu.

---

## Açık işler (tek liste)

> Tamamlanmamış her şey burada. Etiketler kaynak listedeki numarayı korur:
> `#N` = galeri-analizi eylem planı · `N.` = yarışma penceresi listesi.

### [ ] crAPI recall artığı · *(efor: Orta)*
`benchmarks/crapi.result.md` (2026-11-24, kural-only 1/4/0/7) kaçan dört vakayı nedenleriyle listeler:
- SSRF: in-band prob yalnız bulut metadata'yı dener. ✅ Verdict düzeltildi (2026-11-24): OOB
  collector yoksa artık INCONCLUSIVE (önceden kanıtsız REJECTED). Kalan: loopback yansıma kapsamı.
- excessive_data_exposure: BOPLA sır alanlarını arar; başka kullanıcının PII'si (email/vehicleid)
  için aktöre-özel sızıntı kontrolü yok.
- NoSQLi: kural-only planlayıcı POST gövdesine operatör enjeksiyonu hipotezi üretmiyor.
- jwt tip eşlemesi: alg=none `jwt_privilege_escalation` olarak CONFIRMED; etiket `jwt` bekliyor
  (eşleme kararı — puanlama araç çıktısına bakılarak değiştirilmez).
- Holdout hedef: üç hedef de kalibre; genelleme ölçümü için dokunulmamış bir hedef gerekiyor.

### [ ] #8. Fonksiyonel-regresyon kontrolü (düzeltme işlevi bozuyor mu) · *(Görkem · efor: Orta-Yüksek)*
Kaynak: Crucible · katman: oracle/verify (#7 ile eşleşir).
Güvenlik düzeltmesi işlevi (ör. ödeme/format) bozabilir; "exploit bloklandı MI **VE** işlev hâlâ
çalışıyor MU" çift kontrolü. #7'nin doğal devamı, aynı kişide.

### [ ] #9. Causal lineage graph — çok-adımlı BOLA + UntrustedToAction · *(Görkem · efor: Yüksek)*
Kaynak: ChainBreak · katman: oracle.
Veri hassasiyeti + köken + hedef izleyen nedensel köken grafiği; çok-adımlı BOLA ve
`UntrustedToActionOracle` için güçlü temel. En büyük P2 kalemi.

### [~] #10. Entropy-temelli sır detektörü (yeni detector) · *(Görkem · efor: Düşük-Orta)*
Kaynak: SentinelZero · katman: detector.
Shannon entropy ile sır/token tespiti — ucuz, deterministik, mevcut detector ailesine bir alt sınıf
olarak oturur (Open/Closed).
**Durum (2026-11-24, kısmi):** entropy yardımcısı var (`agent/entropy.py`, `tests/test_entropy.py`) ve
agent tarafında kullanılıyor: `SensitiveDisclosureOracle` (display/log'a sır sızması) + ATO token
zayıflık analizi. **Eksik:** HTTP yanıtlarını tarayan `Detector` alt sınıfı yok. Eklenirse
session-id/hash/UUID gürültüsü yüzünden LIKELY-tavanlı (experimental) olmalı — tek başına CONFIRMED değil.

### [ ] 15. Jürinin hiçbir şey kurmadan görebileceği bir şey bırak · *(Serhat · ~1.5s)*
Barındırılmış panel olmasa bile **tek dosyalık `report.html`'i repoya koymak yeter** — jüri indirip
açar, kanıtı görür. (Redaksiyonlu, gerçek bir koşumdan.)

### [ ] 24. Demo videosu üç kare üstüne kurulsun · *(Serhat · ~2.5s)*
1. Zafiyetli hedefte **CONFIRMED** — kanıt + repro-curl ekranda.
2. Sağlamlaştırılmış ikizde **REJECTED** — yanlış alarm yok.
3. `--llm none` ile **aynı sonuç** — tezin ispatı.

> **İkinci kare birincisinden değerli:** "buldum" diyen her demo var; **"bulmadığım yerde de
> bulmadım"** diyen demo yok.

### [ ] 25. Videoda jürinin istediği beş başlık sırayla geçsin · *(Serhat · ~1s)*
problem / çözüm / nasıl çalışıyor / teknoloji / kimin işine yarar.

### [ ] 26. AI kullanım beyanı · *(Serhat · ~1s)*
**Zorunlu** — hangi araçlar, nasıl kullanıldı. Şart "katılımcı gönderdiği işi açıklayabilmeli" diyor;
**jüri kod sorabilir**. (Mevcut `docs/AI_DISCLOSURE.md` temel alınabilir.)

### [ ] 27. Jüriye link bırak · *(Serhat · ~0.5s)*
GitHub reposu yeter; **canlı barındırma zorunlu değil**.

### [ ] 28. Ödül hedefini netleştir · *(Serhat · ~0.5s)*
**Grand Prize / Best Cybersecurity Solution.** "Best Beginner Project" sizin kategoriniz değil,
oraya oynamayın.

### [ ] 29. Commit geçmişi Cuma 10:00 EDT sonrasında başlasın · *(Serhat · ~0.5s)*
Vizyon dosyası ayrı dursun; **kod yarışma penceresinde yazılsın**. Bu bir teslim kuralı — nasıl
uygulanacağına (yeni repo / yeni dal) karar verip yazıya dök.

### [ ] 30. Etik / kapsam uyarısı README'de kalsın · *(Serhat · ~0.5s)*
Pentest aracı için jüri bunu arar; **sizde iyi yazılmış** — silinmesin, İngilizce'ye taşınırken de
korunsun.

### [ ] AS-8. Go-Explore / evrimsel hipotez araması · *(ortak · açık uçlu)*
AS turundan açık kalan tek madde.

---

## Ne ALMAYACAĞIZ (analiz §4 — kimse bu maddelere sapmasın)

- **Tüketici scam/phishing pivotu** — kalabalık, türev, tezi sulandırır.
- **ZK-proof / W3C Verifiable Credentials ağırlığı** (Pramaan) — maliyet çok yüksek; leaked-marker +
  SHA-256 bundle zaten yeterli.
- **Tam sıfır-config / tarayıcı-eklentisi pivotu** — erişim-kontrol testi kimlik ister. Hafif on-ramp
  (#14) evet, pivot hayır.
- **Çoklu-ajan "tartışma" gösterisi** (PARALLAX tarzı) — "kod karar verir" ilkesiyle gerginlik yaratır.

---

## Tamamlananlar — galeri-analizi eylem planı

### [x] #11. MCP tool-manifest tarama (hedefin MCP'sini denetle) · *(Görkem · efor: Orta)*
Kaynak: SentinelZero/Pramaan · katman: detector/oracle.
Biz MCP'yi *sunucu* olarak sunuyoruz; *hedefin* MCP tool şemasındaki tehlikeli execution
örüntülerini tarayan detektör, ajan-güvenliği kapsamımızı genişletir.
**Durum (2026-11-24):** `McpManifestScanner` (`detector/mcp_manifest.py`, `tests/test_mcp_manifest.py`),
`agent-scan --manifest <json>` ile bağlı. Not: manifest yerel JSON olarak verilir; hedef MCP
sunucusundan canlı `tools/list` çekimi yok (gerekirse ayrı madde).

### [x] #12. manifest-deviation gate (ajan-izi: bildirilen ↔ gözlemlenen akış) · *(Serhat · efor: Orta-Yüksek)*
Kaynak: HIVE · katman: policy/oracle.
"İhlal yalnızca bildirilen mimariden sapınca sayılır" kapısı — bizim scope/policy kapımızın
davranışsal karşılığı. Serhat'ın T1 dikey dilim (scope/policy) sahipliğine oturur.

### [x] #13. Dış araç ingestion (özellikle nuclei template'leri) · *(Serhat · efor: Yüksek)*
Kaynak: HORCRUX · katman: net/recon.
Dış araç çıktılarını (öncelikle **nuclei template** ekosistemi) recon/hypothesis'e besle. En büyük
kapsama getirisi; deterministik sonuç otoriter, AI yardımcı ilkesi korunur.

### [x] #14. Hafif "URL ver, pasif tara" on-ramp (auth'suz detektörler) · *(Serhat · efor: Orta)*
Kaynak: Synk · katman: net/webui.
Auth gerektirmeyen pasif detektörler için (exposure/info-leak/headers/CVE) URL-ver-tara hafif giriş
yolu. Friction sorununa kısmi çare — **pivot değil**, on-ramp (analiz §4'e uygun).

### [x] #15. "immunity memory" / öğrenilen imza kütüphanesi · *(Serhat · efor: Yüksek)*
Kaynak: HIVE · katman: hypothesis/store.
Soyut zafiyet örüntülerini hatırlayan imza kütüphanesi; hypothesis üretimini besler. Açık uçlu, en
belirsiz kalem — en sona.

---

## Tamamlananlar — yarışma penceresi listesi

### [x] 10. README'nin ilk ekranı `make demo` + panel ekran görüntüsü olsun · *(Görkem · ~1.5s)*
Şu an okuyan önce Docker, WSL2 ve üç YAML dosyası görüyor.

### [x] 11. "Neden WSL2 + Docker" bölümünü README'den çıkar · *(Görkem · ~1s)*
`docs/gelistirme-ortami.md`'ye taşı (**dosya henüz yok, oluşturulacak**); OneDrive tuzağı notu da
oraya. Doğru bilgi ama okuyana "bu araç zor" diyor.

### [x] 12. `cp config/*.example.yaml` adımlarını demo yolundan kaldır · *(Serhat · ~2.5s)*
**Durum:** `make demo` zaten `scripts/bootstrap_demo.py` ile kendi config'ini
(`runs/demo/config/{scope,actors,endpoints}.yaml`) üretiyor — kullanıcı hiçbir dosya kopyalamıyor.
"🚀 Tek komutla demo" bölümünde de `cp` adımı yok. Doğrulandı (gerçek `make demo` koşumuyla).

### [x] 13. Web panelini ön kapı yap, CLI'ı ikinci bölüme al · *(Görkem · ~1s)*
Şu an tersi. README yapısıyla birlikte (madde 6/10) yapılır.

### [x] 14. Panel ilk açılışta örnek scope üretsin · *(Serhat · ~2s)*
`scripts/serve_ui.py`'a `_bootstrap_example_scope` eklendi: `--scope` dosyası yokken yanındaki
`*.example.yaml`'ı kopyalayıp örnek scope'u kendisi oluşturur (var olan bir scope'u asla ezmez).
Uçtan uca doğrulandı: boş `config/`'ta panel açılıp `/api/scan` artık 503 değil 400 (geçersiz
istek) dönüyor — scope kilitli. `tests/test_serve_ui.py` eklendi.

### [x] 16. Özgünlük iddiasını daralt · *(Görkem · ~1.5s)*
Differential authorization testing yeni değil: **Burp Autorize, AuthMatrix** ve README'de kendi
referans verdiğiniz **AuthProbe**. Yeni olan üç şeyi öne al:
1. deterministik **leaked-marker** ile verdict,
2. **kurcalamaya-dayanıklı imzalı kanıt paketi**,
3. **MCP** üzerinden başka ajanlara **kanıt motoru** olmak.

### [x] 17. Dedektör tablolarını README'nin dibine indir · *(Görkem · ~1s)*
12 oracle + 20 dedektör listesi "bu ZAP klonu mu?" sorusunu davet ediyor ve gerçek farkı gömüyor.

### [x] 18. Etki hikâyesini son kullanıcıya bağla · *(Görkem · ~1s)*
Jürinin tema örnekleri tüketici tarafında (phishing, siber zorbalık, gizlilik); sizinki geliştirici
aracı. **IDOR'un sıradan insanların sipariş / sağlık / mesaj verisinin sızma yolu olduğunu** somut
bir ihlal örneğiyle **bir paragrafta** anlat.

### [x] 19. Kapsam sprawl'ını kes · *(Görkem · ~1s)*
Agent-security oracle'ları, template ekosistemi, sürüm bütünlüğü doğrulama, holdout → **vizyon
dosyasında kalsın**; README'de "yol haritası" başlığı altında **tek satır** olsun.

### [x] 20. `UntrustedToActionOracle` çelişkisini gider · *(Görkem · ~0.5s)*
**Durum (doğrulandı):** README **satır 113** oracle tablosunda **uygulanmış** olarak listeli,
**satır 147** agent-predicate tablosunda "*(yol haritasında)*" diyor. **Gerçek durum: UYGULANDI**
(AS-3 bitti → `src/pentestai/oracle/untrusted_to_action.py`). → **satır 147 düzeltilecek**,
satır 113 kalacak.

### [x] 21. Model isimlerini doğrula · *(Görkem · ~0.5s)*
`qwen3.8:27b` (README 299/375/384/392 + `config/llm.example.yaml`) ve `gemini-3.6-flash`.
**Var olmayan model adı, model tarafını bilen bir jüride kötü durur** — `ollama list` çıktısıyla ve
sağlayıcı dokümanıyla birebir doğrula.

### [x] 22. Kod-dışı referansları kontrol et · *(Görkem · ~1s)*
`DESIGN.md §5`, `docs/sozluk.md`, `SECURITY.md`,
`LICENSE §5`. **Durum:** hepsi artık **VAR** (`docs/sozluk.md` AS-9 ile eklendi; rakip-analizi dokümanları git geçmişine taşındı) —
`scripts/verify_release.py` yerel Markdown linklerini zaten kontrol ediyor, kırık link yok.
Kalan iş: **bölüm numaralarının** (`DESIGN.md §5`, `LICENSE §5`) gerçekten o bölüme denk geldiğini
doğrulamak. Olmayan dosyaya/bölüme link vermeyin.

### [x] 23. "Stage 0 / 1 / 2" tablosunu gerçekleşenle eşle · *(Görkem · ~0.5s)*
Yarışma sonunda Stage 0 bitmişse tabloda öyle görünsün.

---

## Tamamlananlar — teknik öncelik sırası (48 saat)

### [x] T1. Dikey dilim · *(Serhat · ~6s)* — **kritik yol**
İki aktör oturumu → scope/policy kapısı → **tek replay noktası** → `IdorOracle` → leaked-marker
verdict → evidence + tek rapor.
**Kabul:** Juice Shop'ta **tek bir gerçek CONFIRMED** çıkarsa proje ayakta.
**Doğrulandı:** gerçek `make demo` koşumu — `27 bulgu · 4 CONFIRMED`, `runs/run-20260918-100903-64fa82/`.

### [x] T2. Hardened ikiz · *(Serhat · ~2s)* — **ilk günün işi**
Aynı oracle'ın, yetkilendirmesi düzgün bir endpoint'te **REJECTED** demesi.
**Kabul:** aynı oracle, aynı koşum, iki hedef → biri CONFIRMED biri REJECTED.
**Doğrulandı:** `python -m scripts.bench_guard` — `[idor-basket] idor: vulnerable=CONFIRMED
hardened=REJECTED · 0-FP OK · recall OK` (+ `idor-public-trap`, `bfla-admin`). Ayrıca bu koşumda
Windows konsolunda (`cp125x`) `✅` karakteri yüzünden çöken bir encoding hatası bulunup düzeltildi
(`scripts/bench_guard.py`).

### [x] T3. LLM'siz hipotez üretimi (kapsam genişletme) · *(Görkem · ~5s)*
- path şablonundan çıkarım (`{id}`, `{uid}` segmentleri)
- OpenAPI/HAR'dan tip bilgisi (integer/uuid parametreler)
- bootstrap crawl'dan öğrenilen **id havuzu**
- yanıt şemasından otomatik **leaked-marker adayı**

**Kabul:** `--llm none` ile hipotez üretimi çalışır (madde 24'ün üçüncü karesi buna dayanır).

### [x] T4. Küçük ama **GERÇEK** benchmark · *(Görkem · ~3s)*
Juice Shop üstünde **5–6 etiketli vaka**, yarısı pozitif yarısı negatif.
**Küçük ve gerçek, büyük ve boştan iyidir.** (Madde 1'de çıkarılan tablonun yerine bu konur.)

---

## Arşiv — önceki görev dalgaları

Önceki içerik (RK-1…RK-14 ve AS-1…AS-9 dalgaları) bu dosyadan kaldırıldı — **kayıp yok, git
geçmişinde ve kodda duruyor**:

- Yarışma penceresi listesinin **1–9.** maddeleri ve A–G blok başlıkları daha önce kaldırıldı;
  kalan 10–30 ve T1–T4 yukarıda.
- RK turu **27/27 Serhat + 27/27 Görkem**; AS turu **bitti** — Görkem AS-2/AS-4/AS-5/AS-7
  (AS-4: `ToolShadowingOracle`), Serhat AS-1/AS-3/AS-6/AS-9. Açık kalan tek madde AS-8 (yukarıda).
- **Madde 19 gereği** agent-security oracle'ları, template ekosistemi, sürüm bütünlüğü doğrulama ve
  holdout **kodda kalır ama README'de öne çıkarılmaz**: vizyon dosyasında durur, README'de tek
  satırlık "yol haritası" olur.
- Gerekçe/kıyas dokümanları: [ROADMAP](ROADMAP.md) · [DESIGN.md](DESIGN.md) ·
  [kalite artığı](GOREVLER_Q.md) · [Tier C](TIER_C.md) (rakip-analizi dokümanları git geçmişinde).
