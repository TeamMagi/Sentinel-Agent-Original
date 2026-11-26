# Erişim Kontrolü Kategorileri

Sentinel-Agent raporu (`report.md` içindeki "Erişim Kontrolü Kategori Kapsamı" tablosu ve
`access_control.json`), aşağıdaki 11 erişim-kontrolü başlığının her biri için "test edildi mi,
sonuç ne" sorusunu yanıtlar. Bulgu yoksa satır yine görünür: durum **TEST EDİLMEDİ** olur ve
nasıl etkinleştirileceği yazılır. Eşleme kodu: `src/pentestai/report/access_control_matrix.py`
(yalnızca özetler; ağa çıkmaz, verdict değiştirmez).

Durum kuralı (öncelik sırasıyla): CONFIRMED varsa **AÇIK**; yoksa LIKELY varsa **ŞÜPHELİ**; yoksa
REJECTED varsa **TEMİZ**; yoksa INCONCLUSIVE varsa **SONUÇSUZ**; hiç bulgu yoksa **TEST EDİLMEDİ**.
Bir bulgu birden fazla kategoriye düşebilir.

## 1. Nesne seviyesi yetkilendirme (BOLA/IDOR)

- **Ne:** Bir kullanıcının başka bir kullanıcının nesnesine id değiştirerek erişmesi.
- **Nasıl test edilir:** `src/pentestai/oracle/idor.py` (id'li uç nokta),
  `src/pentestai/oracle/collection_leak.py` (liste sızıntısı), `src/pentestai/oracle/graphql_bola.py`
  (GraphQL), `src/pentestai/oracle/state_change.py` (PUT/PATCH/DELETE ile yazma/silme yetkisi).
- **CONFIRMED koşulu:** Saldırgan yanıtında kurbana ait leaked-marker görünür; pozitif, negatif ve
  stabilite kontrolleri geçmiştir (yazma için kalıcı mutasyon kurban olarak yeniden okunarak doğrulanır).
- **Etkinleştirme:** İki aktör + `own_object_ids` ile varsayılan taramada çalışır.

## 2. Mass assignment

- **Ne:** İstemcinin göndermemesi gereken ayrıcalık alanlarının (`role`, `isAdmin`...) sunucuda set olması.
- **Nasıl test edilir:** `src/pentestai/oracle/mass_assignment.py` (şemadan öğrenilen alanlarla yaz, oku).
- **CONFIRMED koşulu:** Enjekte edilen ayrıcalık alanı yazmadan sonraki okumada gerçekten yansımıştır.
- **Etkinleştirme:** Yazılabilir id'li uç nokta + `scope.destructive_tests=true`.

## 3. Alan izin listesi (field allow-listing)

- **Ne:** Sunucunun hem kabul ettiği (yazma) hem döndürdüğü (yanıt) alanları izin listesiyle sınırlaması.
- **Nasıl test edilir:** Yazma tarafı `src/pentestai/oracle/mass_assignment.py` (REJECTED `triage_note`
  değeri "field allow-list çalışıyor: ..." ile başlayabilir), yanıt tarafı `src/pentestai/oracle/bopla.py`.
- **CONFIRMED koşulu:** Ayrıcalık alanı kabul edilir (mass assignment) ya da yanıtta dolu hassas alan bulunur (BOPLA).
- **Etkinleştirme:** İkisi de mass assignment ve BOPLA testleriyle ölçülür; ek bayrak gerekmez.

## 4. İstemci tarafı yetkilendirme

- **Ne:** Ayrıcalıklı işlevin yalnızca arayüzde (JS bundle'daki rol kontrolü) gizlenip sunucuda korunmaması.
- **Nasıl test edilir:** `src/pentestai/oracle/client_side_auth.py` — uygulamanın kendi JS bundle'ından
  istemci-tarafı korumalı uçlar çıkarılır, düşük yetkili aktörle sunucuda denenir.
- **CONFIRMED koşulu:** Düşük yetkili aktör yetkilinin yapısal olarak aynı 200 yanıtını alır ve catch-all/SPA
  fallback elemesi (var olmayan sonekli yol) geçilmiştir.
- **Etkinleştirme:** `--client-side-scan` (admin rolünde aktör gerekir).

## 5. Sunucu tarafı yetkilendirme

- **Ne:** Yetki kararının sunucuda, her istekte verilmesi.
- **Nasıl test edilir:** `src/pentestai/oracle/bfla.py` (fonksiyon seviyesi),
  `src/pentestai/oracle/unauthorized_access.py` (anonim erişim), `src/pentestai/oracle/method_bypass.py`
  (alternatif method/override header), ayrıca `src/pentestai/oracle/rbac.py` ve
  `src/pentestai/oracle/client_side_auth.py` bulguları bu başlığa da yazılır.
- **CONFIRMED koşulu:** İzinsiz aktör (anonim ya da düşük yetkili) yetkilinin yapısal olarak aynı 200 yanıtını alır.
- **Etkinleştirme:** Varsayılan taramada çalışır.

## 6. Rol tabanlı erişim kontrolü (RBAC)

- **Ne:** Hangi rolün hangi uç noktaya erişebileceğinin politika matrisine uyması.
- **Nasıl test edilir:** `src/pentestai/oracle/rbac.py` (politika matrisi) ve `src/pentestai/oracle/bfla.py`.
- **CONFIRMED koşulu:** İzinli rol 200 alır (pozitif kontrol), izinsiz rol de yapısal olarak aynı yanıtı alır
  ve catch-all negatif kontrolü geçilir.
- **Etkinleştirme:** `--rbac config/rbac.yaml`.

## 7. Yarış durumu (race condition)

- **Ne:** Tek kullanımlık/limitli işlemin eşzamanlı isteklerle limit aşılarak tekrar edilebilmesi (TOCTOU).
- **Nasıl test edilir:** `src/pentestai/oracle/race_condition.py` — barrier-senkronize eşzamanlı burst,
  sıralı negatif kontrol ve isteğe bağlı durum (bakiye/stok) probu; bulgu `parameter="(concurrency)"` taşır.
- **CONFIRMED koşulu:** Başarı sayısı limiti aşar ve ardışık kontrol isteği reddedilir (ya da durum probu
  limitin üstünde işlem gösterir).
- **Etkinleştirme:** `--race-endpoint 'METHOD:/path'` (+ isteğe bağlı `--race-limit`, `--race-state-*`).

## 8. Atomik işlem / eşzamanlılık (lost update)

- **Ne:** Eşzamanlı güncellemelerin kaybolmaması (atomik read-modify-write).
- **Nasıl test edilir:** `src/pentestai/oracle/race_condition.py` limitsiz modda (`limit=None`); bulgu
  `parameter="(concurrency:atomic)"` taşır ve bu başlığa düşer.
- **CONFIRMED koşulu:** En az 2 başarılı eşzamanlı istek vardır ama durum probu başarı sayısından az işlem kadar değişmiştir.
- **Etkinleştirme:** `--race-endpoint ... --race-unlimited --race-state-path/--race-state-field/--race-state-unit`.

## 9. RLS (satır düzeyi güvenlik) yanlış yapılandırması

- **Ne:** Supabase/PostgREST gibi hedeflerde satır düzeyi güvenliğin kapalı ya da hatalı olması.
- **Nasıl test edilir:** `src/pentestai/oracle/rls.py` — kararı liste farkına değil satır sahipliği kanıtına dayandırır.
- **CONFIRMED koşulu:** A'ya ait bilinen satır id'si B'nin (veya anonim rolün) yanıtında satır olarak görünür;
  kurban kendi satırını görür ve baseline kararlıdır.
- **Etkinleştirme:** Supabase/PostgREST hedefinde keşif (`enumerate_more`) + iki aktör.

## 10. Varsayılan ret (deny by default)

- **Ne:** Politikada açıkça izin verilmeyen her erişimin reddedilmesi.
- **Nasıl test edilir:** `src/pentestai/oracle/rbac.py` — `default: deny` politikasında ihlal `parameter="(rbac:default)"` taşır.
- **CONFIRMED koşulu:** Politikada izni olmayan aktör uç noktaya erişir; pozitif kontrol, stabilite, yapısal eşleşme ve catch-all kontrolü geçilmiştir.
- **Etkinleştirme:** `--rbac` ile `default: deny` politikası.

## 11. En az yetki (least privilege)

- **Ne:** Her rolün yalnızca açıkça tanımlı yetkilere sahip olması.
- **Nasıl test edilir:** `src/pentestai/oracle/rbac.py` — açık rol kuralının ihlali `parameter="(rbac:explicit)"` taşır.
- **CONFIRMED koşulu:** Kuralda yasaklanan rol uç noktaya erişir; RBAC oracle'ının tüm kontrolleri geçilmiştir.
- **Etkinleştirme:** `--rbac` ile açık rol kuralları.
