<!-- Bu dosya `python -m scripts.coverage_matrix --out docs/KAPSAM_MATRISI.md` ile üretilir; elle düzenleme. -->

# Kapsam Matrisi

## Genel özet

- Toplam tip: **71** (`generic` hariç)
- Kanıtlı (proven): **62**
- Deneysel (experimental): **9**
- Kanıtlı oranı: **%87.3**
- Eşlenmemiş tip: yok

## Web (OWASP Top 10 2021)

KANITLI: 8 · DENEYSEL: 1 · BOŞLUK: 1

| Kategori | Durum | Proven | Exp. | Tipler |
|---|---|---|---|---|
| A01:2021 Broken Access Control (Bozuk Erişim Kontrolü) | KANITLI | 18 | 1 | `bfla`, `bola`, `confused_deputy`, `csrf`, `destructive_write`, `excessive_data_exposure`, `exfiltration`, `generic`*, `graphql_bola`, `idor`, `jwt_privilege_escalation`, `manifest_deviation`, `method_bypass`, `open_redirect`, `parameter_pollution`, `path_traversal`, `privilege_escalation`, `state_change_authz`, `unauthorized_access` |
| A02:2021 Cryptographic Failures (Kriptografik Hatalar) | KANITLI | 1 | 3 | `certificate_misconfiguration`*, `jwt`*, `jwt_algorithm_confusion`, `tls_misconfiguration`* |
| A03:2021 Injection (Enjeksiyon, XSS dahil) | KANITLI | 12 | 2 | `blind_sqli`, `command_injection`, `crlf_injection`, `dom_xss`, `injection`*, `insecure_output_handling`, `nosqli`, `prototype_pollution`, `rfi`, `sqli`, `ssti`, `stored_xss`, `timing`*, `xss` |
| A04:2021 Insecure Design (Güvensiz Tasarım) | KANITLI | 6 | 0 | `coupon_reuse`, `file_upload`, `mass_assignment`, `negative_amount`, `race_condition`, `workflow_bypass` |
| A05:2021 Security Misconfiguration (Güvenlik Yanlış Yapılandırması) | KANITLI | 9 | 2 | `cache_poisoning`, `clickjacking`, `cors`, `debug_mode`*, `exposure`, `graphql_introspection`, `host_header_injection`, `http_request_smuggling`, `info_leak`, `security_headers`*, `xxe` |
| A06:2021 Vulnerable and Outdated Components (Zafiyetli/Eski Bileşenler) | DENEYSEL | 0 | 1 | `vulnerable_component`* |
| A07:2021 Identification and Authentication Failures (Kimlik Doğrulama Hataları) | KANITLI | 9 | 1 | `default_credentials`, `host_header_injection`, `jwt`*, `mfa_bypass`, `oauth_misconfig`, `password_reset_abuse`, `rate_limit`, `session_lifecycle`, `unauthorized_access`, `user_enumeration` |
| A08:2021 Software and Data Integrity Failures (Yazılım/Veri Bütünlüğü Hataları) | KANITLI | 3 | 0 | `file_upload`, `prototype_pollution`, `rfi` |
| A09:2021 Security Logging and Monitoring Failures (Loglama/İzleme Hataları) | BOŞLUK | 0 | 0 | — |
| A10:2021 Server-Side Request Forgery (SSRF) | KANITLI | 1 | 0 | `ssrf` |

## API (OWASP API Security Top 10 2023)

KANITLI: 9 · DENEYSEL: 0 · BOŞLUK: 1

| Kategori | Durum | Proven | Exp. | Tipler |
|---|---|---|---|---|
| API1:2023 Broken Object Level Authorization (BOLA/IDOR) | KANITLI | 3 | 0 | `bola`, `graphql_bola`, `idor` |
| API2:2023 Broken Authentication (Bozuk Kimlik Doğrulama) | KANITLI | 9 | 1 | `default_credentials`, `jwt`*, `jwt_algorithm_confusion`, `jwt_privilege_escalation`, `mfa_bypass`, `oauth_misconfig`, `password_reset_abuse`, `session_lifecycle`, `unauthorized_access`, `user_enumeration` |
| API3:2023 Broken Object Property Level Authorization (Nesne Özelliği Yetkisi) | KANITLI | 1 | 0 | `excessive_data_exposure` |
| API4:2023 Unrestricted Resource Consumption (Sınırsız Kaynak Tüketimi) | KANITLI | 1 | 0 | `rate_limit` |
| API5:2023 Broken Function Level Authorization (BFLA) | KANITLI | 5 | 0 | `bfla`, `jwt_privilege_escalation`, `method_bypass`, `privilege_escalation`, `state_change_authz` |
| API6:2023 Unrestricted Access to Sensitive Business Flows (Hassas İş Akışlarına Sınırsız Erişim) | KANITLI | 6 | 0 | `coupon_reuse`, `mass_assignment`, `negative_amount`, `race_condition`, `rate_limit`, `workflow_bypass` |
| API7:2023 Server Side Request Forgery (SSRF) | KANITLI | 1 | 0 | `ssrf` |
| API8:2023 Security Misconfiguration (Yanlış Yapılandırma) | KANITLI | 6 | 4 | `cache_poisoning`, `certificate_misconfiguration`*, `cors`, `debug_mode`*, `exposure`, `graphql_introspection`, `http_request_smuggling`, `info_leak`, `security_headers`*, `tls_misconfiguration`* |
| API9:2023 Improper Inventory Management (Hatalı Envanter Yönetimi) | KANITLI | 2 | 0 | `exposure`, `graphql_introspection` |
| API10:2023 Unsafe Consumption of APIs (API'lerin Güvensiz Tüketimi) | BOŞLUK | 0 | 0 | — |

## LLM (OWASP Top 10 for LLM Apps 2025)

KANITLI: 7 · DENEYSEL: 0 · BOŞLUK: 3

| Kategori | Durum | Proven | Exp. | Tipler |
|---|---|---|---|---|
| LLM01:2025 Prompt Injection (İstem Enjeksiyonu) | KANITLI | 3 | 0 | `memory_poisoning`, `prompt_injection`, `untrusted_to_action` |
| LLM02:2025 Sensitive Information Disclosure (Hassas Bilgi İfşası) | KANITLI | 3 | 0 | `exfiltration`, `info_leak`, `sensitive_disclosure` |
| LLM03:2025 Supply Chain (Tedarik Zinciri) | KANITLI | 1 | 1 | `tool_shadowing`, `vulnerable_component`* |
| LLM04:2025 Data and Model Poisoning (Veri ve Model Zehirleme) | KANITLI | 1 | 0 | `memory_poisoning` |
| LLM05:2025 Improper Output Handling (Hatalı Çıktı İşleme) | KANITLI | 1 | 0 | `insecure_output_handling` |
| LLM06:2025 Excessive Agency (Aşırı Yetki/Özerklik) | KANITLI | 9 | 1 | `confused_deputy`, `dangerous_mcp_tool`*, `destructive_write`, `excessive_agency`, `excessive_autonomy`, `exfiltration`, `manifest_deviation`, `privilege_escalation`, `tool_shadowing`, `untrusted_to_action` |
| LLM07:2025 System Prompt Leakage (Sistem İstemi Sızıntısı) | KANITLI | 1 | 0 | `system_prompt_leakage` |
| LLM08:2025 Vector and Embedding Weaknesses (Vektör/Gömme Zayıflıkları) | BOŞLUK | 0 | 0 | — |
| LLM09:2025 Misinformation (Yanlış Bilgi) | BOŞLUK | 0 | 0 | — |
| LLM10:2025 Unbounded Consumption (Sınırsız Tüketim) | BOŞLUK | 0 | 0 | — |

`*` = experimental (eval twin'iyle henüz kanıtlanmadı).

## Boşluk analizi

### Hiç tipi olmayan kategoriler

- [Web] A09:2021 Security Logging and Monitoring Failures (Loglama/İzleme Hataları)
- [API] API10:2023 Unsafe Consumption of APIs (API'lerin Güvensiz Tüketimi)
- [LLM] LLM08:2025 Vector and Embedding Weaknesses (Vektör/Gömme Zayıflıkları)
- [LLM] LLM09:2025 Misinformation (Yanlış Bilgi)
- [LLM] LLM10:2025 Unbounded Consumption (Sınırsız Tüketim)

### Eksik aile kontrolü

| Aile | OWASP | Sentinel karşılığı | Not |
|---|---|---|---|
| İş mantığı / workflow bypass | A04:2021, API6:2023 | `workflow_bypass` | adım atlama, fiyat/miktar manipülasyonu, kupon kötüye kullanımı |
| Hesap ele geçirme / şifre sıfırlama | A07:2021, API2:2023 | YOK | tahmin edilebilir/yeniden kullanılabilir reset token |
| 2FA / MFA atlatma | A07:2021, API2:2023 | `mfa_bypass` | OTP brute-force, adım atlama, yanıt manipülasyonu |
| WebSocket güvenliği | A01:2021, A05:2021 | YOK | origin kontrolü yok, kimlik doğrulamasız kanal |
| Insecure deserialization | A08:2021 | YOK | güvensiz nesne seri-kaldırma → RCE/mantık atlatma |
| JS bundle'da sır sızıntısı | A02:2021, A05:2021 | YOK | istemci paketinde API anahtarı/token |
| LDAP / XPath injection | A03:2021 | YOK | dizin/XML sorgu enjeksiyonu |
| GraphQL batching / derinlik DoS | API4:2023 | YOK | alias/batch ile rate-limit atlatma, derin sorgu |
| Subdomain takeover | A05:2021, API9:2023 | YOK | sahipsiz DNS kaydı → alan adı devralma |
| Yansıyan (reflected) XSS | A03:2021 | `xss` | yansıyan XSS: InjectionOracle `xss` tipi (marker ham yansıma) |
| Sistem istemi sızıntısı | LLM07:2025 | `system_prompt_leakage` | hedef LLM'in gizli sistem istemini ifşa etmesi |
| Vektör/RAG zayıflıkları | LLM08:2025 | YOK | gömme/RAG deposu zehirleme veya çapraz-kiracı sızıntı |
| Sınırsız tüketim (LLM/API maliyet DoS) | LLM10:2025, API4:2023 | YOK | token/kaynak sınırı yok |
| Loglama/izleme eksikliği | A09:2021 | YOK | dışarıdan kanıtlanması zor; çoğunlukla kapsam dışı |
