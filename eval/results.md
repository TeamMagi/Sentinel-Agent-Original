# Sentinel-Agent — Çalıştırılabilir self-eval (planted TP + FP + near-miss)

**Vaka:** 31 · **TP/FP/FN/TN:** 14/0/0/17

- **Precision:** %100.0
- **Recall:** %100.0
- **FP-rate:** %0.0
- **Near-miss disiplini:** ✅ hepsi doğru flag'lenmedi

| Vaka | Tip | Kategori | Beklenen | Verdict | Sonuç |
|---|---|---|---|---|---|
| idor-basket:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-basket:hardened | idor | negative | not:CONFIRMED | REJECTED | ✅ |
| bfla-admin:vulnerable | bfla | positive | CONFIRMED | CONFIRMED | ✅ |
| bfla-admin:hardened | bfla | negative | not:CONFIRMED | REJECTED | ✅ |
| idor-public-by-design:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-public-by-design:near-miss | idor | near_miss | not:CONFIRMED | REJECTED | ✅ |
| idor-session-scoped:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-session-scoped:near-miss | idor | near_miss | not:CONFIRMED | INCONCLUSIVE | ✅ |
| idor-query-param:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-query-param:hardened | idor | negative | not:CONFIRMED | REJECTED | ✅ |
| idor-empty-result:vulnerable | idor | positive | CONFIRMED | CONFIRMED | ✅ |
| idor-empty-result:near-miss | idor | near_miss | not:CONFIRMED | LIKELY | ✅ |
| collection-leak:vulnerable | bola | positive | CONFIRMED | CONFIRMED | ✅ |
| collection-leak:scoped | bola | negative | not:CONFIRMED | REJECTED | ✅ |
| collection-leak:public | bola | near_miss | not:CONFIRMED | REJECTED | ✅ |
| path-traversal:vulnerable | path_traversal | positive | CONFIRMED | CONFIRMED | ✅ |
| path-traversal:hardened | path_traversal | negative | not:CONFIRMED | REJECTED | ✅ |
| path-traversal:echo | path_traversal | near_miss | not:CONFIRMED | REJECTED | ✅ |
| unauthorized-access-admin:vulnerable | unauthorized_access | positive | CONFIRMED | CONFIRMED | ✅ |
| unauthorized-access-admin:hardened | unauthorized_access | negative | not:CONFIRMED | REJECTED | ✅ |
| bopla-exposure:vulnerable | excessive_data_exposure | positive | CONFIRMED | CONFIRMED | ✅ |
| bopla-exposure:hardened | excessive_data_exposure | negative | not:CONFIRMED | REJECTED | ✅ |
| bopla-exposure:near-miss | excessive_data_exposure | near_miss | not:CONFIRMED | LIKELY | ✅ |
| method-bypass-delete:vulnerable | method_bypass | positive | CONFIRMED | CONFIRMED | ✅ |
| method-bypass-delete:hardened | method_bypass | negative | not:CONFIRMED | REJECTED | ✅ |
| mass-assignment-isadmin:vulnerable | mass_assignment | positive | CONFIRMED | CONFIRMED | ✅ |
| mass-assignment-isadmin:hardened | mass_assignment | negative | not:CONFIRMED | REJECTED | ✅ |
| graphql-bola-order:vulnerable | graphql_bola | positive | CONFIRMED | CONFIRMED | ✅ |
| graphql-bola-order:hardened | graphql_bola | negative | not:CONFIRMED | REJECTED | ✅ |
| state-change-bola-write:vulnerable | state_change_authz | positive | CONFIRMED | CONFIRMED | ✅ |
| state-change-bola-write:hardened | state_change_authz | negative | not:CONFIRMED | REJECTED | ✅ |
