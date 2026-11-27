"""HypothesisGenerator + LLM parse. DESIGN.md §14 (Stage 1)."""
import pytest

from pentestai.llm import MockLLMClient
from pentestai.llm.client import _parse_hypotheses
from pentestai.models import Endpoint, Hypothesis, Param
from pentestai.planner import HypothesisGenerator

EPS = [
    Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
    Endpoint(method="GET", path_template="/api/admin/config", id_param="id"),
    Endpoint(method="GET", path_template="/api/health", id_param="id"),
    Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id"),
    Endpoint(method="POST", path_template="/api/uploads", id_param="id"),
]


def test_deterministic_rules():
    hs = HypothesisGenerator().deterministic(EPS)
    types = {(h.type, h.endpoint.path_template, h.endpoint.method) for h in hs}
    assert ("idor", "/api/orders/{id}", "GET") in types     # path param → IDOR
    assert ("excessive_data_exposure", "/api/orders/{id}", "GET") in types  # obje → BOPLA
    assert ("bfla", "/api/admin/config", "GET") in types     # admin → BFLA
    plain_types = {(h.type, h.endpoint.path_template) for h in hs}
    assert ("idor", "/api/health") not in plain_types       # id yok → aday değil
    # B1: csrf + mass_assignment yalnızca yazma-metodu + id'li endpoint'te
    assert ("csrf", "/api/orders/{id}", "PUT") in types
    assert ("mass_assignment", "/api/orders/{id}", "PUT") in types
    assert ("state_change_authz", "/api/orders/{id}", "PUT") in types
    # B1: file_upload — path'inde "upload" geçen endpoint
    assert ("file_upload", "/api/uploads", "POST") in types
    assert ("csrf", "/api/uploads", "POST") not in types    # yazma metodu var ama id yok


def test_emits_jwt_privilege_escalation_for_identity_reads():
    eps = [
        Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),  # obje okuması
        Endpoint(method="GET", path_template="/api/me"),                          # kimlik segmenti
        Endpoint(method="GET", path_template="/api/management"),                  # "me" YALNIZ substring
        Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id"),  # yazma → hariç
    ]
    types = {(h.type, h.endpoint.path_template, h.endpoint.method)
             for h in HypothesisGenerator().deterministic(eps)}
    assert ("jwt_privilege_escalation", "/api/orders/{id}", "GET") in types   # has_id okuma
    assert ("jwt_privilege_escalation", "/api/me", "GET") in types            # segment eşleşmesi
    # segment eşleşmesi (substring değil): "management" segmenti "me" ile eşleşMEmeli
    assert ("jwt_privilege_escalation", "/api/management", "GET") not in types
    # dikey yükseltme yalnız GET/HEAD — yazma metodunda iki-kez-baseline riski var
    assert ("jwt_privilege_escalation", "/api/orders/{id}", "PUT") not in types


def test_emits_nested_idor_for_dotted_body_id():
    ep = Endpoint(method="POST", path_template="/api/getOrder",
                  id_param="filter.orderId", id_location="body")
    hs = HypothesisGenerator().deterministic([ep])
    nested = [h for h in hs if h.type == "nested_idor"]
    assert len(nested) == 1 and nested[0].body_path == "filter.orderId"
    # düz body id (nokta yok) → nested_idor ÜRETİLMEZ (mevcut IdorOracle zaten kapsıyor)
    flat = Endpoint(method="POST", path_template="/api/getOrder",
                    id_param="orderId", id_location="body")
    assert not any(h.type == "nested_idor" for h in HypothesisGenerator().deterministic([flat]))


def test_injection_hypothesis_targets_json_body_field():
    # crAPI coupon sınıfı: gövde alanı için injection hipotezi param_location="body" taşımalı
    # (oracle NoSQL operatörünü nesne olarak gömsün diye).
    ep = Endpoint(method="POST", path_template="/community/api/v2/coupon/validate-coupon",
                  id_param="coupon_code", id_location="body")
    inj = [h for h in HypothesisGenerator().deterministic([ep]) if h.type == "injection"]
    assert len(inj) == 1
    assert inj[0].param == "coupon_code" and inj[0].param_location == "body"


@pytest.mark.asyncio
async def test_generate_merges_llm_and_dedupes():
    canned = [Hypothesis(type="idor", endpoint=Endpoint(path_template="/api/carts/{id}"))]
    gen = HypothesisGenerator(MockLLMClient(canned))
    hs = await gen.generate(EPS)
    paths = {(h.type, h.endpoint.path_template) for h in hs}
    assert ("idor", "/api/carts/{id}") in paths       # LLM'den
    assert ("idor", "/api/orders/{id}") in paths       # deterministik
    # dedupe: aynı (type, method, path) tek kez
    assert len(hs) == len({(h.type, h.endpoint.method, h.endpoint.path_template) for h in hs})


def test_llm_parse_valid_json():
    text = '[{"type":"idor","path_template":"/api/x/{id}","id_param":"id"}]'
    hs = _parse_hypotheses(text)
    assert len(hs) == 1 and hs[0].type == "idor" and hs[0].source == "llm"


def test_llm_parse_ignores_prose_and_bad_items():
    text = 'İşte adaylar: [{"type":"bfla","path_template":"/api/admin"},{"bad":1}] bitti'
    hs = _parse_hypotheses(text)
    assert len(hs) == 1 and hs[0].type == "bfla"     # geçersiz öğe atıldı, prose yok sayıldı


class _RaisingLLM(MockLLMClient):
    """propose_hypotheses çağrısında hata fırlatan client (Ollama erişilemez senaryosu)."""

    async def propose_hypotheses(self, recon_summary):
        raise RuntimeError("ollama erişilemez")


@pytest.mark.asyncio
async def test_generate_llm_error_falls_back_to_deterministic():
    # LLM erişilemezse (ağ/servis hatası) tarama ÇÖKMEZ; deterministik hipotezler döner.
    gen = HypothesisGenerator(_RaisingLLM())
    hs = await gen.generate(EPS)
    det = HypothesisGenerator().deterministic(EPS)
    assert {(h.type, h.endpoint.method, h.endpoint.path_template) for h in hs} == \
           {(h.type, h.endpoint.method, h.endpoint.path_template) for h in det}
    assert all(h.source == "deterministic" for h in hs)


# --- Faz 3 / T3: çok-parametreli hipotez üretimi + risk-sınıflı param hipotezleri ---

def test_injection_and_timing_generated_for_every_query_param_id_less_endpoint():
    """id'siz GET /search?q= ucunda `q` için injection hipotezi üretilir (önceden hiç
    üretilmiyordu — has_id dalı dışındaki parametreler atlanıyordu)."""
    ep = Endpoint(method="GET", path_template="/rest/products/search",
                 params=[Param(name="q", location="query", type="string")])
    hyps = HypothesisGenerator().deterministic([ep])
    inj = [h for h in hyps if h.type == "injection" and h.param == "q"]
    timing = [h for h in hyps if h.type == "timing" and h.param == "q"]
    assert len(inj) == 1 and inj[0].param_location == "query"
    assert len(timing) == 1


def test_injection_generated_for_body_param_distinct_from_id_param():
    """id_param'ı ('id', path) KORUYARAK ek bir gövde parametresi ('note') için de ayrı bir
    injection hipotezi üretilir — ikisi birbirini EZMEZ (dedupe param+location'ı anahtara katar)."""
    ep = Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id",
                 params=[Param(name="note", location="body", type="string")])
    hyps = HypothesisGenerator().deterministic([ep])
    inj = [h for h in hyps if h.type == "injection"]
    params = {(h.param, h.param_location) for h in inj}
    assert ("id", "path") in params
    assert ("note", "body") in params
    assert len(inj) == 2   # ikisi de kaldı, ne biri diğerini ezdi ne de yinelendi


def test_url_like_param_gets_ssrf_and_open_redirect_hypotheses_with_param():
    ep = Endpoint(method="GET", path_template="/rest/image",
                 params=[Param(name="url", location="query", type="string")])
    hyps = HypothesisGenerator().deterministic([ep])
    ssrf = [h for h in hyps if h.type == "ssrf" and h.param == "url"]
    openr = [h for h in hyps if h.type == "open_redirect" and h.param == "url"]
    assert len(ssrf) == 1 and ssrf[0].param_location == "query"
    assert len(openr) == 1


def test_file_like_param_gets_path_traversal_hypothesis_with_param():
    ep = Endpoint(method="GET", path_template="/rest/download",
                 params=[Param(name="file", location="query", type="string")])
    hyps = HypothesisGenerator().deterministic([ep])
    pt = [h for h in hyps if h.type == "path_traversal" and h.param == "file"]
    assert len(pt) == 1


def test_role_like_body_param_adds_mass_assignment_for_idless_destructive_endpoint():
    """id'siz PUT/PATCH/DELETE ucunda rol/yetki adlı gövde alanı varsa mass_assignment adayı
    üretilir — önceden bu dal yalnızca has_id altındaydı, id'siz ama destructive uçlar kaçıyordu."""
    ep = Endpoint(method="PUT", path_template="/rest/profile",
                 params=[Param(name="role", location="body", type="string")])
    hyps = HypothesisGenerator().deterministic([ep])
    assert any(h.type == "mass_assignment" for h in hyps)


def test_no_role_like_body_param_no_extra_mass_assignment_for_idless_endpoint():
    """Rol/yetki adlı alan yoksa id'siz destructive uçta yine mass_assignment üretilmez
    (0-FP: sinyalsiz aday eklenmez)."""
    ep = Endpoint(method="PUT", path_template="/rest/profile",
                 params=[Param(name="nickname", location="body", type="string")])
    hyps = HypothesisGenerator().deterministic([ep])
    assert not any(h.type == "mass_assignment" for h in hyps)
