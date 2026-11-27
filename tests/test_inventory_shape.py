"""Yanıt şekli parmak izi testleri — değer sızdırmazlığı ve determinizm."""
import json

from pentestai.inventory.shape import (
    SENSITIVE_FIELD_HINTS,
    response_fields,
    response_shape_fingerprint,
    sensitive_fields,
)


def test_nested_object_and_list_fields():
    fields = response_fields({"id": 1, "user": {"email": "a@b", "tags": ["x"]}})
    assert fields == [
        "id:int",
        "user:object",
        "user.email:str",
        "user.tags:list",
        "user.tags[]:str",
    ]


def test_list_element_schemas_are_merged():
    fields = response_fields({"items": [{"id": 1, "name": "a"}, {"id": 2, "extra": True}]})
    assert fields == [
        "items:list",
        "items[]:object",
        "items[].extra:bool",
        "items[].id:int",
        "items[].name:str",
    ]


def test_scalar_type_distinctions():
    fields = response_fields({
        "a": True, "b": 1, "c": 1.5, "d": None, "e": "x", "f": [], "g": {},
    })
    assert fields == [
        "a:bool", "b:int", "c:float", "d:null", "e:str", "f:list", "g:object",
    ]


def test_values_never_appear_in_output():
    fields = response_fields({
        "email": "secret@example.com",
        "token": "super-secret-token",
        "nested": {"phone": "+905551112233"},
    })
    joined = "\n".join(fields)
    assert "secret@example.com" not in joined
    assert "super-secret-token" not in joined
    assert "+905551112233" not in joined
    assert joined == "email:str\nnested:object\nnested.phone:str\ntoken:str"


def test_non_json_body_returns_none_and_empty():
    assert response_shape_fingerprint("<html>merhaba</html>") == (None, [])
    assert response_shape_fingerprint(b"\xff\xfe bozuk") == (None, [])
    assert response_shape_fingerprint(None) == (None, [])
    assert response_shape_fingerprint("") == (None, [])


def test_same_schema_different_values_same_hash():
    first_hash, first_fields = response_shape_fingerprint('{"id": 1, "name": "ali"}')
    second_hash, second_fields = response_shape_fingerprint(b'{"name": "veli", "id": 999}')
    assert first_hash is not None
    assert len(first_hash) == 16
    assert first_hash == second_hash
    assert first_fields == second_fields == ["id:int", "name:str"]


def test_adding_a_field_changes_hash():
    before, _ = response_shape_fingerprint(json.dumps({"id": 1}))
    after, fields = response_shape_fingerprint(json.dumps({"id": 1, "email": "x@y"}))
    assert before is not None and after is not None
    assert before != after
    assert "email:str" in fields


def test_depth_limit_stops_descending():
    fields = response_fields({"a": {"b": {"c": 1}}}, max_depth=1)
    assert fields == ["a:object"]


def test_field_limit_caps_output():
    data = {f"k{i}": i for i in range(20)}
    fields = response_fields(data, max_fields=3)
    assert len(fields) == 3


def test_zero_limits_return_empty():
    assert response_fields({"a": 1}, max_fields=0) == []
    assert response_fields({"a": 1}, max_depth=-1) == []


def test_sensitive_fields_matches_last_segment_case_insensitively():
    fields = [
        "id:int",
        "user.email:str",
        "user.password:str",
        "meta.apiKey:str",
        "user.tags[]:str",
        "billing.iban:str",
        "profile.Email:str",
    ]
    assert sensitive_fields(fields) == [
        "user.email:str",
        "user.password:str",
        "meta.apiKey:str",
        "billing.iban:str",
        "profile.Email:str",
    ]


def test_sensitive_field_hints_include_required_tokens():
    required = {
        "email", "ssn", "password", "passwd", "token", "secret", "phone", "address",
        "card", "iban", "dob", "birth", "salary", "api_key", "apikey", "credit",
    }
    assert required.issubset(set(SENSITIVE_FIELD_HINTS))
