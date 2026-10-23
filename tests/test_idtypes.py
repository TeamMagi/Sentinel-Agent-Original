"""IdTypeInferrer testleri — id tipi çıkarımı ve bogus id üretimi."""
from pentestai.idtypes import (
    INTEGER, OBJECTID, OPAQUE, STRING, UNKNOWN, UUID,
    IdTypeInferrer,
)


# ===================== from_value =====================

def test_from_value_integer():
    assert IdTypeInferrer.from_value(42) == INTEGER

def test_from_value_integer_string():
    assert IdTypeInferrer.from_value("12345") == INTEGER

def test_from_value_uuid():
    assert IdTypeInferrer.from_value("550e8400-e29b-41d4-a716-446655440000") == UUID

def test_from_value_uuid_uppercase():
    assert IdTypeInferrer.from_value("550E8400-E29B-41D4-A716-446655440000") == UUID

def test_from_value_objectid():
    assert IdTypeInferrer.from_value("507f1f77bcf86cd799439011") == OBJECTID

def test_from_value_opaque():
    assert IdTypeInferrer.from_value("tok_abc123xyz456def") == OPAQUE

def test_from_value_short_string():
    assert IdTypeInferrer.from_value("hello") == STRING

def test_from_value_empty():
    assert IdTypeInferrer.from_value("") == UNKNOWN

def test_from_value_none():
    assert IdTypeInferrer.from_value(None) == UNKNOWN

def test_from_value_bool():
    assert IdTypeInferrer.from_value(True) == UNKNOWN

def test_from_value_zero():
    assert IdTypeInferrer.from_value(0) == INTEGER


# ===================== from_openapi_schema =====================

def test_openapi_uuid():
    assert IdTypeInferrer.from_openapi_schema({"type": "string", "format": "uuid"}) == UUID

def test_openapi_integer():
    assert IdTypeInferrer.from_openapi_schema({"type": "integer"}) == INTEGER

def test_openapi_number():
    assert IdTypeInferrer.from_openapi_schema({"type": "number"}) == INTEGER

def test_openapi_string():
    assert IdTypeInferrer.from_openapi_schema({"type": "string"}) == STRING

def test_openapi_uuid_pattern():
    assert IdTypeInferrer.from_openapi_schema({"type": "string", "pattern": "[0-9a-fA-F]{8}-"}) == UUID

def test_openapi_none():
    assert IdTypeInferrer.from_openapi_schema(None) == UNKNOWN

def test_openapi_empty_dict():
    assert IdTypeInferrer.from_openapi_schema({}) == UNKNOWN


# ===================== bogus_for =====================

def test_bogus_integer():
    b = IdTypeInferrer.bogus_for(INTEGER)
    assert b.isdigit()

def test_bogus_uuid():
    b = IdTypeInferrer.bogus_for(UUID)
    assert len(b) == 36
    assert "-" in b

def test_bogus_objectid():
    b = IdTypeInferrer.bogus_for(OBJECTID)
    assert len(b) == 24

def test_bogus_unknown():
    b = IdTypeInferrer.bogus_for(UNKNOWN)
    assert b.isdigit()

def test_bogus_none():
    b = IdTypeInferrer.bogus_for(None)
    assert b.isdigit()
