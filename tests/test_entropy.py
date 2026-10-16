from pentestai.agent.entropy import (
    find_high_entropy_strings,
    has_high_entropy_secret,
    shannon_entropy,
)


def test_empty_string():
    assert shannon_entropy('') == 0.0

def test_single_char():
    assert shannon_entropy('aaaa') == 0.0

def test_high_entropy():
    assert shannon_entropy('sk_live_abc123def456ghi789') > 4.0

def test_low_entropy():
    assert shannon_entropy('hello') < 2.5

def test_find_high_entropy():
    result = find_high_entropy_strings('key=sk_live_abc123def456ghi789jkl012')
    assert len(result) == 1

def test_find_nothing():
    assert find_high_entropy_strings('hello world') == []

def test_has_secret_true():
    assert has_high_entropy_secret('token=AbCdEfGhIjKlMnOpQrStUvWxYz123456') is True

def test_has_secret_false():
    assert has_high_entropy_secret('normal text here') is False
