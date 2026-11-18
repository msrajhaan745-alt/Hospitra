from app.core.security import hash_password, new_session_token, token_digest, verify_password


def test_hash_and_verify_round_trip():
    encoded = hash_password("a-long-password", iterations=1000)
    assert encoded.startswith("pbkdf2_sha256$1000$")
    assert verify_password("a-long-password", encoded)
    assert not verify_password("a-long-passwore", encoded)


def test_salts_differ_and_plaintext_not_stored():
    a, b = hash_password("same-password-1", iterations=1000), hash_password("same-password-1", iterations=1000)
    assert a != b
    assert "same-password-1" not in a


def test_malformed_hashes_never_verify():
    for bad in ["", "plain", "md5$1$a$b", "pbkdf2_sha256$x$y$z", "pbkdf2_sha256$1000$!!$!!"]:
        assert verify_password("anything", bad) is False


def test_tokens_are_unique_and_digests_stable():
    t1, t2 = new_session_token(), new_session_token()
    assert t1 != t2 and len(t1) >= 40
    assert token_digest(t1) == token_digest(t1) and token_digest(t1) != t1 and len(token_digest(t1)) == 64
