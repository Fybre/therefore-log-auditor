"""Pure unit tests for crypto.py - no DB needed."""
from cryptography.fernet import Fernet


def test_arbitrary_string_round_trips(monkeypatch):
    """The whole point: AUDITOR_ENC_KEY doesn't need to be a real Fernet key, any string works."""
    from auditor import crypto
    monkeypatch.setattr(crypto, "_key_cache", None)
    monkeypatch.setenv("AUDITOR_ENC_KEY", "just some passphrase, not a real Fernet key")
    assert crypto.decrypt(crypto.encrypt("hunter2")) == "hunter2"


def test_same_string_derives_the_same_key_across_processes(monkeypatch):
    """Stability across restarts is the entire requirement - encrypting under one process and
    decrypting under a fresh one (simulated here by clearing the cache) must still work."""
    from auditor import crypto
    monkeypatch.setenv("AUDITOR_ENC_KEY", "a stable passphrase")
    monkeypatch.setattr(crypto, "_key_cache", None)
    token = crypto.encrypt("s3cret")
    monkeypatch.setattr(crypto, "_key_cache", None)   # simulate a fresh process
    assert crypto.decrypt(token) == "s3cret"


def test_different_strings_derive_different_keys(monkeypatch):
    from auditor import crypto
    monkeypatch.setenv("AUDITOR_ENC_KEY", "passphrase one")
    monkeypatch.setattr(crypto, "_key_cache", None)
    token = crypto.encrypt("s3cret")

    monkeypatch.setenv("AUDITOR_ENC_KEY", "a totally different passphrase")
    monkeypatch.setattr(crypto, "_key_cache", None)
    assert crypto.decrypt(token) == ""   # wrong key - can't read it, matches old behaviour


def test_a_real_fernet_key_is_used_as_is_not_rederived(monkeypatch):
    """Backward compatibility: anyone who already generated a real key with
    Fernet.generate_key() keeps using it unchanged, rather than it being re-derived into a
    different key that would orphan their existing encrypted secrets."""
    from auditor import crypto
    real_key = Fernet.generate_key().decode()
    monkeypatch.setenv("AUDITOR_ENC_KEY", real_key)
    monkeypatch.setattr(crypto, "_key_cache", None)
    assert crypto._key() == real_key.encode()


def test_enc_key_is_stable_true_for_any_nonempty_value(monkeypatch):
    from auditor import crypto
    monkeypatch.setenv("AUDITOR_ENC_KEY", "literally anything")
    assert crypto.enc_key_is_stable() is True


def test_enc_key_is_stable_false_when_unset(monkeypatch):
    from auditor import crypto
    monkeypatch.delenv("AUDITOR_ENC_KEY", raising=False)
    assert crypto.enc_key_is_stable() is False
