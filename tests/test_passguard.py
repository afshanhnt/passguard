import json

import pytest

from passguard.generator import generate_passphrase, generate_password
from passguard.strength import analyze
from passguard.vault import Vault, VaultError


def test_common_password_is_very_weak():
    assert analyze("password").score == 0


def test_strong_password_scores_high():
    assert analyze("k9#Lm2$vQx7!Zp4wRt").score >= 3


def test_sequences_are_penalised():
    assert analyze("abcd1234XYZ!").entropy_bits < analyze("kd8#Xq2!Lp9z").entropy_bits


def test_generated_password_meets_rules():
    pw = generate_password(20)
    assert len(pw) == 20
    assert any(c.isupper() for c in pw) and any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)


def test_passwords_are_unique():
    assert len({generate_password() for _ in range(50)}) == 50


def test_passphrase_word_count():
    assert len(generate_passphrase(6).split("-")) == 6


def test_generator_rejects_short_length():
    with pytest.raises(ValueError):
        generate_password(4)


def test_vault_roundtrip(tmp_path):
    v = Vault(tmp_path / "v.pg")
    v.init("master-pass")
    v.add("master-pass", "github", "alice", "s3cret")
    assert v.get("master-pass", "github") == {"username": "alice", "password": "s3cret"}
    assert v.list_names("master-pass") == ["github"]


def test_vault_wrong_password(tmp_path):
    v = Vault(tmp_path / "v.pg")
    v.init("right")
    with pytest.raises(VaultError):
        v.load("wrong")


def test_vault_detects_tampering(tmp_path):
    path = tmp_path / "v.pg"
    v = Vault(path)
    v.init("pw")
    v.add("pw", "a", "u", "p")
    blob = json.loads(path.read_text())
    ct = bytearray(__import__("base64").b64decode(blob["ciphertext"]))
    ct[0] ^= 1
    blob["ciphertext"] = __import__("base64").b64encode(bytes(ct)).decode()
    path.write_text(json.dumps(blob))
    with pytest.raises(VaultError):
        v.load("pw")


def test_vault_file_has_no_plaintext(tmp_path):
    path = tmp_path / "v.pg"
    v = Vault(path)
    v.init("pw")
    v.add("pw", "bank", "bob", "hunter2")
    assert "hunter2" not in path.read_text()
    assert "bank" not in path.read_text()
