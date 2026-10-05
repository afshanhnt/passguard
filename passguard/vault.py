"""Encrypted password vault.

Security design:
  * Key derivation: scrypt (memory-hard) turns the master password into a 256-bit key.
  * Encryption: AES-256-GCM, which provides confidentiality AND tamper detection.
  * A fresh random salt is created per vault and a fresh nonce on every save.
"""
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
VERSION = 1


class VaultError(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def _derive_key(master: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(master.encode())


class Vault:
    def __init__(self, path):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def _write(self, entries: dict, master: str, salt: bytes):
        key = _derive_key(master, salt)
        nonce = os.urandom(12)
        header = f"passguard-v{VERSION}".encode()  # authenticated but not encrypted
        ct = AESGCM(key).encrypt(nonce, json.dumps(entries).encode(), header)
        blob = {"version": VERSION, "salt": _b64e(salt),
                "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}
        self.path.write_text(json.dumps(blob))
        try:
            os.chmod(self.path, 0o600)  # owner read/write only
        except OSError:
            pass

    def init(self, master: str):
        if self.exists():
            raise VaultError("Vault already exists.")
        self._write({}, master, os.urandom(16))

    def load(self, master: str) -> dict:
        if not self.exists():
            raise VaultError("Vault not found. Run 'vault init' first.")
        blob = json.loads(self.path.read_text())
        salt, nonce, ct = _b64d(blob["salt"]), _b64d(blob["nonce"]), _b64d(blob["ciphertext"])
        key = _derive_key(master, salt)
        try:
            header = f"passguard-v{blob['version']}".encode()
            return json.loads(AESGCM(key).decrypt(nonce, ct, header))
        except InvalidTag:
            raise VaultError("Wrong master password, or the vault file was tampered with.")

    def save(self, entries: dict, master: str):
        salt = _b64d(json.loads(self.path.read_text())["salt"])
        self._write(entries, master, salt)

    def add(self, master: str, name: str, username: str, password: str):
        entries = self.load(master)
        entries[name] = {"username": username, "password": password}
        self.save(entries, master)

    def get(self, master: str, name: str) -> dict:
        entries = self.load(master)
        if name not in entries:
            raise VaultError(f"No entry named '{name}'.")
        return entries[name]

    def delete(self, master: str, name: str):
        entries = self.load(master)
        if name not in entries:
            raise VaultError(f"No entry named '{name}'.")
        del entries[name]
        self.save(entries, master)

    def list_names(self, master: str) -> list:
        return sorted(self.load(master))
