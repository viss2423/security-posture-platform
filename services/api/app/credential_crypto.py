"""Fernet encryption for user-supplied connector credentials (GitHub PATs, AWS keys).

Keys come from ``settings.CREDENTIAL_ENCRYPTION_KEYS`` — a JSON object mapping an integer
key version to a urlsafe-base64 Fernet key, e.g. ``{"1": "<fernet-key>"}``. New secrets are
encrypted with ``CREDENTIAL_ENCRYPTION_ACTIVE_VERSION`` and every ciphertext records the
version that produced it, so keys can be rotated (add version 2, flip the active version)
without re-encrypting existing rows.

Fails closed: if no usable key is configured, ``encrypt_secret`` raises
``CredentialEncryptionUnavailableError``. Callers MUST treat that as "refuse to store the
secret" — never as a signal to persist the credential in the clear.
"""

from __future__ import annotations

import json

from cryptography.fernet import Fernet, InvalidToken

from app.settings import settings


class CredentialEncryptionUnavailableError(RuntimeError):
    """Raised when credentials cannot be en/decrypted (missing/invalid key). Fail closed."""


def _load_keys() -> dict[int, Fernet]:
    raw = str(getattr(settings, "CREDENTIAL_ENCRYPTION_KEYS", "") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CredentialEncryptionUnavailableError(
            "CREDENTIAL_ENCRYPTION_KEYS is not valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise CredentialEncryptionUnavailableError("CREDENTIAL_ENCRYPTION_KEYS must be a JSON object")
    keys: dict[int, Fernet] = {}
    for version, key in parsed.items():
        try:
            keys[int(version)] = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
        except Exception as exc:  # noqa: BLE001 - any bad key = fail closed for that version
            raise CredentialEncryptionUnavailableError(
                f"invalid Fernet key for version {version}"
            ) from exc
    return keys


def _active_version() -> int:
    return int(getattr(settings, "CREDENTIAL_ENCRYPTION_ACTIVE_VERSION", 0) or 0)


def encrypt_secret(plaintext: str) -> tuple[str, int]:
    """Encrypt ``plaintext`` with the active key. Returns (ciphertext, key_version)."""
    keys = _load_keys()
    version = _active_version()
    fernet = keys.get(version)
    if fernet is None:
        raise CredentialEncryptionUnavailableError("no active credential encryption key configured")
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8"), version


def decrypt_secret(ciphertext: str, key_version: int) -> str:
    """Decrypt ``ciphertext`` using the key that produced it (by ``key_version``)."""
    keys = _load_keys()
    fernet = keys.get(int(key_version))
    if fernet is None:
        raise CredentialEncryptionUnavailableError(
            f"no credential encryption key for version {key_version}"
        )
    try:
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialEncryptionUnavailableError("credential decryption failed") from exc
