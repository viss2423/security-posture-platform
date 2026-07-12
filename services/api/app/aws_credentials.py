"""Canonical (de)serialization for stored AWS connector credentials.

AWS needs several secret fields (access key id + secret access key, plus an optional
session token) where GitHub needs only a single PAT. Rather than widen the
``user_credentials`` schema, the whole credential is canonicalized into a compact JSON
document and stored in the existing single ``ciphertext`` column, encrypted as one Fernet
blob. This module is the *only* place that defines that on-disk shape, so connect-time
canonicalization and scan-time parsing can never drift apart.

Fails closed: malformed input or missing required fields raise ``AwsCredentialError`` so a
caller refuses the credential rather than persisting — or scanning with — junk. A stored
blob that isn't the expected shape (e.g. a legacy raw string) is rejected on read for the
same reason: better a failed scan than boto3 silently falling back to ambient credentials.
"""

from __future__ import annotations

import json

# Bound each field so a malformed/oversized paste can't bloat the encrypted row. Real AWS
# access key ids are 20 chars and secret keys 40; session tokens are larger but well under 4k.
_MAX_FIELD_LEN = 4096


class AwsCredentialError(ValueError):
    """Raised when AWS credential material is missing required fields or malformed."""


def _clean_fields(parsed: object) -> dict[str, str]:
    if not isinstance(parsed, dict):
        raise AwsCredentialError("aws credentials must be a JSON object")
    access_key_id = str(parsed.get("access_key_id") or "").strip()
    secret_access_key = str(parsed.get("secret_access_key") or "").strip()
    session_token = str(parsed.get("session_token") or "").strip()
    if not access_key_id or not secret_access_key:
        raise AwsCredentialError("access_key_id and secret_access_key are required")
    for name, value in (
        ("access_key_id", access_key_id),
        ("secret_access_key", secret_access_key),
        ("session_token", session_token),
    ):
        if len(value) > _MAX_FIELD_LEN:
            raise AwsCredentialError(f"{name} is too long")
    canonical = {"access_key_id": access_key_id, "secret_access_key": secret_access_key}
    if session_token:
        canonical["session_token"] = session_token
    return canonical


def canonicalize_aws_credential(raw: str) -> str:
    """Validate user-supplied AWS credential material and return canonical JSON to encrypt.

    ``raw`` is the value from the connect ``token`` field: a JSON object with
    ``access_key_id`` and ``secret_access_key`` (and optionally ``session_token``). Unknown
    keys are dropped; required keys must be non-empty. The returned string is what gets
    encrypted and stored, so it is stable and minimal.
    """
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise AwsCredentialError("aws credentials must be a JSON object") from exc
    return json.dumps(_clean_fields(parsed), separators=(",", ":"), sort_keys=True)


def parse_aws_credential(plaintext: str) -> dict[str, str]:
    """Parse a decrypted canonical AWS credential document back into fields.

    Returns a dict with ``access_key_id``, ``secret_access_key`` and optionally
    ``session_token``. Raises ``AwsCredentialError`` if the stored blob is not the expected
    shape, so a scan fails closed instead of handing boto3 empty/partial credentials.
    """
    try:
        parsed = json.loads(plaintext)
    except (json.JSONDecodeError, TypeError) as exc:
        raise AwsCredentialError("stored aws credential is not valid JSON") from exc
    return _clean_fields(parsed)
