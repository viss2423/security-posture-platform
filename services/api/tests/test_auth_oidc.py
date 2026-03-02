"""
Phase B.1: Auth config and OIDC SSO endpoints.

Tests GET /auth/config, GET /auth/oidc/login, GET /auth/oidc/callback (error paths).
Run: pytest services/api/tests/test_auth_oidc.py -v
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app.main import app
from app.routers import auth

client = TestClient(app)


def test_auth_config_oidc_disabled():
    """When OIDC env vars are not set, oidc_enabled is false."""
    with patch.object(auth.settings, "OIDC_ISSUER_URL", None):
        with patch.object(auth.settings, "OIDC_CLIENT_ID", None):
            auth._oidc_config = None  # clear cache
            r = client.get("/auth/config")
    assert r.status_code == 200
    assert r.json() == {"oidc_enabled": False}


def test_auth_config_oidc_enabled():
    """When OIDC env vars are set, oidc_enabled is true."""
    with patch.object(auth.settings, "OIDC_ISSUER_URL", "https://idp.example.com"):
        with patch.object(auth.settings, "OIDC_CLIENT_ID", "client1"):
            with patch.object(auth.settings, "OIDC_CLIENT_SECRET", "secret"):
                with patch.object(auth.settings, "OIDC_REDIRECT_URI", "http://api.example.com/cb"):
                    auth._oidc_config = None
                    r = client.get("/auth/config")
    assert r.status_code == 200
    assert r.json() == {"oidc_enabled": True}


def test_oidc_login_disabled_returns_404():
    """GET /auth/oidc/login when OIDC not configured returns 404."""
    with patch.object(auth.settings, "OIDC_ISSUER_URL", None):
        auth._oidc_config = None
        r = client.get("/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 404
    body = r.json()
    detail = body.get("detail") or (body.get("error") or {}).get("detail", "")
    assert "OIDC not configured" in detail


def test_oidc_login_enabled_redirects_to_idp():
    """GET /auth/oidc/login when OIDC configured returns 302 with Location to IdP auth endpoint."""
    fake_discovery = {
        "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/token",
    }
    with patch.object(auth.settings, "OIDC_ISSUER_URL", "https://idp.example.com"):
        with patch.object(auth.settings, "OIDC_CLIENT_ID", "client1"):
            with patch.object(auth.settings, "OIDC_CLIENT_SECRET", "secret"):
                with patch.object(
                    auth.settings, "OIDC_REDIRECT_URI", "http://api.example.com/auth/oidc/callback"
                ):
                    with patch.object(auth.settings, "OIDC_SCOPES", "openid profile email"):
                        with patch.object(auth, "_get_oidc_config", return_value=fake_discovery):
                            auth._oidc_config = None
                            r = client.get("/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers.get("Location", "")
    assert "https://idp.example.com/oauth2/authorize" in location
    assert "client_id=client1" in location
    assert "response_type=code" in location
    assert "state=" in location
    assert "nonce=" in location
    assert "redirect_uri=" in location


def test_oidc_callback_with_error_param_redirects():
    """GET /auth/oidc/callback?error=access_denied redirects to frontend with error in fragment."""
    with patch.object(auth.settings, "FRONTEND_URL", "http://localhost:3000"):
        r = client.get("/auth/oidc/callback?error=access_denied", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers.get("Location", "")
    assert location.startswith("http://localhost:3000/login#")
    assert "error=access_denied" in location


def test_oidc_callback_invalid_state_redirects():
    """GET /auth/oidc/callback with invalid state redirects with error."""
    with patch.object(auth.settings, "FRONTEND_URL", "http://localhost:3000"):
        r = client.get(
            "/auth/oidc/callback?code=abc&state=invalid_state_value",
            follow_redirects=False,
        )
    assert r.status_code == 302
    location = r.headers.get("Location", "")
    assert "error=invalid_callback" in location


def test_oidc_callback_missing_code_redirects():
    """GET /auth/oidc/callback with no code redirects with error."""
    with patch.object(auth.settings, "FRONTEND_URL", "http://localhost:3000"):
        r = client.get("/auth/oidc/callback?state=invalid", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers.get("Location", "")
    assert "error=invalid_callback" in location


def test_validate_oidc_discovery_rejects_issuer_mismatch():
    with patch.object(auth.settings, "OIDC_ISSUER_URL", "https://issuer.example.com"):
        with pytest.raises(HTTPException) as ex:
            auth._validate_oidc_discovery(
                {
                    "issuer": "https://other.example.com",
                    "authorization_endpoint": "https://issuer.example.com/auth",
                    "token_endpoint": "https://issuer.example.com/token",
                    "jwks_uri": "https://issuer.example.com/jwks",
                }
            )
    assert ex.value.status_code == 503
    assert ex.value.detail == "oidc_discovery_issuer_mismatch"


def test_verify_oidc_id_token_rejects_unapproved_alg():
    fake_config = {"jwks_uri": "https://idp.example.com/jwks"}
    with patch.object(auth.settings, "OIDC_ISSUER_URL", "https://idp.example.com"):
        with patch.object(auth.settings, "OIDC_CLIENT_ID", "client1"):
            with patch.object(auth.jwt, "get_unverified_header", return_value={"alg": "HS256"}):
                with pytest.raises(HTTPException) as ex:
                    auth._verify_oidc_id_token("dummy", fake_config, expected_nonce="abc")
    assert ex.value.status_code == 401
    assert ex.value.detail == "invalid_id_token_alg"


def test_verify_oidc_id_token_rejects_azp_mismatch():
    fake_config = {"jwks_uri": "https://idp.example.com/jwks"}
    fake_claims = {
        "sub": "alice",
        "nonce": "nonce-ok",
        "aud": ["client1", "another-audience"],
        "azp": "wrong-client",
    }
    with patch.object(auth.settings, "OIDC_ISSUER_URL", "https://idp.example.com"):
        with patch.object(auth.settings, "OIDC_CLIENT_ID", "client1"):
            with patch.object(auth.jwt, "get_unverified_header", return_value={"alg": "RS256"}):
                with patch.object(
                    auth,
                    "_get_oidc_jwks",
                    return_value={"keys": [{"kid": "kid1", "kty": "RSA"}]},
                ):
                    with patch.object(auth, "_select_jwk_for_token", return_value={"kid": "kid1"}):
                        with patch.object(auth.jwt, "decode", return_value=fake_claims):
                            with pytest.raises(HTTPException) as ex:
                                auth._verify_oidc_id_token(
                                    "dummy",
                                    fake_config,
                                    expected_nonce="nonce-ok",
                                )
    assert ex.value.status_code == 401
    assert ex.value.detail == "invalid_id_token_azp"


def test_oidc_callback_discovery_failure_redirects():
    valid_state = auth._sign_state("nonce-x")
    with patch.object(auth.settings, "FRONTEND_URL", "http://localhost:3000"):
        with patch.object(
            auth, "_get_oidc_config", side_effect=HTTPException(status_code=503, detail="boom")
        ):
            r = client.get(
                f"/auth/oidc/callback?code=abc&state={valid_state}",
                follow_redirects=False,
            )
    assert r.status_code == 302
    assert "error=oidc_discovery_failed" in (r.headers.get("Location", ""))
