"""Tests for the FastAPI JWKS server."""

from __future__ import annotations

import base64

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.main import app


def decode_base64url_uint(value: str) -> int:
    """Decode a base64url integer used by RSA JWK values."""
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


def test_auth_returns_token_signed_with_valid_key():
    with TestClient(app) as client:
        response = client.post("/auth")

    assert response.status_code == 200
    token = response.json()["token"]
    headers = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert headers["kid"].isdigit()
    assert payload == {"username": "userABC"}


def test_auth_expired_uses_expired_key():
    with TestClient(app) as client:
        expired_response = client.post("/auth?expired=true")
        valid_response = client.post("/auth")

    assert expired_response.status_code == 200
    assert valid_response.status_code == 200

    expired_kid = jwt.get_unverified_header(expired_response.json()["token"])["kid"]
    valid_kid = jwt.get_unverified_header(valid_response.json()["token"])["kid"]

    assert expired_kid.isdigit()
    assert valid_kid.isdigit()
    assert expired_kid != valid_kid


def test_jwks_returns_only_non_expired_keys():
    with TestClient(app) as client:
        jwks_response = client.get("/.well-known/jwks.json")
        valid_token_response = client.post("/auth")
        expired_token_response = client.post("/auth?expired=true")

    assert jwks_response.status_code == 200
    data = jwks_response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    valid_kid = jwt.get_unverified_header(valid_token_response.json()["token"])["kid"]
    expired_kid = jwt.get_unverified_header(expired_token_response.json()["token"])["kid"]
    jwk = next(key for key in data["keys"] if key["kid"] == valid_kid)

    assert all(key["kid"] != expired_kid for key in data["keys"])
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"

    public_numbers = rsa.RSAPublicNumbers(
        e=decode_base64url_uint(jwk["e"]),
        n=decode_base64url_uint(jwk["n"]),
    )
    public_key = public_numbers.public_key()
    payload = jwt.decode(
        valid_token_response.json()["token"],
        key=public_key,
        algorithms=["RS256"],
    )

    assert payload == {"username": "userABC"}
