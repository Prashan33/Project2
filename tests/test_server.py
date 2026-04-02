"""Tests for the FastAPI JWKS server."""

from __future__ import annotations

import base64
import sqlite3
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.db import initialize_database
from app.main import app, create_app


def decode_base64url_uint(value: str) -> int:
    """Decode a base64url integer used by RSA JWK values."""
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


def test_auth_returns_token_signed_with_valid_key():
    with TestClient(app) as client:
        response = client.post("/auth")

    assert response.status_code == 200
    token = response.json()["jwt"]
    assert response.json()["token"] == token
    headers = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert headers["kid"].isdigit()
    assert payload["username"] == "userABC"
    assert isinstance(payload["exp"], int)


def test_auth_accepts_json_body():
    with TestClient(app) as client:
        response = client.post(
            "/auth",
            json={"username": "userABC", "password": "password123"},
        )

    assert response.status_code == 200
    token = response.json()["jwt"]
    headers = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert headers["kid"].isdigit()
    assert payload["username"] == "userABC"
    assert isinstance(payload["exp"], int)


def test_auth_accepts_basic_auth_header():
    credentials = base64.b64encode(b"userABC:password123").decode("utf-8")

    with TestClient(app) as client:
        response = client.post(
            "/auth",
            headers={"Authorization": f"Basic {credentials}"},
        )

    assert response.status_code == 200
    token = response.json()["jwt"]
    headers = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert headers["kid"].isdigit()
    assert payload["username"] == "userABC"
    assert isinstance(payload["exp"], int)


def test_auth_accepts_invalid_json_without_rejecting_request():
    with TestClient(app) as client:
        response = client.post(
            "/auth",
            content=b"{not-json",
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 200
    assert "jwt" in response.json()
    assert response.json()["token"] == response.json()["jwt"]


def test_auth_supports_blob_key_material():
    temp_db_path = Path("tests/blob-key-test.db")
    initialize_database(temp_db_path)
    try:
        with sqlite3.connect(temp_db_path) as connection:
            row = connection.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (int(time.time()),),
            ).fetchone()
            connection.execute(
                "UPDATE keys SET key = ? WHERE kid = ?",
                (sqlite3.Binary(row[1].encode("utf-8")), row[0]),
            )
            connection.commit()

        with TestClient(create_app(temp_db_path)) as client:
            response = client.post("/auth")

        assert response.status_code == 200
        assert "jwt" in response.json()
    finally:
        temp_db_path.unlink(missing_ok=True)


def test_auth_expired_uses_expired_key():
    with TestClient(app) as client:
        expired_response = client.post("/auth?expired=true")
        valid_response = client.post("/auth")

    assert expired_response.status_code == 200
    assert valid_response.status_code == 200

    expired_kid = jwt.get_unverified_header(expired_response.json()["jwt"])["kid"]
    valid_kid = jwt.get_unverified_header(valid_response.json()["jwt"])["kid"]

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

    valid_kid = jwt.get_unverified_header(valid_token_response.json()["jwt"])["kid"]
    expired_kid = jwt.get_unverified_header(expired_token_response.json()["jwt"])["kid"]
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
        valid_token_response.json()["jwt"],
        key=public_key,
        algorithms=["RS256"],
    )

    assert payload["username"] == "userABC"
    assert isinstance(payload["exp"], int)
