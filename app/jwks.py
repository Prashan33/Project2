"""RSA key generation and JWKS conversion helpers."""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    """Generate a new RSA private key for RS256 signing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def normalize_private_key_pem(private_key_pem: str | bytes) -> bytes:
    """Normalize PEM data loaded from SQLite TEXT/BLOB columns."""
    if isinstance(private_key_pem, bytes):
        return private_key_pem
    return private_key_pem.encode("utf-8")


def pem_to_private_key(private_key_pem: str | bytes) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM data stored as text or bytes."""
    return serialization.load_pem_private_key(
        normalize_private_key_pem(private_key_pem),
        password=None,
    )


def base64url_uint(value: int) -> str:
    """Encode an RSA integer as base64url without padding."""
    byte_length = max(1, (value.bit_length() + 7) // 8)
    raw_bytes = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("utf-8")


def private_key_to_jwk(private_key_pem: str | bytes, kid: str) -> dict[str, Any]:
    """Convert a PEM private key into a public JWKS entry."""
    private_key = pem_to_private_key(private_key_pem)
    public_numbers = private_key.public_key().public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": base64url_uint(public_numbers.n),
        "e": base64url_uint(public_numbers.e),
    }
