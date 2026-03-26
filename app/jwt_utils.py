"""JWT creation helpers."""

from __future__ import annotations

import jwt

from app.jwks import pem_to_private_key


def create_jwt(private_key_pem: str, kid: str) -> str:
    """Sign and return a JWT using RS256 with the supplied key id."""
    private_key = pem_to_private_key(private_key_pem)
    payload = {"username": "userABC"}

    return jwt.encode(
        payload=payload,
        key=private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )
