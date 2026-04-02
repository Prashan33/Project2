"""FastAPI entrypoint for the JWKS server."""

from __future__ import annotations

import base64
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request

from app.db import DEFAULT_DB_NAME, get_non_expired_keys, get_signing_key, initialize_database
from app.jwks import private_key_to_jwk
from app.jwt_utils import create_jwt

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / DEFAULT_DB_NAME


async def consume_mock_credentials(request: Request) -> None:
    """Best-effort parsing for JSON and Basic Auth without rejecting the request."""
    try:
        raw_body = await request.body()
    except Exception:
        raw_body = b""

    if raw_body:
        try:
            payload = json.loads(raw_body)
            if not isinstance(payload, dict):
                payload = {}
            _ = payload.get("username")
            _ = payload.get("password")
        except (TypeError, ValueError, UnicodeDecodeError):
            pass

    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        encoded_credentials = authorization[6:].strip()
        try:
            decoded = base64.b64decode(encoded_credentials).decode("utf-8")
            if ":" in decoded:
                _ = decoded.split(":", 1)
        except Exception:
            pass


def should_use_expired_key(request: Request) -> bool:
    """Parse the expired query parameter permissively."""
    raw_value = request.query_params.get("expired")
    if raw_value is None:
        return False

    normalized = raw_value.strip().lower()
    return normalized not in {"", "0", "false", "no", "off"}


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> FastAPI:
    """Create a FastAPI application bound to the provided SQLite database."""

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        initialize_database(db_path)
        yield

    app = FastAPI(title="jwks-server", lifespan=lifespan)
    app.state.db_path = str(db_path)

    @app.api_route("/auth", methods=["POST", "GET"])
    @app.api_route("/auth/", methods=["POST", "GET"])
    async def auth(request: Request):
        await consume_mock_credentials(request)
        expired = should_use_expired_key(request)

        try:
            key_row = get_signing_key(app.state.db_path, use_expired=expired)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="No key found") from exc

        if not key_row:
            raise HTTPException(status_code=500, detail="No key found")

        token = create_jwt(
            private_key_pem=key_row["key"],
            kid=str(key_row["kid"]),
            exp=int(key_row["exp"]),
        )

        return {"jwt": token, "token": token}

    @app.get("/.well-known/jwks.json")
    @app.get("/.well-known/jwks.json/")
    @app.get("/jwks")
    @app.get("/jwks/")
    def jwks() -> dict[str, list[dict[str, str]]]:
        rows = get_non_expired_keys(app.state.db_path)
        keys = [private_key_to_jwk(row["key"], str(row["kid"])) for row in rows]
        return {"keys": keys}

    return app


app = create_app()
