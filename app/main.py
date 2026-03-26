"""FastAPI entrypoint for the JWKS server."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request

from app.db import DEFAULT_DB_NAME, get_non_expired_keys, get_signing_key, initialize_database
from app.jwks import private_key_to_jwk
from app.jwt_utils import create_jwt

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / DEFAULT_DB_NAME


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> FastAPI:
    """Create a FastAPI application bound to the provided SQLite database."""

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        initialize_database(db_path)
        yield

    app = FastAPI(title="jwks-server", lifespan=lifespan)
    app.state.db_path = str(db_path)

    @app.post("/auth")
    async def auth(request: Request, expired: bool = False):
        username = "userABC"

        try:
            body = await request.json()
            if isinstance(body, dict):
                username = body.get("username", "userABC")
        except Exception:
            pass

        try:
            key_row = get_signing_key(app.state.db_path, use_expired=expired)
        except Exception:
            raise HTTPException(status_code=500, detail="No key found")

        if not key_row:
            raise HTTPException(status_code=500, detail="No key found")

        token = create_jwt(
            private_key_pem=key_row["key"],
            kid=str(key_row["kid"])
        )

        _ = username
        return {"token": token}

    @app.get("/.well-known/jwks.json")
    def jwks() -> dict[str, list[dict[str, str]]]:
        rows = get_non_expired_keys(app.state.db_path)
        keys = [private_key_to_jwk(row["key"], str(row["kid"])) for row in rows]
        return {"keys": keys}

    return app


app = create_app()