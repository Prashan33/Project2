"""SQLite helpers for the JWKS server."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from app.jwks import generate_rsa_private_key

DEFAULT_DB_NAME = "totally_not_my_privateKeys.db"
SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection for the provided database path."""
    connection = sqlite3.connect(str(db_path), check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(db_path: str | Path) -> None:
    """Create the database schema and ensure expired and valid keys exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    connection = get_connection(db_path)
    try:
        cursor = connection.cursor()
        cursor.execute(SCHEMA)

        now = int(time.time())
        expired_count = cursor.execute(
            "SELECT COUNT(*) AS count FROM keys WHERE exp < ?",
            (now,),
        ).fetchone()["count"]
        valid_count = cursor.execute(
            "SELECT COUNT(*) AS count FROM keys WHERE exp > ?",
            (now,),
        ).fetchone()["count"]

        if expired_count == 0:
            insert_key(cursor, exp=now - 3600)

        if valid_count == 0:
            insert_key(cursor, exp=now + 3600)

        connection.commit()
    finally:
        connection.close()


def seed_keys(cursor: sqlite3.Cursor) -> None:
    """Insert one expired RSA private key and one valid RSA private key."""
    now = int(time.time())
    insert_key(cursor, exp=now - 3600)
    insert_key(cursor, exp=now + 3600)


def insert_key(cursor: sqlite3.Cursor, exp: int) -> None:
    """Insert a PEM-encoded RSA private key with the supplied expiration."""
    private_key = generate_rsa_private_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    cursor.execute(
        "INSERT INTO keys(key, exp) VALUES(?, ?)",
        (private_key_pem, exp),
    )


def get_signing_key(db_path: str | Path, use_expired: bool) -> sqlite3.Row:
    """Fetch a single signing key row based on expiration status."""
    now = int(time.time())
    query = """
        SELECT kid, key, exp
        FROM keys
        WHERE exp < ?
    """ if use_expired else """
        SELECT kid, key, exp
        FROM keys
        WHERE exp > ?
    """

    connection = get_connection(db_path)
    try:
        row = connection.execute(query + " ORDER BY exp DESC LIMIT 1", (now,)).fetchone()
    finally:
        connection.close()

    if row is None:
        status = "expired" if use_expired else "valid"
        raise ValueError(f"No {status} signing key found in the database.")

    return row


def get_non_expired_keys(db_path: str | Path) -> list[sqlite3.Row]:
    """Return all non-expired key rows for JWKS publishing."""
    now = int(time.time())
    connection = get_connection(db_path)
    try:
        rows = connection.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp > ?
            ORDER BY kid ASC
            """,
            (now,),
        ).fetchall()
    finally:
        connection.close()
    return rows
