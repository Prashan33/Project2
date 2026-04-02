"""SQLite helpers for the JWKS server."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

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
DB_LOCK = threading.RLock()


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection for the provided database path."""
    connection = sqlite3.connect(
        str(db_path),
        check_same_thread=False,
        timeout=30.0,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


@contextmanager
def managed_connection(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection and always close it."""
    connection = get_connection(db_path)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database(db_path: str | Path) -> None:
    """Create the schema and guarantee both expired and valid keys exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with DB_LOCK:
        with managed_connection(db_path) as connection:
            connection.execute(SCHEMA)
            ensure_key_inventory(connection)


def ensure_key_inventory(connection: sqlite3.Connection, now: int | None = None) -> None:
    """Ensure the database always contains at least one expired and one valid key."""
    current_time = int(time.time()) if now is None else now
    expired_count = connection.execute(
        "SELECT COUNT(*) AS count FROM keys WHERE exp < ?",
        (current_time,),
    ).fetchone()["count"]
    valid_count = connection.execute(
        "SELECT COUNT(*) AS count FROM keys WHERE exp > ?",
        (current_time,),
    ).fetchone()["count"]

    if expired_count == 0:
        insert_key(connection, exp=current_time - 3600)

    if valid_count == 0:
        insert_key(connection, exp=current_time + 3600)


def seed_keys(connection: sqlite3.Connection) -> None:
    """Insert one expired RSA private key and one valid RSA private key."""
    now = int(time.time())
    insert_key(connection, exp=now - 3600)
    insert_key(connection, exp=now + 3600)


def insert_key(connection: sqlite3.Connection, exp: int) -> None:
    """Insert a PEM-encoded RSA private key with the supplied expiration."""
    private_key = generate_rsa_private_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    connection.execute(
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
        ORDER BY exp DESC
        LIMIT 1
    """ if use_expired else """
        SELECT kid, key, exp
        FROM keys
        WHERE exp > ?
        ORDER BY exp DESC
        LIMIT 1
    """

    with DB_LOCK:
        with managed_connection(db_path) as connection:
            connection.execute(SCHEMA)
            ensure_key_inventory(connection, now=now)
            row = connection.execute(query, (now,)).fetchone()

    if row is None:
        status = "expired" if use_expired else "valid"
        raise ValueError(f"No {status} signing key found in the database.")

    return row


def get_non_expired_keys(db_path: str | Path) -> list[sqlite3.Row]:
    """Return all non-expired key rows for JWKS publishing."""
    now = int(time.time())
    with DB_LOCK:
        with managed_connection(db_path) as connection:
            connection.execute(SCHEMA)
            ensure_key_inventory(connection, now=now)
            rows = connection.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY kid ASC
                """,
                (now,),
            ).fetchall()
    return rows
