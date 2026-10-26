import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


DB_PATH = Path(os.getenv("NEOCARE_AUTH_DB", Path(__file__).with_name("neocare_auth.sqlite3")))
PBKDF2_ROUNDS = 480_000
SESSION_SECONDS = 12 * 60 * 60
FIREBASE_AUTH_PATH = "neocare_system/auth"
_firebase_database = None


def _firebase_ref(path):
    if _firebase_database is None:
        raise RuntimeError("Firebase auth storage has not been initialized.")
    return _firebase_database.reference(f"{FIREBASE_AUTH_PATH}/{path}")


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize(firebase_database=None):
    global _firebase_database
    _firebase_database = firebase_database
    if os.getenv("NEOCARE_AUTH_STORAGE") == "firebase":
        if _firebase_database is None:
            raise RuntimeError(
                "Firebase auth storage was selected, but Firebase is not initialized."
            )
        return

    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS parents (
                parent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                phone TEXT NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                user_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_state (
                child_id TEXT PRIMARY KEY,
                severity INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                child_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                child_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                email_status TEXT NOT NULL
            );
            """
        )


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS
    )
    return salt, digest


def create_parent(parent_id, name, email, phone, password):
    salt, digest = hash_password(password)
    if _firebase_database is not None:
        email_key = hashlib.sha256(email.lower().encode("utf-8")).hexdigest()
        email_index = _firebase_ref(f"parent_email_index/{email_key}")
        claimed_parent_id = email_index.transaction(
            lambda current: parent_id if current is None else current
        )
        if claimed_parent_id != parent_id:
            raise sqlite3.IntegrityError("Parent email already exists.")
        try:
            _firebase_ref(f"parents/{parent_id}").set(
                {
                    "parent_id": parent_id,
                    "name": name,
                    "email": email,
                    "phone": phone,
                    "password_salt": salt.hex(),
                    "password_hash": digest.hex(),
                    "created_at": int(time.time()),
                }
            )
        except Exception:
            email_index.transaction(
                lambda current: None if current == parent_id else current
            )
            raise
        return

    with connect() as db:
        db.execute(
            """
            INSERT INTO parents(parent_id, name, email, phone, password_salt, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (parent_id, name, email, phone, salt, digest, int(time.time())),
        )


def authenticate_parent(email, password):
    if _firebase_database is not None:
        email_key = hashlib.sha256(email.lower().encode("utf-8")).hexdigest()
        parent_id = _firebase_ref(f"parent_email_index/{email_key}").get()
        row = _firebase_parent_by_id(parent_id) if parent_id else None
        if row is None:
            hash_password(password, b"\0" * 16)
            return None
        salt = bytes.fromhex(row["password_salt"])
        stored_hash = bytes.fromhex(row["password_hash"])
        _, candidate = hash_password(password, salt)
        if not hmac.compare_digest(candidate, stored_hash):
            return None
        return {
            "role": "parent",
            "user_id": row["parent_id"],
            "display_name": row["name"],
            "email": row["email"],
        }

    with connect() as db:
        row = db.execute(
            "SELECT * FROM parents WHERE email = ?", (email,)
        ).fetchone()
    if row is None:
        hash_password(password, b"\0" * 16)
        return None
    _, candidate = hash_password(password, row["password_salt"])
    if not hmac.compare_digest(candidate, row["password_hash"]):
        return None
    return {
        "role": "parent",
        "user_id": row["parent_id"],
        "display_name": row["name"],
        "email": row["email"],
    }


def parent_by_id(parent_id):
    if _firebase_database is not None:
        row = _firebase_parent_by_id(parent_id)
        if row is None:
            return None
        return {
            key: row[key]
            for key in ("parent_id", "name", "email", "phone")
            if key in row
        }

    with connect() as db:
        row = db.execute(
            "SELECT parent_id, name, email, phone FROM parents WHERE parent_id = ?",
            (parent_id,),
        ).fetchone()
    return dict(row) if row else None


def _firebase_parent_by_id(parent_id):
    row = _firebase_ref(f"parents/{parent_id}").get()
    return row if isinstance(row, dict) else None


def parent_by_email(email):
    if _firebase_database is not None:
        email_key = hashlib.sha256(email.lower().encode("utf-8")).hexdigest()
        parent_id = _firebase_ref(f"parent_email_index/{email_key}").get()
        if not parent_id:
            return None
        return parent_by_id(parent_id)

    with connect() as db:
        row = db.execute(
            "SELECT parent_id, name, email, phone FROM parents WHERE email = ?",
            (email,),
        ).fetchone()
    return dict(row) if row else None


def create_session(role, user_id, display_name):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = int(time.time()) + SESSION_SECONDS
    if _firebase_database is not None:
        _firebase_ref(f"sessions/{token_hash}").set(
            {
                "role": role,
                "user_id": user_id,
                "display_name": display_name,
                "expires_at": expires_at,
            }
        )
        return token

    with connect() as db:
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
        db.execute(
            "INSERT INTO sessions(token_hash, role, user_id, display_name, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                token_hash,
                role,
                user_id,
                display_name,
                expires_at,
            ),
        )
    return token


def get_session(token):
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if _firebase_database is not None:
        row = _firebase_ref(f"sessions/{token_hash}").get()
        if not isinstance(row, dict):
            return None
        if row.get("expires_at", 0) <= int(time.time()):
            _firebase_ref(f"sessions/{token_hash}").delete()
            return None
        return row

    with connect() as db:
        row = db.execute(
            "SELECT role, user_id, display_name, expires_at FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] <= int(time.time()):
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            return None
    return dict(row)


def delete_session(token):
    if not token:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if _firebase_database is not None:
        _firebase_ref(f"sessions/{token_hash}").delete()
        return

    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def save_alert_severity(child_id, severity):
    if _firebase_database is not None:
        _firebase_ref(f"alert_state/{child_id}").set(
            {"severity": severity, "updated_at": int(time.time())}
        )
        return

    with connect() as db:
        db.execute(
            """
            INSERT INTO alert_state(child_id, severity, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(child_id) DO UPDATE SET severity=excluded.severity, updated_at=excluded.updated_at
            """,
            (child_id, severity, int(time.time())),
        )


def get_alert_severity(child_id):
    if _firebase_database is not None:
        row = _firebase_ref(f"alert_state/{child_id}").get()
        return row.get("severity", 0) if isinstance(row, dict) else 0

    with connect() as db:
        row = db.execute(
            "SELECT severity FROM alert_state WHERE child_id = ?", (child_id,)
        ).fetchone()
    return row["severity"] if row else 0


def add_alert(child_id, parent_id, child_name, severity, subject, message, email_status):
    created_at = int(time.time())
    if _firebase_database is not None:
        alert_ref = _firebase_ref("alerts").push()
        alert_id = alert_ref.key
        alert_ref.set(
            {
                "child_id": child_id,
                "parent_id": parent_id,
                "child_name": child_name,
                "severity": severity,
                "subject": subject,
                "message": message,
                "created_at": created_at,
                "email_status": email_status,
            }
        )
        return alert_id

    with connect() as db:
        cursor = db.execute(
            """
            INSERT INTO alerts(child_id, parent_id, child_name, severity, subject, message, created_at, email_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                child_id,
                parent_id,
                child_name,
                severity,
                subject,
                message,
                created_at,
                email_status,
            ),
        )
        return cursor.lastrowid


def list_alerts(role, user_id, limit=100):
    if _firebase_database is not None:
        records = _firebase_ref("alerts").get() or {}
        alerts = [
            {"alert_id": alert_id, **alert}
            for alert_id, alert in records.items()
            if isinstance(alert, dict)
            and (role != "parent" or alert.get("parent_id") == user_id)
        ]
        alerts.sort(key=lambda alert: alert.get("created_at", 0), reverse=True)
        return alerts[:limit]

    query = (
        "SELECT alert_id, child_id, parent_id, child_name, severity, subject, "
        "message, created_at, email_status FROM alerts "
    )
    parameters = []
    if role == "parent":
        query += "WHERE parent_id = ? "
        parameters.append(user_id)
    query += "ORDER BY created_at DESC LIMIT ?"
    parameters.append(limit)
    with connect() as db:
        rows = db.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def get_thresholds():
    if _firebase_database is not None:
        value = _firebase_ref("settings/alert_thresholds").get()
        return value if isinstance(value, dict) else None

    with connect() as db:
        row = db.execute(
            "SELECT value FROM settings WHERE key = 'alert_thresholds'"
        ).fetchone()
    return json.loads(row["value"]) if row else None


def save_thresholds(value):
    if _firebase_database is not None:
        _firebase_ref("settings/alert_thresholds").set(value)
        return

    with connect() as db:
        db.execute(
            "INSERT INTO settings(key, value) VALUES ('alert_thresholds', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(value),),
        )
