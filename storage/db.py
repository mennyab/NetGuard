"""שכבת אחסון SQLite.

הערה: פרטי גישה (סיסמאות) לא נשמרים כאן לעולם.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from core.config_loader import project_path, settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    subnets      TEXT NOT NULL,
    risk_score   INTEGER
);

CREATE TABLE IF NOT EXISTS devices (
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    device_id    TEXT NOT NULL,
    ip           TEXT,
    mac          TEXT,
    hostname     TEXT,
    vendor       TEXT,
    model        TEXT,
    os           TEXT,
    device_type  TEXT,
    managed      INTEGER DEFAULT 0,
    data_json    TEXT,            -- interfaces, open ports וכו'
    PRIMARY KEY (scan_id, device_id)
);

CREATE TABLE IF NOT EXISTS links (
    scan_id   INTEGER NOT NULL REFERENCES scans(id),
    device_a  TEXT, port_a TEXT,
    device_b  TEXT, port_b TEXT,
    source    TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id),
    device_id  TEXT,
    title      TEXT,
    category   TEXT,
    severity   TEXT,
    details    TEXT,
    evidence   TEXT
);

CREATE TABLE IF NOT EXISTS mitigations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER REFERENCES scans(id),
    device_id    TEXT,
    title        TEXT,
    commands     TEXT,
    approved_by  TEXT,
    approved_at  TEXT,
    status       TEXT,
    output       TEXT,
    backup_path  TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT DEFAULT (datetime('now', 'localtime')),
    actor      TEXT,
    action     TEXT,
    target     TEXT,
    details    TEXT
);
"""


def _db_path():
    return project_path(settings()["storage"]["database_path"])


@contextmanager
def connect():
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def audit(actor: str, action: str, target: str = "", details: str = "") -> None:
    """רישום פעולה ביומן הביקורת."""
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, details) VALUES (?, ?, ?, ?)",
            (actor, action, target, details),
        )
