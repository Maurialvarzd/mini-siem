import sqlite3
from datetime import datetime
from typing import Iterable, List, Optional

from models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    src_ip TEXT,
    username TEXT,
    raw TEXT NOT NULL,
    UNIQUE(timestamp, raw)
);
CREATE INDEX IF NOT EXISTS idx_events_type_ip_time
    ON events(event_type, src_ip, timestamp);
    CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    description TEXT NOT NULL,
    UNIQUE(timestamp, rule, src_ip)
);
"""


def connect(db_path: str = "siem.db") -> sqlite3.Connection:
    """Abre la base (la crea si no existe) y asegura que la tabla esté lista."""
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    return conn


def insert_events(conn: sqlite3.Connection, events: Iterable[Event]) -> int:
    """Guarda eventos. Devuelve cuántos eran nuevos (ignora los duplicados)."""
    before = conn.total_changes
    conn.executemany(
        "INSERT OR IGNORE INTO events "
        "(timestamp, source, event_type, src_ip, username, raw) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            (e.timestamp.isoformat(), e.source, e.event_type,
             e.src_ip, e.username, e.raw)
            for e in events
        ),
    )
    conn.commit()
    return conn.total_changes - before


def fetch_events(
    conn: sqlite3.Connection, event_type: Optional[str] = None
) -> List[Event]:
    """Lee eventos de la base, opcionalmente filtrados por tipo."""
    query = ("SELECT timestamp, source, event_type, src_ip, username, raw "
             "FROM events")
    params = ()
    if event_type is not None:
        query += " WHERE event_type = ?"
        params = (event_type,)
    query += " ORDER BY timestamp"

    return [
        Event(
            timestamp=datetime.fromisoformat(row[0]),
            source=row[1],
            event_type=row[2],
            src_ip=row[3],
            username=row[4],
            raw=row[5],
        )
        for row in conn.execute(query, params)
    ]


def insert_alerts(conn: sqlite3.Connection, alerts: Iterable[Alert]) -> List[Alert]:
    
    new_alerts = []
    for alert in alerts:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO alerts "
            "(timestamp, rule, severity, src_ip, description) "
            "VALUES (?, ?, ?, ?, ?)",
            (alert.timestamp.isoformat(), alert.rule, alert.severity,
             alert.src_ip, alert.description),
        )
        if cursor.rowcount == 1:
            new_alerts.append(alert)
    conn.commit()
    return new_alerts