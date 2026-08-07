"""
ABS VIGIL - Data layer

Two tables:
  scans     - one row per scan, any channel (url / qr / sms / email)
  entities  - the cross-channel correlation graph. Every domain or phone
              number seen in ANY scan gets upserted here. When the same
              entity resurfaces in a different channel, callers can pull
              its history and use it to reinforce (or soften) the new
              score. This is what turns three separate scanners into a
              single connected threat-intelligence platform.
"""

import sqlite3
import json
import datetime

DB_PATH = "abs_vigil_history.db"


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = _conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            channel TEXT DEFAULT 'url',
            url TEXT,
            final_score INTEGER,
            risk_level TEXT,
            confidence TEXT,
            details TEXT
        )
    """)
    # Backfill: older DBs created before the 'channel' column existed.
    c.execute("PRAGMA table_info(scans)")
    cols = [row[1] for row in c.fetchall()]
    if "channel" not in cols:
        c.execute("ALTER TABLE scans ADD COLUMN channel TEXT DEFAULT 'url'")

    c.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT,          -- 'domain' or 'phone'
            value TEXT UNIQUE,
            first_seen TEXT,
            last_seen TEXT,
            times_seen INTEGER DEFAULT 0,
            max_score INTEGER DEFAULT 0,
            worst_risk_level TEXT,
            channels TEXT DEFAULT '[]' -- JSON list, e.g. ["sms","url"]
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------
# Scans
# ---------------------------------

def save_scan(url, final_score, risk_level, confidence, details, channel="url"):
    conn = _conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (timestamp, channel, url, final_score, risk_level, confidence, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            channel,
            url,
            final_score,
            risk_level,
            confidence,
            json.dumps(details)
        )
    )
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def update_scan(scan_id, final_score, risk_level, confidence, details):
    conn = _conn()
    c = conn.cursor()
    c.execute(
        "UPDATE scans SET final_score = ?, risk_level = ?, confidence = ?, details = ? WHERE id = ?",
        (final_score, risk_level, confidence, json.dumps(details), scan_id)
    )
    conn.commit()
    conn.close()


def load_history(limit=100, channel=None):
    conn = _conn()
    c = conn.cursor()
    if channel:
        c.execute(
            "SELECT timestamp, channel, url, final_score, risk_level, confidence FROM scans "
            "WHERE channel = ? ORDER BY id DESC LIMIT ?",
            (channel, limit)
        )
    else:
        c.execute(
            "SELECT timestamp, channel, url, final_score, risk_level, confidence FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,)
        )
    rows = c.fetchall()
    conn.close()
    return rows


def clear_history():
    conn = _conn()
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    c.execute("DELETE FROM entities")
    conn.commit()
    conn.close()


# ---------------------------------
# Entity Risk Graph
# ---------------------------------

def lookup_entity(value):
    """Return prior history for a domain/phone BEFORE this scan updates it."""
    conn = _conn()
    c = conn.cursor()
    c.execute(
        "SELECT entity_type, value, first_seen, last_seen, times_seen, max_score, "
        "worst_risk_level, channels FROM entities WHERE value = ?",
        (value.lower(),)
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "entity_type": row[0],
        "value": row[1],
        "first_seen": row[2],
        "last_seen": row[3],
        "times_seen": row[4],
        "max_score": row[5],
        "worst_risk_level": row[6],
        "channels": json.loads(row[7]) if row[7] else []
    }


def upsert_entity(entity_type, value, score, risk_level, channel):
    """
    Record this sighting. Returns the PRIOR record (or None if this is the
    entity's first appearance) so the scoring engine can decide whether to
    apply a cross-channel reinforcement bonus.
    """
    if not value:
        return None
    value = value.lower()
    prior = lookup_entity(value)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = _conn()
    c = conn.cursor()

    if prior is None:
        c.execute(
            "INSERT INTO entities (entity_type, value, first_seen, last_seen, times_seen, "
            "max_score, worst_risk_level, channels) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entity_type, value, now, now, 1, score, risk_level, json.dumps([channel]))
        )
    else:
        channels = set(prior["channels"])
        channels.add(channel)
        c.execute(
            "UPDATE entities SET last_seen = ?, times_seen = ?, max_score = ?, "
            "worst_risk_level = ?, channels = ? WHERE value = ?",
            (
                now,
                prior["times_seen"] + 1,
                max(prior["max_score"], score),
                risk_level if score >= prior["max_score"] else prior["worst_risk_level"],
                json.dumps(sorted(channels)),
                value
            )
        )
    conn.commit()
    conn.close()
    return prior
