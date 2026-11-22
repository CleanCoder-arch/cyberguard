import csv
import hashlib
import json
import math
import sqlite3
from collections import Counter
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path


HISTORY_COLUMNS = (
    "timestamp", "input_type", "scan_status", "risk_level", "latency_ms", "feed_freshness"
)
INPUT_TYPES = ("URL", "SMS", "QR")
SCAN_STATUSES = ("completed", "incomplete", "failed")
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH")
FEED_STATES = ("fresh", "stale", "unavailable")

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    input_type TEXT NOT NULL CHECK (input_type IN ('URL', 'SMS', 'QR')),
    scan_status TEXT NOT NULL CHECK (scan_status IN ('completed', 'incomplete', 'failed')),
    risk_level TEXT CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    latency_ms REAL CHECK (latency_ms >= 0),
    feed_freshness TEXT CHECK (feed_freshness IN ('fresh', 'stale', 'unavailable'))
)
"""
_CREATE_IMPORTS = """
CREATE TABLE IF NOT EXISTS legacy_imports (
    metadata_hash BLOB NOT NULL,
    occurrence INTEGER NOT NULL,
    PRIMARY KEY (metadata_hash, occurrence)
)
"""
_INSERT_SCAN = """
INSERT INTO scans (timestamp, input_type, scan_status, risk_level, latency_ms, feed_freshness)
VALUES (?, ?, ?, ?, ?, ?)
"""


def _utc_timestamp(timestamp):
    if timestamp.tzinfo is None:
        raise ValueError("Scan timestamps require a time zone.")
    return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")


class ScanHistory:
    """Store only scan metadata in a local SQLite database."""

    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def _database(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute(_CREATE_SCANS)
            connection.execute(_CREATE_IMPORTS)
            connection.execute("CREATE INDEX IF NOT EXISTS scans_by_time ON scans (timestamp)")
            yield connection

    def record(
        self, input_type, scan_status, *, risk_level=None, latency_ms=None,
        feed_freshness=None, timestamp=None,
    ):
        """Add one scan using an explicit set of metadata fields."""
        if input_type not in INPUT_TYPES or scan_status not in SCAN_STATUSES:
            raise ValueError("Invalid scan input type or status.")
        if risk_level is not None and risk_level not in RISK_LEVELS:
            raise ValueError("Invalid risk level.")
        if feed_freshness is not None and feed_freshness not in FEED_STATES:
            raise ValueError("Invalid feed freshness.")
        if latency_ms is not None and (not math.isfinite(latency_ms) or latency_ms < 0):
            raise ValueError("Latency must be a nonnegative finite number.")

        recorded_at = _utc_timestamp(timestamp or datetime.now(timezone.utc))
        with self._database() as connection:
            connection.execute(_INSERT_SCAN, (
                recorded_at, input_type, scan_status, risk_level, latency_ms, feed_freshness,
            ))

    def read(self, *, start_date=None, end_date=None, input_type=None):
        """Return newest-first metadata, optionally filtered by inclusive UTC dates and type."""
        filters = []
        values = []
        if start_date is not None:
            filters.append("timestamp >= ?")
            values.append(start_date.isoformat())
        if end_date is not None:
            filters.append("timestamp <= ?")
            values.append(f"{end_date.isoformat()}T23:59:59.999999+00:00")
        if input_type is not None:
            filters.append("input_type = ?")
            values.append(input_type)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        query = f"SELECT {', '.join(HISTORY_COLUMNS)} FROM scans{where} ORDER BY timestamp DESC, id DESC"

        with self._database() as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(query, values)]

    def import_legacy_csv(self, path, *, legacy_timezone=None):
        """Import legacy metadata once. Naive legacy timestamps use the host time zone by default."""
        try:
            fixture = Path(path).open(encoding="utf-8-sig", newline="")
        except FileNotFoundError:
            return 0

        with fixture:
            reader = csv.DictReader(fixture)
            if reader.fieldnames is None:
                return 0
            if not {"timestamp", "type", "risk_level"}.issubset(reader.fieldnames):
                raise ValueError("The legacy CSV is missing scan metadata columns.")

            seen = Counter()
            records = []
            for row in reader:
                input_type = (row["type"] or "").strip().upper()
                risk_level = (row["risk_level"] or "").strip().upper()
                if input_type not in INPUT_TYPES or risk_level not in RISK_LEVELS:
                    continue
                try:
                    observed_at = datetime.fromisoformat((row["timestamp"] or "").strip())
                    if observed_at.tzinfo is None and legacy_timezone is not None:
                        observed_at = observed_at.replace(tzinfo=legacy_timezone)
                    recorded_at = _utc_timestamp(observed_at.astimezone(timezone.utc))
                except (ValueError, OverflowError, OSError):
                    continue

                # The identity uses metadata only. Occurrences retain separate scans from the same second.
                metadata = (recorded_at, input_type, "completed", risk_level, None, None)
                digest = hashlib.sha256(json.dumps(metadata).encode("utf-8")).digest()
                seen[digest] += 1
                records.append((digest, seen[digest], metadata))

        inserted = 0
        with self._database() as connection:
            for digest, occurrence, metadata in records:
                claim = connection.execute(
                    "INSERT OR IGNORE INTO legacy_imports (metadata_hash, occurrence) VALUES (?, ?)",
                    (digest, occurrence),
                )
                if claim.rowcount:
                    connection.execute(_INSERT_SCAN, metadata)
                    inserted += 1
        return inserted

    def clear(self):
        """Remove saved scans and retain migration markers for the preserved legacy CSV."""
        with self._database() as connection:
            connection.execute("DELETE FROM scans")
