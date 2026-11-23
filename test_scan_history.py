import csv
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import date, datetime, timedelta, timezone

from scan_history import HISTORY_COLUMNS, ScanHistory


def test_qr_records_are_metadata_only_and_date_and_type_filters_are_inclusive(tmp_path):
    database = tmp_path / "scan_history.sqlite3"
    history = ScanHistory(database)
    day = datetime(2026, 11, 23, tzinfo=timezone.utc)
    history.record("QR", "completed", risk_level="LOW", latency_ms=125.5,
                   feed_freshness="fresh", timestamp=day)
    history.record("SMS", "incomplete", latency_ms=240, feed_freshness="stale", timestamp=day)
    history.record("QR", "failed", latency_ms=5, timestamp=day + timedelta(days=1))

    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
    assert columns == {"id", *HISTORY_COLUMNS}

    assert len(history.read(start_date=day.date(), end_date=day.date())) == 2
    assert history.read(end_date=date(2026, 11, 22)) == []
    assert history.read(input_type="QR", start_date=day.date(), end_date=day.date()) == [{
        "timestamp": "2026-11-23T00:00:00.000000+00:00",
        "input_type": "QR",
        "scan_status": "completed",
        "risk_level": "LOW",
        "latency_ms": 125.5,
        "feed_freshness": "fresh",
    }]
    assert history.read(input_type="SMS")[0]["risk_level"] is None


def test_csv_import_preserves_source_duplicates_different_scans_and_is_repeatable(tmp_path):
    path = tmp_path / "scan_history.csv"
    with path.open("w", encoding="utf-8", newline="") as source:
        writer = csv.writer(source)
        writer.writerow(["timestamp", "type", "input", "ml_prediction", "risk_score", "risk_level"])
        writer.writerows([
            ["2026-11-23 12:00:00", "URL", "fixture-only-url", "LEGITIMATE", "0", "LOW"],
            ["2026-11-23 12:00:00", "URL", "fixture-only-url-two", "LEGITIMATE", "0", "LOW"],
            ["bad date", "SMS", "message", "LEGITIMATE", "0", "LOW"],
        ])
    original = path.read_bytes()
    copied_path = tmp_path / "copied_history.csv"
    copied_path.write_bytes(original)
    database = tmp_path / "history.sqlite3"
    history = ScanHistory(database)
    legacy_zone = timezone(timedelta(hours=5, minutes=30))

    assert history.import_legacy_csv(path, legacy_timezone=legacy_zone) == 2
    assert history.import_legacy_csv(path, legacy_timezone=legacy_zone) == 0
    assert history.import_legacy_csv(copied_path, legacy_timezone=legacy_zone) == 0
    assert len(history.read()) == 2
    assert history.read()[0] == {
        "timestamp": "2026-11-23T06:30:00.000000+00:00",
        "input_type": "URL",
        "scan_status": "completed",
        "risk_level": "LOW",
        "latency_ms": None,
        "feed_freshness": None,
    }
    assert b"fixture-only-url" not in database.read_bytes()
    assert path.read_bytes() == original

    history.clear()
    assert history.import_legacy_csv(path, legacy_timezone=legacy_zone) == 0
    assert history.read() == []


def test_parallel_writers_keep_every_scan(tmp_path):
    path = tmp_path / "scan_history.sqlite3"

    def record(latency):
        ScanHistory(path).record("URL", "completed", risk_level="HIGH", latency_ms=latency)

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(record, range(30)))

    assert sorted(row["latency_ms"] for row in ScanHistory(path).read()) == list(range(30))


def test_clearing_history_removes_feedback_and_rejects_stale_scan(tmp_path):
    path = tmp_path / "scan_history.sqlite3"
    history = ScanHistory(path)
    day = datetime(2026, 11, 23, tzinfo=timezone.utc)
    original = history.record("URL", "completed", risk_level="LOW", timestamp=day)
    assert history.record_feedback(*original, "yes", timestamp=day)

    history.clear()
    replacement = history.record("SMS", "completed", risk_level="HIGH", timestamp=day + timedelta(days=1))
    assert replacement[0] == original[0]
    assert not history.record_feedback(*original, "no")

    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT * FROM scan_feedback").fetchall() == []
