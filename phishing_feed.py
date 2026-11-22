import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from threading import Lock
from urllib.request import HTTPRedirectHandler, Request, build_opener

from url_normalizer import URLValidationError, normalize_url


PROVIDER = "Phishunt"
FEED_URL = "https://phishunt.io/feed.txt"
REFRESH_INTERVAL = timedelta(hours=1)
REQUEST_TIMEOUT = 5
MAX_FEED_BYTES = 10 * 1024 * 1024
CACHE_TIMEOUT = 1
CACHE_PATH = Path(__file__).resolve().parent / "data" / "phishing_feed.sqlite3"


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_feed(url, *, timeout):
    request = Request(url, headers={"Accept": "text/plain", "User-Agent": "CyberGuard/1.0"})
    with build_opener(_NoRedirects()).open(request, timeout=timeout) as response:
        return response.read(MAX_FEED_BYTES + 1)


def _utc_now():
    return datetime.now(timezone.utc)


def _match_key(url):
    # The normalizer preserves path and query spelling. An omitted scheme uses
    # its HTTP placeholder as the exact key, without an alternate HTTPS lookup.
    normalized, _ = normalize_url(url)
    return normalized


def _parse_feed(payload):
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError("Phishunt feed exceeds the cache size limit.")

    urls = set()
    for line in payload.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith(("http://", "https://")):
            raise ValueError("Phishunt feed contains a non-URL record.")
        try:
            key = _match_key(line)
        except URLValidationError:
            continue
        urls.add(key)

    if not urls:
        raise ValueError("Phishunt feed contains no scannable URLs.")
    return urls


@dataclass(frozen=True)
class FeedSnapshot:
    status: str = "unavailable"
    refreshed_at: datetime | None = None
    urls: frozenset[str] = frozenset()

    def metadata(self):
        return {
            "provider": PROVIDER,
            "status": self.status,
            "refreshed_at": self.refreshed_at.isoformat() if self.refreshed_at else None,
        }

    def lookup(self, url):
        result = {**self.metadata(), "matched": None}
        try:
            key = _match_key(url)
        except URLValidationError:
            result["reason"] = "invalid_url"
        else:
            if self.status != "unavailable":
                result["matched"] = key in self.urls
        return result


class PhishingFeedCache:
    """Refresh the provider snapshot independently of local URL lookups."""

    def __init__(self, path, *, fetch=_fetch_feed, clock=_utc_now):
        self.path = Path(path).resolve()
        self._fetch = fetch
        self._clock = clock
        self._last_good = None
        self._snapshot_lock = Lock()

    def _read_snapshot(self):
        uri = self.path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=CACHE_TIMEOUT)) as db:
            row = db.execute("SELECT refreshed_at, urls FROM feed_cache WHERE id = 1").fetchone()
        if row is None or row[0] is None:
            return None

        refreshed_at = datetime.fromisoformat(row[0])
        urls = json.loads(row[1])
        if refreshed_at.utcoffset() is None or not isinstance(urls, list) or not urls:
            return None
        if any(not isinstance(url, str) for url in urls):
            return None
        return refreshed_at, frozenset(urls)

    def snapshot(self):
        """Read the local snapshot without requesting the feed."""
        try:
            stored = self._read_snapshot()
        except (OSError, sqlite3.Error, TypeError, ValueError):
            stored = None

        with self._snapshot_lock:
            if stored is not None and (self._last_good is None or stored[0] >= self._last_good[0]):
                self._last_good = stored
            last_good = self._last_good

        if last_good is None:
            return FeedSnapshot()
        refreshed_at, urls = last_good
        stale = self._clock() - refreshed_at >= REFRESH_INTERVAL
        return FeedSnapshot("stale" if stale else "fresh", refreshed_at, urls)

    def _claim_refresh(self, attempted_at):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=CACHE_TIMEOUT)) as db, db:
            # The write lock makes the refresh interval apply across processes.
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """CREATE TABLE IF NOT EXISTS feed_cache (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    attempted_at TEXT NOT NULL,
                    refreshed_at TEXT,
                    urls TEXT
                )"""
            )
            row = db.execute("SELECT attempted_at FROM feed_cache WHERE id = 1").fetchone()
            if row and attempted_at - datetime.fromisoformat(row[0]) < REFRESH_INTERVAL:
                return False
            db.execute(
                """INSERT INTO feed_cache (id, attempted_at) VALUES (1, ?)
                   ON CONFLICT(id) DO UPDATE SET attempted_at = excluded.attempted_at""",
                (attempted_at.isoformat(),),
            )
        return True

    def _save_snapshot(self, urls, attempted_at):
        with closing(sqlite3.connect(self.path, timeout=CACHE_TIMEOUT)) as db, db:
            db.execute(
                """UPDATE feed_cache SET refreshed_at = ?, urls = ?
                   WHERE id = 1 AND attempted_at = ?""",
                (self._clock().isoformat(), json.dumps(sorted(urls)), attempted_at.isoformat()),
            )

    def refresh_if_due(self):
        """Fetch at most hourly, keeping the previous snapshot on failure."""
        attempted_at = self._clock()
        try:
            if not self._claim_refresh(attempted_at):
                return self.snapshot()
        except (OSError, sqlite3.Error, TypeError, ValueError):
            return self.snapshot()

        try:
            # Only the fixed provider endpoint is passed to the HTTP client.
            urls = _parse_feed(self._fetch(FEED_URL, timeout=REQUEST_TIMEOUT))
        except Exception:
            return self.snapshot()

        try:
            self._save_snapshot(urls, attempted_at)
        except (OSError, sqlite3.Error):
            pass
        return self.snapshot()


@lru_cache(maxsize=1)
def get_feed_cache():
    return PhishingFeedCache(CACHE_PATH)
