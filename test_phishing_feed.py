from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest

from cyberguard import analyze_input
from cyberguard_url import analyze_url
from phishing_feed import FEED_URL, REFRESH_INTERVAL, REQUEST_TIMEOUT, PhishingFeedCache


LISTED_URL = "https://example.com/Case?Key=ABC"
FEED_FIXTURE = b"HTTPS://EXAMPLE.COM/Case?Key=ABC\r\nhttp://example.org/Case\r\n"


@pytest.fixture
def clock():
    return Mock(return_value=datetime(2026, 11, 23, 3, tzinfo=timezone.utc))


def test_fresh_cache_matches_exact_normalized_urls_offline(tmp_path, clock):
    fetch = Mock(return_value=FEED_FIXTURE)
    path = tmp_path / "feed.sqlite3"
    first = PhishingFeedCache(path, fetch=fetch, clock=clock)
    assert first.refresh_if_due().lookup(LISTED_URL) == {
        "provider": "Phishunt",
        "status": "fresh",
        "matched": True,
        "refreshed_at": clock.return_value.isoformat(),
    }

    reopened = PhishingFeedCache(path, fetch=fetch, clock=clock)
    snapshot = reopened.snapshot()
    assert snapshot.lookup("example.org/Case")["matched"] is True
    assert snapshot.lookup("https://example.org/Case")["matched"] is False
    assert snapshot.lookup("https://example.com/case?Key=ABC")["matched"] is False
    assert snapshot.lookup("https://example.com/Case?Key=abc")["matched"] is False
    assert snapshot.lookup("https://example.com/Case?key=ABC")["matched"] is False
    assert snapshot.lookup("https://example.com:70000/")["reason"] == "invalid_url"
    assert reopened.refresh_if_due() == snapshot
    fetch.assert_called_once_with(FEED_URL, timeout=REQUEST_TIMEOUT)


@pytest.mark.parametrize("failure", [TimeoutError("timed out"), b"<html>Unavailable</html>", b""])
def test_failed_refresh_keeps_stale_matches_then_recovers(tmp_path, clock, failure):
    replacement = b"https://example.org/New\n"
    fetch = Mock(side_effect=[FEED_FIXTURE, failure, replacement])
    path = tmp_path / "feed.sqlite3"
    cache = PhishingFeedCache(path, fetch=fetch, clock=clock)
    first = cache.refresh_if_due()
    clock.return_value += REFRESH_INTERVAL + timedelta(seconds=1)

    stale = cache.refresh_if_due()
    assert stale.status == "stale"
    assert stale.refreshed_at == first.refreshed_at
    assert stale.lookup(LISTED_URL)["matched"] is True
    assert stale.lookup("https://example.com/Case?Key=abc")["matched"] is False

    reopened = PhishingFeedCache(path, fetch=fetch, clock=clock)
    assert reopened.refresh_if_due() == stale
    assert fetch.call_count == 2

    clock.return_value += REFRESH_INTERVAL
    recovered = reopened.refresh_if_due()
    assert recovered.status == "fresh"
    assert recovered.refreshed_at == clock.return_value
    assert recovered.lookup(LISTED_URL)["matched"] is False
    assert recovered.lookup("https://example.org/New")["matched"] is True
    assert fetch.call_count == 3


def test_unavailable_is_distinct_from_a_miss_and_can_recover(tmp_path, clock):
    fetch = Mock(side_effect=[TimeoutError("timed out"), FEED_FIXTURE])
    cache = PhishingFeedCache(tmp_path / "feed.sqlite3", fetch=fetch, clock=clock)
    assert cache.refresh_if_due().lookup(LISTED_URL) == {
        "provider": "Phishunt",
        "status": "unavailable",
        "matched": None,
        "refreshed_at": None,
    }
    clock.return_value += REFRESH_INTERVAL
    assert cache.refresh_if_due().lookup(LISTED_URL)["matched"] is True


def test_direct_and_sms_scans_share_the_cache_without_changing_scores(tmp_path, clock):
    fetch = Mock(return_value=FEED_FIXTURE)
    cache = PhishingFeedCache(tmp_path / "feed.sqlite3", fetch=fetch, clock=clock)
    different_case = "https://example.com/Case?Key=abc"
    baseline = analyze_url(LISTED_URL)
    with patch("cyberguard.get_feed_cache", return_value=cache):
        direct = analyze_input("URL", LISTED_URL)
        sms = analyze_input("SMS", f"See {LISTED_URL} or {different_case}")

    assert direct["phishing_feed"]["matched"] is True
    assert {key: direct[key] for key in baseline} == baseline
    assert [link["phishing_feed"]["matched"] for link in sms["url_results"]] == [True, False]
    assert sms["phishing_feed"] == cache.snapshot().metadata()
    with patch("cyberguard.get_feed_cache", return_value=PhishingFeedCache(
        tmp_path / "missing.sqlite3", fetch=Mock(side_effect=TimeoutError()), clock=clock
    )):
        unavailable = analyze_input("SMS", f"See {LISTED_URL} or {different_case}")
    assert unavailable["url_results"][0]["phishing_feed"]["matched"] is None
    assert unavailable["combined_risk"] == sms["combined_risk"]
    assert unavailable["checks"] == sms["checks"]
    fetch.assert_called_once_with(FEED_URL, timeout=REQUEST_TIMEOUT)
