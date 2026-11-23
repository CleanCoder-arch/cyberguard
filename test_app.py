import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import streamlit as st
from streamlit.testing.v1 import AppTest

from cyberguard import analyze_input as analyze_with_detectors
from phishing_feed import FEED_URL, REQUEST_TIMEOUT, PhishingFeedCache
from scan_history import ScanHistory
from sms_ocr import SMSOCRError
from url_normalizer import URLValidationError


APP_PATH = Path(__file__).with_name("app.py").resolve()
QR_FIXTURES = APP_PATH.parent / "tests" / "fixtures" / "qr"
HISTORY_PATH = Path("data/scan_history.sqlite3")
URL_RESULT = {
    "url": "https://example.com",
    "hostname": "example.com",
    "risk_score": 10,
    "risk_level": "LOW",
    "recommendation": "Verify the destination before proceeding.",
    "ml_prediction": "LEGITIMATE",
    "malicious_probability": 0.1,
    "reasons": [],
    "positive_signals": [],
}
EXPLAINED_URL_RESULT = {
    **URL_RESULT,
    "ml_prediction": "MALICIOUS",
    "malicious_probability": 0.525,
    "model_explanation": {
        "scale": "log_odds",
        "positive_class": "MALICIOUS",
        "baseline": -0.4,
        "positive": [
            {"feature": "url_length", "kind": "url_structure", "contribution": 0.7, "value": 19}
        ],
        "negative": [{"feature": "example", "kind": "url_tfidf", "contribution": -0.2}],
        "other_contribution": 0.0,
        "total": 0.1,
    },
    "score_breakdown": {
        "starting_score": 0,
        "adjustments": [
            {"rule": "Model probability", "delta": 15},
            {"rule": "HTTPS scheme", "delta": -5},
        ],
        "final_score": 10,
    },
    "checks": [{"check": "URL analysis", "status": "completed"}],
}
SMS_RESULT = {
    "sms_result": {
        "risk_score": 10,
        "risk_level": "LOW",
        "ml_prediction": "LEGITIMATE",
        "phishing_probability": 0.1,
        "reasons": [],
        "positive_signals": [],
    },
    "combined_risk": {
        "risk_score": 10,
        "risk_level": "LOW",
        "recommendation": "Verify unfamiliar requests.",
        "suspicious_url_count": 0,
        "base_score": 10,
        "multi_url_bonus": 0,
    },
    "detected_urls": [],
    "url_results": [],
}
FEED_MATCH = {
    "provider": "Phishunt",
    "status": "fresh",
    "matched": True,
    "refreshed_at": "2026-11-22T06:00:00+00:00",
}


class TestScannerApp(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(temp.name)

        analysis = patch("cyberguard.analyze_input", return_value=URL_RESULT)
        self.analyze_input = analysis.start()
        self.addCleanup(analysis.stop)

        self.app = AppTest.from_file(str(APP_PATH), default_timeout=15).run()
        self.assertFalse(self.app.exception)
        self.assertEqual(self.app.session_state["active_page"], "Scanner")

    def select_page(self, page):
        key = "cyberguard_brand" if page == "Dashboard" else f"nav_{page.lower()}"
        self.app.button(key=key).click().run()
        self.assertFalse(self.app.exception)

    def select_mode(self, mode):
        self.app.radio(key="scanner_mode").set_value(mode).run()
        self.assertFalse(self.app.exception)

    def scan_url(self, url):
        self.app.text_input[0].set_value(url)
        self.click_scanner_button("Analyze URL")

    def click_scanner_button(self, label):
        next(button for button in self.app.main.button if button.label == label).click().run()

    def upload_qr(self, filename):
        mime_type = "image/jpeg" if filename.endswith(".jpg") else "image/png"
        image = (QR_FIXTURES / filename).read_bytes()
        self.app.file_uploader[0].set_value((filename, image, mime_type)).run()

    def select_qr_with_offline_feed(self):
        self.analyze_input.side_effect = analyze_with_detectors
        fetch = Mock(return_value=b"https://EXAMPLE.COM\n")
        feed = PhishingFeedCache(
            Path("data/feed-fixture.sqlite3"),
            fetch=fetch,
            clock=lambda: datetime(2026, 11, 23, 6, tzinfo=timezone.utc),
        )
        feed.refresh_if_due()
        fetch.assert_called_once_with(FEED_URL, timeout=REQUEST_TIMEOUT)
        fetch.reset_mock()
        cache_patch = patch("cyberguard.get_feed_cache", return_value=feed)
        cache_patch.start()
        self.addCleanup(cache_patch.stop)
        self.select_mode("QR Image")
        return fetch

    def assert_report_visible(self, visible):
        self.assertFalse(self.app.exception)
        labels = [button.label for button in self.app.download_button]
        self.assertEqual(labels, ["Download summary"] if visible else [])

    def assert_feedback_visible(self, visible):
        labels = [button.label for button in self.app.main.button if button.label in {"Yes", "No"}]
        self.assertEqual(labels, ["Yes", "No"] if visible else [])
        prompt_visible = any("Was this result helpful?" in element.value for element in self.app.markdown)
        self.assertEqual(prompt_visible, visible)

    def report_html(self):
        return "\n".join(item.proto.body for item in self.app.get("html"))

    def seed_history(self):
        history = ScanHistory(HISTORY_PATH)
        for day, scan_type, status, risk, latency, freshness in (
            (22, "URL", "completed", "LOW", 20, "fresh"),
            (22, "SMS", "incomplete", None, 80, "stale"),
            (23, "SMS", "completed", "HIGH", 140, "unavailable"),
            (23, "QR", "failed", None, 40, None),
            (23, "QR", "completed", "MEDIUM", 60, "fresh"),
        ):
            history.record(
                scan_type, status, risk_level=risk, latency_ms=latency, feed_freshness=freshness,
                timestamp=datetime(2026, 11, day, 12, tzinfo=timezone.utc),
            )

    def test_dashboard_counts_and_filters_match_saved_metadata(self):
        self.seed_history()
        self.select_page("History")
        self.assertEqual(self.app.session_state["active_page"], "History")
        self.assertEqual(len(self.app.dataframe[0].value), 5)

        self.select_page("Dashboard")
        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics, {
            "Total scans": "5", "Completed": "3", "Incomplete": "1", "Failed": "1",
        })

        self.app.date_input[0].set_value(date(2026, 11, 22))
        self.app.date_input[1].set_value(date(2026, 11, 22))
        self.app.selectbox[0].set_value("SMS").run()
        self.assertFalse(self.app.exception)
        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics, {
            "Total scans": "1", "Completed": "0", "Incomplete": "1", "Failed": "0",
        })
        table = self.app.dataframe[0].value
        self.assertEqual(table["input_type"].tolist(), ["SMS"])
        self.assertEqual(table["feed_freshness"].tolist(), ["Stale"])

        self.app.selectbox[0].set_value("QR").run()
        self.assertFalse(self.app.exception)
        self.assertIn("No scans match these filters.", self.app.info[0].value)

    def test_dashboard_shortcuts_open_each_scanner(self):
        for label, mode in (
            ("Scan a URL", "URL"), ("Scan an SMS", "SMS"), ("Scan a QR image", "QR Image"),
        ):
            with self.subTest(mode=mode):
                self.select_page("Dashboard")
                next(button for button in self.app.button if button.label == label).click().run()
                self.assertFalse(self.app.exception)
                self.assertEqual(self.app.session_state["active_page"], "Scanner")
                self.assertEqual(self.app.radio(key="scanner_mode").value, mode)

    def test_analytics_shows_verdict_latency_and_feed_counts_when_benchmark_missing(self):
        self.seed_history()
        with patch("benchmark_results.load_stage3b_benchmark", return_value=None):
            self.select_page("Analytics")

        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics["Incomplete"], "1")
        self.assertEqual(metrics["Median latency"], "60.0 ms")
        self.assertEqual(metrics["95th percentile latency"], "128.0 ms")
        self.assertEqual(metrics["Measured scans"], "5")
        verdicts = self.app.dataframe[0].value.set_index("Input type")
        self.assertEqual(verdicts.loc["URL", "LOW"], 1)
        self.assertEqual(verdicts.loc["SMS", "HIGH"], 1)
        self.assertEqual(verdicts.loc["QR", "MEDIUM"], 1)
        freshness = self.app.dataframe[1].value.set_index("Cache state")["Scans"].to_dict()
        self.assertEqual(freshness, {"Fresh": 2, "Stale": 1, "Unavailable": 1, "Unrecorded": 1})
        self.assertIn("Locked Stage 3B benchmark results are missing", self.app.info[0].value)

    def test_input_type_edits_and_navigation_clear_completed_report(self):
        self.assert_report_visible(False)
        self.scan_url("https://example.com")
        self.assert_report_visible(True)
        self.assertEqual(ScanHistory(HISTORY_PATH).read()[0]["input_type"], "URL")
        self.analyze_input.assert_called_once_with("URL", "https://example.com")

        self.app.text_input[0].set_value("https://example.org").run()
        self.assert_report_visible(False)
        self.analyze_input.assert_called_once()

        self.scan_url("https://example.org")
        self.assert_report_visible(True)
        self.select_mode("SMS")
        self.assert_report_visible(False)
        self.select_mode("URL")
        self.assert_report_visible(False)

        self.scan_url("https://example.com")
        self.assert_report_visible(True)
        self.select_page("Analytics")
        self.assert_report_visible(False)
        self.select_page("Scanner")
        self.assert_report_visible(False)

    def test_repeated_feedback_clicks_replace_only_the_current_scan_response(self):
        url = "https://example.com"
        self.assert_feedback_visible(False)
        self.scan_url(url)
        self.assert_feedback_visible(True)
        report = self.report_html()

        with closing(sqlite3.connect(HISTORY_PATH)) as database:
            (scan_id,), = database.execute("SELECT id FROM scans")
            self.assertEqual(database.execute("SELECT * FROM scan_feedback").fetchall(), [])
            for label in ("Yes", "Yes", "No"):
                with self.subTest(label=label):
                    self.click_scanner_button(label)
                    self.assert_report_visible(True)
                    (saved_id, response, timestamp), = database.execute(
                        "SELECT scan_id, response, timestamp FROM scan_feedback"
                    )
                    self.assertEqual((saved_id, response), (scan_id, label.lower()))
                    self.assertEqual(datetime.fromisoformat(timestamp).tzinfo, timezone.utc)

            self.assertEqual(self.report_html(), report)
            self.analyze_input.assert_called_once_with("URL", url)
            self.assertEqual(database.execute("SELECT id FROM scans").fetchall(), [(scan_id,)])

            self.click_scanner_button("Analyze URL")
            self.assert_feedback_visible(True)
            (new_scan_id,), = database.execute("SELECT id FROM scans WHERE id != ?", (scan_id,))
            self.assertEqual(
                database.execute("SELECT scan_id, response FROM scan_feedback").fetchall(), [(scan_id, "no")]
            )
            self.click_scanner_button("Yes")
            self.assertEqual(
                database.execute("SELECT scan_id, response FROM scan_feedback ORDER BY scan_id").fetchall(),
                [(scan_id, "no"), (new_scan_id, "yes")],
            )
            self.assertEqual(self.analyze_input.call_count, 2)

    def test_url_sample_loads_input_and_report_controls_follow_analysis(self):
        self.analyze_input.return_value = EXPLAINED_URL_RESULT
        self.scan_url("https://example.com")
        self.assert_report_visible(True)
        self.assertNotIn("Sample report", self.report_html())
        self.analyze_input.reset_mock()

        self.click_scanner_button("Load a sample")

        self.assertEqual(self.app.text_input[0].value, "https://example.com")
        self.assert_report_visible(False)
        self.assertNotIn("Sample report", self.report_html())
        self.analyze_input.assert_not_called()

        self.click_scanner_button("Analyze URL")

        self.analyze_input.assert_called_once_with("URL", "https://example.com")
        self.assert_report_visible(True)
        report = self.report_html()
        self.assertIn("Low overall risk", report)
        self.assertIn("Sample report", report)
        self.assertIn("Recommended action", report)
        self.assertIn(EXPLAINED_URL_RESULT["recommendation"], report)
        evidence, = [section for section in self.app.expander if section.label == "Why this result?"]
        self.assertFalse(evidence.proto.expanded)
        self.assertTrue(evidence.get("dataframe"))
        self.assertFalse(evidence.get("download_button"))

        self.click_scanner_button("Load a sample")
        self.assert_report_visible(False)
        self.analyze_input.assert_called_once()

        self.scan_url("https://example.org")
        self.assert_report_visible(True)
        self.assertNotIn("Sample report", self.report_html())

    def test_sms_sample_waits_for_analysis(self):
        self.analyze_input.return_value = SMS_RESULT
        self.select_mode("SMS")
        self.click_scanner_button("Load a sample")

        message = "Reminder: our meeting starts at 10 tomorrow."
        self.assertEqual(self.app.text_area[0].value, message)
        self.assert_report_visible(False)
        self.analyze_input.assert_not_called()

        self.click_scanner_button("Analyze Message")

        self.analyze_input.assert_called_once_with("SMS", message)
        self.assert_report_visible(True)

    def test_sms_screenshot_prefills_editable_text_without_saving_payload(self):
        self.analyze_input.return_value = SMS_RESULT
        self.select_mode("SMS")
        filename = "private-screenshot.png"
        screenshot = (QR_FIXTURES / "url.png").read_bytes()
        extracted = "Recognized private code 701293."
        corrected = "Corrected private code 701294."

        with patch("sms_ocr.extract_sms_text", return_value=extracted) as ocr:
            uploader, = self.app.file_uploader
            self.assertEqual(uploader.label, "Upload screenshot")
            uploader.set_value((filename, screenshot, "image/png")).run()
            self.assertEqual(self.app.text_area[0].value, extracted)
            self.assert_report_visible(False)
            self.analyze_input.assert_not_called()
            self.assertFalse(HISTORY_PATH.exists())

            self.app.text_area[0].set_value(corrected).run()
            self.app.run()
            self.assertEqual(self.app.text_area[0].value, corrected)
            self.analyze_input.assert_not_called()

            with patch("streamlit.download_button", wraps=st.download_button) as download:
                self.click_scanner_button("Analyze Message")

            ocr.assert_called_once_with(screenshot)

        self.analyze_input.assert_called_once_with("SMS", corrected)
        self.assert_report_visible(True)
        record, = ScanHistory(HISTORY_PATH).read()
        self.assertEqual((record["input_type"], record["scan_status"]), ("SMS", "completed"))
        database = HISTORY_PATH.read_bytes()
        download.assert_called_once()
        summary = download.call_args.kwargs["data"].encode()
        for payload in (filename.encode(), screenshot, extracted.encode(), corrected.encode()):
            self.assertNotIn(payload, database)
            self.assertNotIn(payload, summary)

    def test_sms_screenshot_ocr_errors_preserve_manual_entry(self):
        self.analyze_input.return_value = SMS_RESULT
        self.select_mode("SMS")
        message = "Text entered manually."
        self.app.text_area[0].set_value(message).run()
        screenshot = (QR_FIXTURES / "text.jpg").read_bytes()

        for filename, notice in (
            ("unavailable.jpg", "Local OCR is unavailable."),
            ("blank.jpg", "No text was found in the screenshot."),
        ):
            with self.subTest(notice=notice), patch(
                "sms_ocr.extract_sms_text", side_effect=SMSOCRError(notice),
            ) as ocr:
                self.app.file_uploader[0].set_value((filename, screenshot, "image/jpeg")).run()
                self.assertEqual(self.app.text_area[0].value, message)
                self.assertIn(
                    f"{notice} You can still type or paste the SMS.", [item.value for item in self.app.warning]
                )
                self.assert_report_visible(False)
                self.analyze_input.assert_not_called()
                ocr.assert_called_once_with(screenshot)

        self.click_scanner_button("Analyze Message")
        self.analyze_input.assert_called_once_with("SMS", message)
        self.assert_report_visible(True)

    def test_qr_sample_is_decoded_and_upload_replaces_sample(self):
        self.select_mode("QR Image")
        self.click_scanner_button("Load a sample")

        self.assert_report_visible(False)
        self.analyze_input.assert_not_called()

        self.click_scanner_button("Analyze QR Image")

        self.analyze_input.assert_called_once_with("URL", "https://example.com")
        self.assert_report_visible(True)
        self.assertIn("Decoded URL: https://example.com", [item.value for item in self.app.text])
        record, = ScanHistory(HISTORY_PATH).read()
        self.assertEqual((record["input_type"], record["scan_status"]), ("QR", "completed"))

        self.click_scanner_button("Load a sample")
        self.assert_report_visible(False)
        self.analyze_input.assert_called_once()

        self.upload_qr("unreadable.png")
        self.click_scanner_button("Analyze QR Image")

        self.assert_report_visible(False)
        self.assertIn("could not be read", self.app.error[0].value)
        self.analyze_input.assert_called_once()

    def test_partial_sms_shows_completed_checks_without_overall_verdict(self):
        failed_url = "https://example.org"
        self.analyze_input.return_value = {
            "sms_result": {
                "risk_score": 40,
                "risk_level": "MEDIUM",
                "ml_prediction": "PHISHING/SPAM",
                "phishing_probability": 0.4,
                "reasons": ["SMS check found a warning sign."],
                "positive_signals": [],
            },
            "detected_urls": [URL_RESULT["url"], failed_url],
            "url_results": [
                {
                    **EXPLAINED_URL_RESULT,
                    "phishing_feed": {**FEED_MATCH, "status": "stale", "matched": False},
                },
                {
                    "url": failed_url,
                    "error": "Link check failed.",
                    "phishing_feed": {**FEED_MATCH, "status": "stale"},
                },
            ],
            "combined_risk": None,
            "checks": [
                {"check": "Link extraction", "status": "completed"},
                {"check": "SMS analysis", "status": "completed"},
                {"check": "URL analysis", "status": "completed", "url": URL_RESULT["url"]},
                {"check": "URL analysis", "status": "failed", "url": failed_url},
                {"check": "Overall risk", "status": "skipped"},
            ],
        }
        self.select_mode("SMS")
        self.app.text_area[0].set_value(
            "Meeting at https://example.com or https://example.org"
        )
        self.click_scanner_button("Analyze Message")

        self.assert_report_visible(True)
        self.assert_feedback_visible(False)
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["SMS Risk Score"], "40/100")
        self.assertEqual(metrics["URL Risk"], "10/100")
        self.assertNotIn("Overall Risk", metrics)
        self.assertNotIn("Combined Risk", metrics)
        self.assertIn(
            "Analysis incomplete. An overall verdict is unavailable.",
            [item.value for item in self.app.warning],
        )
        self.assertIn("Unable to analyze this URL", [item.value for item in self.app.error])
        self.assertIn(
            "Phishunt phishing feed · Exact match found",
            [item.value for item in self.app.warning],
        )
        captions = [item.value for item in self.app.caption]
        self.assertIn("Phishunt phishing feed · No exact match", captions)
        self.assertIn(f"Stale cache · Last successful refresh {FEED_MATCH['refreshed_at']}", captions)
        checks = [item.value for item in self.app.text]
        self.assertIn(failed_url, checks)
        self.assertIn("Link check failed.", checks)
        self.assertIn("Completed · Link extraction", checks)
        self.assertIn("Completed · SMS analysis", checks)
        self.assertIn(f"Completed · URL analysis · {URL_RESULT['url']}", checks)
        self.assertIn(f"Failed · URL analysis · {failed_url}", checks)
        self.assertIn("Skipped · Overall risk", checks)
        self.assertIn("+15 points · Model probability", checks)
        self.assertEqual(self.app.dataframe[0].value["Type"].tolist(), ["URL structure", "URL text"])
        record, = ScanHistory(HISTORY_PATH).read()
        self.assertEqual((record["input_type"], record["scan_status"], record["risk_level"]), (
            "SMS", "incomplete", None,
        ))

    def test_url_report_explains_model_flag_and_low_risk(self):
        self.analyze_input.return_value = EXPLAINED_URL_RESULT
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        self.assertIn("Model signal", self.report_html())
        self.assertIn("Flagged · 52.50%", self.report_html())
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["Overall Risk"], "LOW")
        self.assertEqual(metrics["ML Malicious Probability"], "52.50%")
        self.assertIn("**Prediction:** MALICIOUS", [item.value for item in self.app.markdown])
        self.assertTrue(
            any("rules total 10/100. MEDIUM risk starts at 30." in item.value for item in self.app.caption)
        )
        contributions = self.app.dataframe[0].value
        self.assertEqual(contributions["Feature"].tolist(), ["url_length", "example"])
        self.assertEqual(contributions["Contribution"].tolist(), ["+0.700", "-0.200"])
        self.assertEqual(contributions["Input value"].iloc[0], "19")
        report = [item.value for item in self.app.text]
        self.assertIn("Starting score 0/100", report)
        self.assertIn("+15 points · Model probability", report)
        self.assertIn("-5 points · HTTPS scheme", report)
        self.assertIn("Final score 10/100", report)

    def test_feed_states_are_visible_alongside_url_verdict(self):
        self.analyze_input.return_value = {**EXPLAINED_URL_RESULT, "phishing_feed": FEED_MATCH}
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        self.assertIn("Threat feed", self.report_html())
        self.assertIn("Exact match found · Fresh cache", self.report_html())
        self.assertIn(
            "Phishunt phishing feed · Exact match found",
            [item.value for item in self.app.warning],
        )
        self.assertIn(
            f"Fresh cache · Last successful refresh {FEED_MATCH['refreshed_at']}",
            [item.value for item in self.app.caption],
        )
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["Risk Score"], "10/100")
        self.assertEqual(metrics["Overall Risk"], "LOW")

        self.analyze_input.return_value = {
            **EXPLAINED_URL_RESULT,
            "phishing_feed": {
                **FEED_MATCH,
                "status": "unavailable",
                "matched": None,
                "refreshed_at": None,
            },
        }
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        self.assertIn("Cache unavailable", self.report_html())
        self.assertIn(
            "Phishunt phishing feed · Cache unavailable",
            [item.value for item in self.app.info],
        )
        self.assertIn("No successful refresh yet", [item.value for item in self.app.caption])
        self.assertEqual({metric.label: metric.value for metric in self.app.metric}, metrics)

    def test_verdict_remains_visible_when_contributions_are_unavailable(self):
        self.analyze_input.return_value = {
            **EXPLAINED_URL_RESULT,
            "model_explanation": {"status": "unavailable"},
        }
        self.scan_url("https://example.com")

        self.assert_report_visible(True)
        metrics = {metric.label: metric.value for metric in self.app.metric}
        self.assertEqual(metrics["Overall Risk"], "LOW")
        self.assertIn(
            "Feature contributions are unavailable for this model.",
            [item.value for item in self.app.caption],
        )

    def test_failed_url_rescan_clears_existing_report(self):
        self.scan_url("https://example.com")
        self.assert_report_visible(True)

        self.analyze_input.side_effect = RuntimeError("URL check failed.")
        self.click_scanner_button("Analyze URL")

        self.assert_report_visible(False)
        self.assert_feedback_visible(False)
        self.assertTrue(self.app.error)

    def test_url_report_displays_unknown_scheme_and_validation_error(self):
        self.analyze_input.return_value = {**URL_RESULT, "scheme": "unknown"}
        self.scan_url("example.com")
        self.assert_report_visible(True)
        self.assertTrue(
            any("**Scheme:** unknown" in item.value for item in self.app.markdown)
        )

        self.analyze_input.side_effect = URLValidationError("Invalid URL: invalid port")
        self.scan_url("https://example.com:70000/")
        self.assert_report_visible(False)
        self.assertEqual(
            [item.value for item in self.app.error], ["Invalid URL: invalid port"]
        )

    def test_qr_url_reuses_report_and_records_metadata_only(self):
        fetch = self.select_qr_with_offline_feed()
        self.upload_qr("url.png")
        self.click_scanner_button("Analyze QR Image")

        self.assert_report_visible(True)
        self.analyze_input.assert_called_once_with("URL", "https://example.com")
        self.assertIn(
            "QR image decoded locally as a web URL.", [item.value for item in self.app.caption]
        )
        self.assertIn(
            "Phishunt phishing feed · Exact match found", [item.value for item in self.app.warning]
        )
        metrics = {item.label: item.value for item in self.app.metric}
        self.assertEqual(metrics["Risk Score"], "10/100")
        self.assertIn("path_len", self.app.dataframe[0].value["Feature"].tolist())
        self.assertIn("Decoded URL: https://example.com", [item.value for item in self.app.text])
        self.assertTrue(any(item.value.startswith("+10 points") for item in self.app.text))
        record, = ScanHistory(HISTORY_PATH).read()
        self.assertEqual(
            (record["input_type"], record["scan_status"], record["risk_level"], record["feed_freshness"]),
            ("QR", "completed", "LOW", "fresh"),
        )
        self.assertGreaterEqual(record["latency_ms"], 0)
        database = HISTORY_PATH.read_bytes()
        self.assertNotIn(b"https://example.com", database)
        self.assertNotIn((QR_FIXTURES / "url.png").read_bytes(), database)
        fetch.assert_not_called()

    def test_qr_text_reuses_sms_and_link_reports_and_stores_no_payload(self):
        self.scan_url("https://example.org/previous")
        self.analyze_input.reset_mock()
        fetch = self.select_qr_with_offline_feed()
        self.upload_qr("text.jpg")
        self.click_scanner_button("Analyze QR Image")

        self.assert_report_visible(True)
        self.analyze_input.assert_called_once_with("SMS", "Meeting details: https://example.com/Agenda")
        captions = [item.value for item in self.app.caption]
        self.assertIn("QR image decoded locally as a text message.", captions)
        self.assertIn("Phishunt phishing feed · No exact match", captions)
        self.assertIn("https://example.com/Agenda", [item.value for item in self.app.text])
        self.assertFalse(any("https://example.com/Agenda" in item.value for item in self.app.markdown))
        self.assertTrue(any(item.label == "Combined Risk" for item in self.app.metric))
        self.assertGreaterEqual(len(self.app.dataframe), 2)
        qr, previous = ScanHistory(HISTORY_PATH).read()
        self.assertEqual((qr["input_type"], previous["input_type"]), ("QR", "URL"))
        self.assertNotIn(b"Meeting details: https://example.com/Agenda", HISTORY_PATH.read_bytes())
        fetch.assert_not_called()

    def test_invalid_qr_uploads_clear_previous_report_and_do_not_start_scan(self):
        self.select_mode("QR Image")
        self.upload_qr("url.png")
        self.click_scanner_button("Analyze QR Image")
        self.assert_report_visible(True)
        self.analyze_input.reset_mock()

        for filename, description in (
            ("unreadable.png", "could not be read"),
            ("multiple.png", "multiple QR codes"),
            ("unsupported.png", "Wi-Fi credentials are unsupported"),
            ("payment.png", "Payment links are unsupported"),
        ):
            with self.subTest(filename=filename):
                self.upload_qr(filename)
                self.assert_report_visible(False)
                self.click_scanner_button("Analyze QR Image")
                self.assert_report_visible(False)
                self.assertIn(description, self.app.error[0].value)
                self.assertNotIn("fixture-only", self.app.error[0].value)
        self.analyze_input.assert_not_called()
        scans = ScanHistory(HISTORY_PATH).read()
        self.assertEqual([row["scan_status"] for row in scans], ["failed"] * 4 + ["completed"])
        self.assertTrue(all(row["input_type"] == "QR" for row in scans))


if __name__ == "__main__":
    unittest.main()
