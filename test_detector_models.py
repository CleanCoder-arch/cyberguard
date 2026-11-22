import math
import unittest

from cyberguard_sms import analyze_sms
from cyberguard_url import analyze_url


class TestDeployedModelExplanations(unittest.TestCase):
    def assert_log_odds_match_model(self, report, probability_key):
        explanation = report["model_explanation"]
        self.assertEqual(explanation["status"], "completed")
        self.assertEqual(explanation["scale"], "log_odds")
        probability = report[probability_key]
        self.assertAlmostEqual(explanation["total"], math.log(probability / (1 - probability)))

        positive = [entry["contribution"] for entry in explanation["positive"]]
        negative = [entry["contribution"] for entry in explanation["negative"]]
        self.assertTrue(0 < len(positive) <= 3)
        self.assertTrue(0 < len(negative) <= 3)
        self.assertGreater(min(positive), 0)
        self.assertLess(max(negative), 0)
        self.assertEqual(positive, sorted(positive, reverse=True))
        self.assertEqual(negative, sorted(negative))
        self.assertAlmostEqual(
            explanation["total"],
            math.fsum([explanation["baseline"], explanation["other_contribution"], *positive, *negative]),
        )
        return explanation

    def test_url_report_explains_scaled_structural_features(self):
        report = analyze_url("https://example.com")
        explanation = self.assert_log_odds_match_model(report, "malicious_probability")
        structural_terms = [
            entry for entry in explanation["positive"] + explanation["negative"]
            if entry["kind"] == "url_structure"
        ]
        self.assertTrue(structural_terms)
        for entry in structural_terms:
            self.assertEqual(entry["value"], report["features"][entry["feature"]])

    def test_sms_report_uses_fitted_text_terms(self):
        message = "Your account is suspended. Verify immediately at https://example.com"
        report = analyze_sms(message)
        explanation = self.assert_log_odds_match_model(report, "phishing_probability")
        for entry in explanation["positive"] + explanation["negative"]:
            self.assertEqual(entry["kind"], "sms_tfidf")
            self.assertIn(entry["feature"], message.lower())
