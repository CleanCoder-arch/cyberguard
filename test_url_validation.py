import unittest
from unittest.mock import patch

from cyberguard_url import analyze_url
from risk_engine import analyze_risk
from url_features import extract_features
from url_normalizer import URLValidationError, normalize_url


class TestURLValidation(unittest.TestCase):
    def test_normalization_preserves_suffix_and_user_info(self):
        self.assertEqual(
            normalize_url("HTTPS://User:PaSs@EXAMPLE.COM:00443/Case?Key=Value!#End."),
            ("https://User:PaSs@example.com:443/Case?Key=Value!#End.", True),
        )
        self.assertEqual(
            normalize_url("//localhost:8080/Case?Key=Value"),
            ("http://localhost:8080/Case?Key=Value", False),
        )

    def test_invalid_hosts_and_ports_do_not_load_models(self):
        invalid_urls = (
            None,
            "https:///example.com",
            "https://-broken.example",
            "https://example..com",
            "https://bad_host.example",
            "https://exa\nmple.com",
            "https://256.0.0.1",
            "example.com:",
            "example.com:abc",
            "https://example.com:0",
            "https://example.com:65536",
            "https://[2001:db8::1]wrong",
            "https://[2001:db8:::1]",
            "https://2001:db8::1",
            "https://[127.0.0.1]",
        )
        with patch("cyberguard_url.load_artifacts") as load_artifacts:
            for url in invalid_urls:
                with self.subTest(url=url), self.assertRaises(URLValidationError):
                    analyze_url(url)
            load_artifacts.assert_not_called()

    def test_unsupported_schemes_are_rejected(self):
        for url in ("ftp://example.com", "mailto:user@example.com", "data:text/plain,test", "javascript:1234"):
            with self.subTest(url=url), self.assertRaisesRegex(URLValidationError, "Unsupported URL scheme"):
                normalize_url(url)

    def test_bracketed_ipv6_is_preserved_and_scored_as_an_ip(self):
        self.assertEqual(
            normalize_url("[2001:DB8::1]:8080/Case"),
            ("http://[2001:db8::1]:8080/Case", False),
        )
        result = analyze_url("https://[2001:db8::1]:443/Case")
        self.assertEqual(result["url"], "https://[2001:db8::1]:443/Case")
        self.assertEqual(result["hostname"], "2001:db8::1")
        self.assertIn("URL uses an IP address instead of a normal domain.", result["reasons"])

    def test_unknown_scheme_does_not_change_existing_model_input(self):
        omitted = analyze_url("EXAMPLE.COM:8080/Case?Key=Value")
        explicit_http = analyze_url("http://example.com:8080/Case?Key=Value")

        self.assertEqual(omitted["url"], "example.com:8080/Case?Key=Value")
        self.assertEqual(omitted["scheme"], "unknown")
        self.assertFalse(omitted["explicit_scheme"])
        self.assertEqual(explicit_http["scheme"], "http")
        self.assertEqual(omitted["features"], explicit_http["features"])
        self.assertEqual(omitted["malicious_probability"], explicit_http["malicious_probability"])
        self.assertNotIn("URL does not use HTTPS.", omitted["reasons"])
        self.assertIn("URL does not use HTTPS.", explicit_http["reasons"])
        self.assertEqual(explicit_http["risk_score"] - omitted["risk_score"], 10)

    def test_embedded_scheme_does_not_describe_the_outer_url(self):
        url = "example.com/Path?next=https://example.org"
        result = analyze_risk(url, 0.0, extract_features(url))
        self.assertNotIn("URL does not use HTTPS.", result["reasons"])
        self.assertNotIn("URL uses HTTPS.", result["positive_signals"])
