import unittest

from sms_risk_engine import analyze_message_risk
from sms_url_extractor import extract_urls


class TestSmsLinkExtraction(unittest.TestCase):
    def test_email_addresses_do_not_add_a_link_signal(self):
        message = (
            'Contact first.last+tag@www.example.com, '
            '"Ada Lovelace"@mail.example.org, or mailto:person@team.example.net.'
        )

        self.assertEqual(extract_urls(message), [])
        result = analyze_message_risk(message, 0.05)
        self.assertEqual(result["detected_urls"], [])
        self.assertEqual(result["risk_score"], 0)

    def test_case_and_order_of_url_suffixes_are_preserved(self):
        message = (
            "Example.com:8443?Ref=ABC https://EXAMPLE.com/Report?Token=X "
            "HTTPS://example.COM/Report?Token=X https://example.com/report?Token=X "
            "https://example.com/Report?Token=x example.com/Report?Token=X"
        )
        expected = [
            "Example.com:8443?Ref=ABC",
            "https://EXAMPLE.com/Report?Token=X",
            "https://example.com/report?Token=X",
            "https://example.com/Report?Token=x",
            "example.com/Report?Token=X",
        ]

        self.assertEqual(extract_urls(message), expected)
        self.assertEqual(analyze_message_risk(message, 0.05)["detected_urls"], expected)

    def test_ipv6_and_explicit_malformed_candidates_are_retained(self):
        message = (
            "See (https://[2001:db8::1]:443/Path_(A)) or "
            "[2001:DB8::2]:8443?Ref=B. "
            "ftp://example.com/Case https://example.org:bad https://example.net]"
        )

        self.assertEqual(
            extract_urls(message),
            [
                "https://[2001:db8::1]:443/Path_(A)",
                "[2001:DB8::2]:8443?Ref=B",
                "ftp://example.com/Case",
                "https://example.org:bad",
                "https://example.net]",
            ],
        )

    def test_delimited_urls_retain_query_punctuation(self):
        message = '<example.org?Ending=ABC,> "https://example.com?Ending=DEF."'

        self.assertEqual(
            extract_urls(message),
            ["example.org?Ending=ABC,", "https://example.com?Ending=DEF."],
        )


class TestSmsKeywordBoundaries(unittest.TestCase):
    def test_keyword_substrings_do_not_raise_the_score(self):
        result = analyze_message_risk(
            "I know shipping for the accountant is free. "
            "The repayment arrived for the claimant.",
            0.05,
        )

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["reasons"], [])

    def test_keywords_and_phrases_match_at_punctuation_and_line_breaks(self):
        result = analyze_message_risk(
            "Final warning: verify your bank\naccount and enter your PIN now!",
            0.05,
        )

        self.assertEqual(result["risk_score"], 48)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertTrue(any("bank account" in reason for reason in result["reasons"]))


if __name__ == "__main__":
    unittest.main()
