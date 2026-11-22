import unittest
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from stage3a_url import load_urls, registrable_group


class Stage3AURLTests(unittest.TestCase):
    def test_groups_follow_public_and_private_suffix_boundaries(self):
        self.assertEqual(registrable_group("A.B.Example.co.uk."), "example.co.uk")
        self.assertEqual(registrable_group("other.EXAMPLE.co.uk"), "example.co.uk")
        self.assertEqual(registrable_group("a.city.kawasaki.jp"), "city.kawasaki.jp")
        self.assertEqual(registrable_group("a.one.github.io"), "one.github.io")
        self.assertEqual(registrable_group("two.github.io"), "two.github.io")
        self.assertEqual(registrable_group("a.site.test"), "site.test")
        self.assertEqual(registrable_group("localhost"), "localhost")
        self.assertEqual(registrable_group("127.0.0.1"), "127.0.0.1")
        self.assertEqual(registrable_group("2001:0db8:0:0:0:0:0:1"), "2001:db8::1")
        self.assertEqual(registrable_group("a.bücher.de"), "xn--bcher-kva.de")

    def test_raw_loader_normalizes_and_retains_duplicates_and_audits_rejections(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "raw_urls.csv"
            path.write_text(
                "URL,Label\n"
                " a.Example.co.uk/Path?Query=Value ,good\n"
                "http://a.example.co.uk/Path?Query=Value,bad\n"
                "https://b.example.co.uk/other,good\n"
                "https://another.co.uk/,bad\n"
                "https://bad host.example/,bad\n"
                "https://example.net/,other\n"
                ",good\n"
                "\n",
                encoding="utf-8",
            )
            rows, exclusions = load_urls(path)

        self.assertEqual(rows["row_id"].tolist(), [1, 2, 3, 4])
        self.assertEqual(rows["label"].tolist(), [0, 1, 0, 1])
        self.assertEqual(rows["url"].iloc[0], "http://a.example.co.uk/Path?Query=Value")
        self.assertEqual(rows["duplicate_key"].iloc[0], rows["duplicate_key"].iloc[1])
        self.assertEqual(rows["duplicate_key"].iloc[0], sha256(rows["url"].iloc[0].encode()).hexdigest())
        self.assertEqual(rows["group_id"].tolist(), ["example.co.uk"] * 3 + ["another.co.uk"])
        self.assertEqual(exclusions["row_id"].tolist(), [5, 6, 7, 8])
        self.assertIn("whitespace", exclusions["reason"].iloc[0])
        self.assertEqual(exclusions["reason"].iloc[1], "unsupported URL label")
        self.assertEqual(exclusions["reason"].iloc[2], "URL cannot be empty.")
        self.assertEqual(exclusions["reason"].iloc[3], "missing URL label")

    def test_prepared_loader_accepts_numeric_labels(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "urls.csv"
            path.write_text("url,label\nexample.com,0\nexample.org,1\n", encoding="utf-8")
            rows, exclusions = load_urls(path)

        self.assertEqual(rows["label"].tolist(), [0, 1])
        self.assertTrue(exclusions.empty)
