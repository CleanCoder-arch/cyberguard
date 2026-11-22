import csv
import tempfile
import unittest
from pathlib import Path

from stage3a_sms import load_sms, sms_group_ids


class TestStage3aSms(unittest.TestCase):
    def test_load_sms_keeps_duplicate_rows_and_audits_invalid_records(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw_sms.csv"
            with source.open("w", encoding="latin-1", newline="") as handle:
                csv.writer(handle).writerows([
                    ("v1", "v2", "unused"),
                    ("ham", " café\nreservation ", ""),
                    ("spam", "café\nreservation", ""),
                    ("spam", "  ", ""),
                    ("unexpected", "Other text", ""),
                    ("", "Missing label", ""),
                    (),
                ])

            rows, excluded = load_sms(source)

        self.assertEqual(rows["text"].tolist(), ["café\nreservation"] * 2)
        self.assertEqual(rows["label"].tolist(), [0, 1])
        self.assertEqual(rows["row_id"].tolist(), [1, 2])
        self.assertEqual(rows["duplicate_key"].nunique(), 1)
        self.assertEqual(rows["group_id"].nunique(), 1)
        self.assertEqual(
            excluded.to_dict("records"),
            [
                {"row_id": 3, "reason": "empty_text"},
                {"row_id": 4, "reason": "invalid_label"},
                {"row_id": 5, "reason": "missing_label"},
                {"row_id": 6, "reason": "missing_label;empty_text"},
            ],
        )

    def test_normalized_slot_values_and_small_wording_changes_stay_together(self):
        messages = [
            "Your confirmation reference is A1C995. View the receipt at example.com/store.",
            "YOUR CONFIRMATION REFERENCE IS 991023! VIEW THE RECEIPT AT https://other.example/receipt",
            "Your confirmation number is 882031. View the receipt at https://example.org/checkout now.",
            "Can you pick up groceries after you get off work?",
            "Contact us on (212) 555-0100 or billing@example.com.",
            "Contact us on +1 (415) 555-0108 or help@example.org.",
        ]

        groups = sms_group_ids(messages)

        self.assertEqual(len(set(groups[:3])), 1)
        self.assertEqual(groups[4], groups[5])
        self.assertEqual(len(set(groups)), 3)
        self.assertEqual(sms_group_ids(reversed(messages)), list(reversed(groups)))

    def test_near_duplicate_links_form_transitive_groups(self):
        first = "Your order is ready to collect at the delivery desk on Monday."
        middle = "Your order is ready to collect at the delivery desk on Tuesday."
        last = "Your order is ready to collect at the front desk on Tuesday."

        self.assertEqual(len(set(sms_group_ids([first, last]))), 2)
        self.assertEqual(len(set(sms_group_ids([first, middle, last]))), 1)


if __name__ == "__main__":
    unittest.main()
