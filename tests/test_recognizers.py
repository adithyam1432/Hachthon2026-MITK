"""
Unit tests for individual PII recognizers.
"""

import unittest
from pii_firewall.models import PIIType
from pii_firewall.recognizers.email import EmailRecognizer
from pii_firewall.recognizers.phone import PhoneRecognizer
from pii_firewall.recognizers.ssn import SSNRecognizer
from pii_firewall.recognizers.credit_card import CreditCardRecognizer, luhn_checksum_valid


class TestPIIRecognizers(unittest.TestCase):

    def setUp(self):
        self.email_rec = EmailRecognizer()
        self.phone_rec = PhoneRecognizer()
        self.ssn_rec = SSNRecognizer()
        self.card_rec = CreditCardRecognizer()

    def test_email_recognition(self):
        text = "Contact alex.demo@example.test or support@corp.internal for help."
        entities = self.email_rec.find_entities(text)
        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[0].value, "alex.demo@example.test")
        self.assertEqual(entities[1].value, "support@corp.internal")

    def test_email_with_punctuation(self):
        text = "Reach out to user.name+tag@sub.domain.co.in."
        entities = self.email_rec.find_entities(text)
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "user.name+tag@sub.domain.co.in")

    def test_phone_recognition(self):
        test_cases = [
            "Call me at +1-555-123-4567 tomorrow.",
            "My direct line is (555) 234-5678.",
            "International office: +91 98765 43210.",
            "Plain dashed: 555-345-6789.",
        ]
        for tc in test_cases:
            entities = self.phone_rec.find_entities(tc)
            self.assertGreaterEqual(len(entities), 1, f"Failed to detect phone in '{tc}'")

    def test_phone_ignores_dates_and_short_numbers(self):
        text = "Event happened on 2026-10-09 at 3 PM with order 12345."
        entities = self.phone_rec.find_entities(text)
        self.assertEqual(len(entities), 0)

    def test_ssn_valid_and_invalid(self):
        valid_ssn = "His synthetic SSN is 123-45-6789 for testing."
        entities = self.ssn_rec.find_entities(valid_ssn)
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "123-45-6789")

        # Invalid SSA area codes: 000, 666, 900+
        invalid_ssns = "Invalid numbers: 000-12-3456, 666-45-6789, 923-45-6789, 123-00-6789, 123-45-0000"
        bad_entities = self.ssn_rec.find_entities(invalid_ssns)
        self.assertEqual(len(bad_entities), 0)

    def test_credit_card_luhn_validation(self):
        # Valid Luhn test card (canonical synthetic test Visa)
        valid_visa = "4111-1111-1111-1111"
        self.assertTrue(luhn_checksum_valid(valid_visa))

        entities = self.card_rec.find_entities(f"Charged to {valid_visa} successfully.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, valid_visa)

        # Invalid Luhn checksum (arbitrary 16 digit order number)
        fake_num = "4111-1111-1111-1112"
        self.assertFalse(luhn_checksum_valid(fake_num))
        no_entities = self.card_rec.find_entities(f"Order #{fake_num}")
        self.assertEqual(len(no_entities), 0)


if __name__ == "__main__":
    unittest.main()
