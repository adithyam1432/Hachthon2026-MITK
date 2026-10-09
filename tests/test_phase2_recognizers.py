"""
Tests for Phase II Extended Recognizers:
IP Addresses, API Keys & Secrets, Indian PAN, and Aadhaar (Verhoeff).
"""

import unittest
from pii_firewall.models import PIIType
from pii_firewall.recognizers.ip_address import IPAddressRecognizer
from pii_firewall.recognizers.api_key import APIKeyRecognizer
from pii_firewall.recognizers.indian_pii import PANRecognizer, AadhaarRecognizer, verhoeff_validate


class TestPhase2Recognizers(unittest.TestCase):

    def setUp(self):
        self.ip_rec = IPAddressRecognizer()
        self.key_rec = APIKeyRecognizer()
        self.pan_rec = PANRecognizer()
        self.aadhaar_rec = AadhaarRecognizer()

    def test_ip_address_detection(self):
        text = "Server connection from 192.168.1.100 and public gateway 203.0.113.195."
        entities = self.ip_rec.find_entities(text)
        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[0].value, "192.168.1.100")
        self.assertEqual(entities[1].value, "203.0.113.195")

    def test_api_keys_detection(self):
        text = (
            "OpenAI key sk-proj-abcdef1234567890abcdef1234567890123456 and "
            "AWS AKIAIOSFODNN7EXAMPLE used."
        )
        entities = self.key_rec.find_entities(text)
        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[0].pii_type, PIIType.API_KEY)
        self.assertEqual(entities[1].value, "AKIAIOSFODNN7EXAMPLE")

    def test_indian_pan_card(self):
        # Valid PAN format: 5 letters (4th is P for individual), 4 digits, 1 letter
        valid_pan = "ABCPE1234F"
        entities = self.pan_rec.find_entities(f"Taxpayer PAN is {valid_pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, valid_pan)

        # Invalid PAN format
        bad_pan = "12345ABCDE"
        self.assertEqual(len(self.pan_rec.find_entities(bad_pan)), 0)

    def test_aadhaar_with_verhoeff_checksum(self):
        # Valid synthetic Verhoeff Aadhaar: 3675 9834 6016
        digits = "367598346016"
        self.assertTrue(verhoeff_validate(digits))

        entities = self.aadhaar_rec.find_entities("UIDAI Number: 3675 9834 6016.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "3675 9834 6016")

        # Invalid Verhoeff checksum (tampered last digit)
        invalid_digits = "367598346019"
        self.assertFalse(verhoeff_validate(invalid_digits))
        no_entities = self.aadhaar_rec.find_entities("UIDAI Number: 3675 9834 6019.")
        self.assertEqual(len(no_entities), 0)


if __name__ == "__main__":
    unittest.main()
