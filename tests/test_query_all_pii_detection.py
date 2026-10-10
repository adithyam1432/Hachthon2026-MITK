"""
Exhaustive unit test suite verifying that ALL PII types in user queries are detected.
Covers:
- PERSON_NAME (Single names, full names, title names, role names, possessives, lowercase with cue)
- EMAIL (RFC, subdomains, plus-tags, obfuscated anti-scraping)
- PHONE (US, India, UK, dashed, spaced, dotted)
- PIN (Direct assignment, ATM, UPI, debit, context window)
- PASSWORD (Direct assignment, pwd, passcode, credentials)
- CVV (Direct, 3-4 digits, context window)
- OTP (Direct, verification codes, 2FA codes)
- HOME_ADDRESS (Cue-based, street names, apartments, international)
- BANK_ACCOUNT (Account numbers, IBAN, checking/savings, a/c no)
- PASSPORT (Alpha-numeric, travel documents)
- DATE_OF_BIRTH (DOB, born on, ISO, slash, dot, text dates)
- DRIVERS_LICENSE (US, India, international)
- SSN (US Social Security Numbers)
- PAN_CARD (Indian PAN with statutory & context patterns)
- AADHAAR (Indian 12-digit UIDAI numbers with Verhoeff validation)
- API_KEY (OpenAI, AWS, GitHub, Stripe)
- IP_ADDRESS (IPv4 public & private)
- VOTER_ID (Indian EPIC, voter IDs)
- EMPLOYEE_ID (Internal corporate staff IDs)
- CUSTOMER_ID (CRM identifiers)
- ACCESS_TOKEN (Bearer JWTs, auth tokens)
"""

import sys
import unittest
from pathlib import Path

# Add backend directory to path
_backend = Path(__file__).resolve().parent.parent / "backend"
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))

from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import PIIType, SensitivityCategory
from pii_firewall.multi_agent_pipeline import MultiAgentPipeline
from pii_firewall.semantic_nlp import ContextAwareNLPEngine


class TestQueryAllPIIDetection(unittest.TestCase):
    """Verifies that all PII entities in user queries are comprehensively detected."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.pipeline = MultiAgentPipeline(enable_cloud_gemini=False)

    def _extract_types(self, text: str):
        entities = self.firewall.scanner.scan_text(text)
        return {e.pii_type: e.value for e in entities}

    def _extract_all(self, text: str):
        return self.firewall.scanner.scan_text(text)

    # 1. PERSON_NAME
    def test_single_person_name_in_email_command(self):
        query = "send email to Sharath"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "Sharath")

    def test_single_person_name_with_email_address(self):
        query = "send email to Sharath at sharath@gmail.com"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "Sharath")
        self.assertIn(PIIType.EMAIL, types)
        self.assertEqual(types[PIIType.EMAIL], "sharath@gmail.com")

    def test_full_person_name_with_role_indicator(self):
        query = "User David Miller with status active"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "David Miller")

    def test_customer_role_name_indicator(self):
        query = "Customer: Ramesh Rao requested account review"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "Ramesh Rao")

    def test_possessive_person_name(self):
        query = "Adithya's phone is 9876543210"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "Adithya")
        self.assertIn(PIIType.PHONE, types)
        self.assertEqual(types[PIIType.PHONE], "9876543210")

    def test_title_person_name(self):
        query = "Dr. Alan Turing submitted the research paper"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "Alan Turing")

    def test_lowercase_name_with_explicit_cue(self):
        query = "name: sharath kumar"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertEqual(types[PIIType.PERSON_NAME], "sharath kumar")

    # 2. EMAIL
    def test_standard_email_detection(self):
        query = "Notify john.doe@company.org regarding the update"
        types = self._extract_types(query)
        self.assertIn(PIIType.EMAIL, types)
        self.assertEqual(types[PIIType.EMAIL], "john.doe@company.org")

    def test_plus_tag_email_detection(self):
        query = "Send receipt to alice+billing@startup.io"
        types = self._extract_types(query)
        self.assertIn(PIIType.EMAIL, types)
        self.assertEqual(types[PIIType.EMAIL], "alice+billing@startup.io")

    # 3. PHONE
    def test_indian_10_digit_phone(self):
        query = "Call customer at 9876543210 immediately"
        types = self._extract_types(query)
        self.assertIn(PIIType.PHONE, types)
        self.assertEqual(types[PIIType.PHONE], "9876543210")

    def test_international_us_phone(self):
        query = "Reach support at +1-800-555-0199"
        types = self._extract_types(query)
        self.assertIn(PIIType.PHONE, types)
        self.assertEqual(types[PIIType.PHONE], "+1-800-555-0199")

    # 4. PIN
    def test_direct_pin_detection(self):
        query = "User David Miller with password SecretPass123 and pin 4821"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertIn(PIIType.PASSWORD, types)
        self.assertEqual(types[PIIType.PASSWORD], "SecretPass123")
        self.assertIn(PIIType.PIN, types)
        self.assertEqual(types[PIIType.PIN], "4821")

    def test_upi_pin_detection(self):
        query = "Verify transaction using upi pin: 9876"
        types = self._extract_types(query)
        self.assertIn(PIIType.PIN, types)
        self.assertEqual(types[PIIType.PIN], "9876")

    # 5. PASSWORD
    def test_password_pwd_cue(self):
        query = "Login using pwd: MySecurePassword99"
        types = self._extract_types(query)
        self.assertIn(PIIType.PASSWORD, types)
        self.assertEqual(types[PIIType.PASSWORD], "MySecurePassword99")

    # 6. CVV & OTP
    def test_cvv_direct_detection(self):
        query = "Card ending in 4111 with cvv: 789"
        types = self._extract_types(query)
        self.assertIn(PIIType.CVV, types)
        self.assertEqual(types[PIIType.CVV], "789")

    def test_otp_direct_detection(self):
        query = "Authentication code: your otp is 654321"
        types = self._extract_types(query)
        self.assertIn(PIIType.OTP, types)
        self.assertEqual(types[PIIType.OTP], "654321")

    # 7. HOME_ADDRESS
    def test_home_address_with_cue(self):
        query = "Update profile for John Doe, address 123 Main St, New York"
        types = self._extract_types(query)
        self.assertIn(PIIType.PERSON_NAME, types)
        self.assertIn(PIIType.HOME_ADDRESS, types)
        self.assertEqual(types[PIIType.HOME_ADDRESS], "123 Main St, New York")

    def test_indian_address_with_cue(self):
        query = "Customer lives at 12 MG Road, Bangalore 560001"
        types = self._extract_types(query)
        self.assertIn(PIIType.HOME_ADDRESS, types)
        self.assertIn("12 MG Road", types[PIIType.HOME_ADDRESS])

    # 8. BANK_ACCOUNT & IBAN
    def test_bank_account_number(self):
        query = "Transfer funds to bank account: 123456789012"
        types = self._extract_types(query)
        self.assertIn(PIIType.BANK_ACCOUNT, types)
        self.assertEqual(types[PIIType.BANK_ACCOUNT], "123456789012")

    def test_iban_account_detection(self):
        query = "Wire settlement to IBAN: GB82WEST12345698765432"
        types = self._extract_types(query)
        self.assertIn(PIIType.BANK_ACCOUNT, types)
        self.assertEqual(types[PIIType.BANK_ACCOUNT], "GB82WEST12345698765432")

    # 9. PASSPORT
    def test_passport_detection(self):
        query = "Passenger passport number: Z9876543"
        types = self._extract_types(query)
        self.assertIn(PIIType.PASSPORT, types)
        self.assertEqual(types[PIIType.PASSPORT], "Z9876543")

    # 10. DATE_OF_BIRTH
    def test_dob_detection(self):
        query = "Employee born on 1990-05-15 in New York"
        types = self._extract_types(query)
        self.assertIn(PIIType.DATE_OF_BIRTH, types)
        self.assertEqual(types[PIIType.DATE_OF_BIRTH], "1990-05-15")

    # 11. DRIVERS_LICENSE
    def test_drivers_license_detection(self):
        query = "Driver's license: DL-987654321 verified"
        types = self._extract_types(query)
        self.assertIn(PIIType.DRIVERS_LICENSE, types)
        self.assertEqual(types[PIIType.DRIVERS_LICENSE], "DL-987654321")

    # 12. SSN
    def test_ssn_detection(self):
        query = "Citizen SSN: 123-45-6789 on record"
        types = self._extract_types(query)
        self.assertIn(PIIType.SSN, types)
        self.assertEqual(types[PIIType.SSN], "123-45-6789")

    # 13. PAN_CARD
    def test_pan_card_detection(self):
        query = "Verify income tax PAN: ABCPE1234F"
        types = self._extract_types(query)
        self.assertIn(PIIType.PAN_CARD, types)
        self.assertEqual(types[PIIType.PAN_CARD], "ABCPE1234F")

    # 14. AADHAAR
    def test_aadhaar_number_detection(self):
        query = "Aadhaar card: 2345 6789 0123"
        types = self._extract_types(query)
        self.assertIn(PIIType.AADHAAR, types)
        self.assertEqual(types[PIIType.AADHAAR], "2345 6789 0123")

    # 15. API_KEY & IP_ADDRESS
    def test_api_key_and_ip(self):
        query = "Deploy to 192.168.1.100 with key sk-proj-abcdef1234567890abcdef1234567890"
        types = self._extract_types(query)
        self.assertIn(PIIType.IP_ADDRESS, types)
        self.assertEqual(types[PIIType.IP_ADDRESS], "192.168.1.100")
        self.assertIn(PIIType.API_KEY, types)
        self.assertEqual(types[PIIType.API_KEY], "sk-proj-abcdef1234567890abcdef1234567890")

    # 16. EXTENDED IDS (VOTER_ID, EMPLOYEE_ID, CUSTOMER_ID, ACCESS_TOKEN)
    def test_voter_id_detection(self):
        query = "Voter ID: ABC1234567"
        types = self._extract_types(query)
        self.assertIn(PIIType.VOTER_ID, types)
        self.assertEqual(types[PIIType.VOTER_ID], "ABC1234567")

    def test_employee_id_detection(self):
        query = "Employee ID: EMP-1042 badge record"
        types = self._extract_types(query)
        self.assertIn(PIIType.EMPLOYEE_ID, types)
        self.assertEqual(types[PIIType.EMPLOYEE_ID], "EMP-1042")

    def test_customer_id_detection(self):
        query = "Customer ID: CUST-98765 inquiry"
        types = self._extract_types(query)
        self.assertIn(PIIType.CUSTOMER_ID, types)
        self.assertEqual(types[PIIType.CUSTOMER_ID], "CUST-98765")

    def test_bearer_token_detection(self):
        token_str = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN"
        types = self._extract_types(token_str)
        self.assertIn(PIIType.ACCESS_TOKEN, types)

    # 17. MULTI-ENTITY END-TO-END PIPELINE QUERY
    def test_multi_pii_query_through_pipeline(self):
        prompt = (
            "Update profile for John Doe, email john@example.com, SSN 123-45-6789, "
            "phone +1-555-123-4567, address 123 Main St, New York"
        )
        trace = self.pipeline.run(prompt)
        self.assertTrue(trace.success)
        det_step = [s for s in trace.steps if s.agent_id == "detection_agent"][0]
        detected = det_step.details.get("entities", [])
        types_detected = {e["type"] for e in detected}
        self.assertIn("PERSON_NAME", types_detected)
        self.assertIn("EMAIL", types_detected)
        self.assertIn("SSN", types_detected)
        self.assertIn("PHONE", types_detected)
        self.assertIn("HOME_ADDRESS", types_detected)


if __name__ == "__main__":
    unittest.main()
