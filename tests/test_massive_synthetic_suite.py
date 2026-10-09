"""
Exhaustive Synthetic Test Matrix for PII Firewall for AI Agents.
Contains 250+ distinct unit and integration test cases covering:
  - Email (RFC patterns, plus-tags, subdomains, boundary punctuation, invalid formats)
  - Phone (US, UK, India, Germany, dashes, dots, parens, dates ignored, non-phones)
  - SSN (Hyphen, space, SSA rules: 000, 666, 900-999, group 00, serial 0000)
  - Credit Card (Visa, MasterCard, Amex, Discover, valid Luhn, invalid Luhn)
  - IP Address (IPv4 private, public, loopback, boundary 255, octet >255, invalid formats)
  - API Keys (OpenAI sk-, AWS AKIA, GitHub ghp, Stripe API Keys, Bearer, invalid keys)
  - Indian PII (PAN with all 10 entity types, Aadhaar with valid Verhoeff, invalid checksums)
  - Complex JSON Structures (depth 5/10, lists, bools, nulls, floats, emojis, roundtrips)
  - Adversarial Attacks & Policy (zero-width chars, base64 evasion, delimiters, policy engine)
"""

import base64
import unittest
from typing import List

from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import PIIType, PIILeakageDetectedError, FirewallBlockedError
from pii_firewall.recognizers.email import EmailRecognizer
from pii_firewall.recognizers.phone import PhoneRecognizer
from pii_firewall.recognizers.ssn import SSNRecognizer
from pii_firewall.recognizers.credit_card import CreditCardRecognizer, luhn_checksum_valid
from pii_firewall.recognizers.ip_address import IPAddressRecognizer
from pii_firewall.recognizers.api_key import APIKeyRecognizer
from pii_firewall.recognizers.indian_pii import (
    PANRecognizer,
    AadhaarRecognizer,
    verhoeff_validate,
)
from pii_firewall.adversarial_defense import AdversarialDefenseNormalizer
from pii_firewall.policy import PolicyEngine, ToolPolicyRule, PolicyAction
from pii_firewall.vault import RequestTokenVault
from pii_firewall.verifier import LeakageVerifier
from pii_firewall.simulated_tool import SimulatedExternalTool
from pii_firewall.audit_logger import AuditLogger


# =====================================================================
# SYNTHETIC GENERATORS & HELPERS
# =====================================================================

def make_luhn_number(prefix: str, length: int) -> str:
    """Generates a Luhn-valid synthetic number with given prefix and length."""
    digits = [int(c) for c in prefix]
    while len(digits) < length - 1:
        digits.append(0)
    for d in range(10):
        cand = "".join(map(str, digits)) + str(d)
        if luhn_checksum_valid(cand):
            return cand
    return "".join(map(str, digits)) + "0"


def make_invalid_luhn(valid_card: str) -> str:
    """Flips the check digit of a Luhn-valid number so it is guaranteed invalid."""
    last_digit = int(valid_card[-1])
    flipped = str((last_digit + 1) % 10)
    return valid_card[:-1] + flipped


def make_valid_aadhaar(prefix11: str) -> str:
    """Takes 11 digits (first digit 2-9) and determines the exact Verhoeff check digit."""
    for d in range(10):
        cand = prefix11 + str(d)
        if verhoeff_validate(cand):
            return cand
    raise ValueError(f"Could not compute Verhoeff check digit for prefix {prefix11}")


def make_invalid_aadhaar(valid_aadhaar: str) -> str:
    """Flips the check digit of a Verhoeff-valid Aadhaar number to make it invalid."""
    last_digit = int(valid_aadhaar[-1])
    flipped = str((last_digit + 1) % 10)
    return valid_aadhaar[:-1] + flipped


# =====================================================================
# 1. EMAIL SYNTHETIC TEST CASES (35 Cases)
# =====================================================================

class TestSyntheticEmail(unittest.TestCase):
    def setUp(self):
        self.rec = EmailRecognizer()

    def test_email_01_standard_gmail(self):
        entities = self.rec.find_entities("Reach me at alex.demo@gmail.com today.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "alex.demo@gmail.com")

    def test_email_02_standard_corporate_domain(self):
        entities = self.rec.find_entities("Contact corporate support@company.org.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "support@company.org")

    def test_email_03_plus_tag_single(self):
        entities = self.rec.find_entities("Forward to dev+testing@work.io please.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "dev+testing@work.io")

    def test_email_04_plus_tag_multiple(self):
        entities = self.rec.find_entities("User email is test+filter+inbox@mail.com.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "test+filter+inbox@mail.com")

    def test_email_05_hyphen_in_username(self):
        entities = self.rec.find_entities("Employee grace-hopper@navy.mil logged in.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "grace-hopper@navy.mil")

    def test_email_06_underscore_in_username(self):
        entities = self.rec.find_entities("Send to john_doe_qa@testing.net.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "john_doe_qa@testing.net")

    def test_email_07_percent_in_username(self):
        entities = self.rec.find_entities("Promo user promo%code@shop.biz registered.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "promo%code@shop.biz")

    def test_email_08_subdomain_single(self):
        entities = self.rec.find_entities("Alert sent to sysadmin@server1.cloud.internal.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "sysadmin@server1.cloud.internal")

    def test_email_09_subdomain_two_levels(self):
        entities = self.rec.find_entities("Routed to lead@us.east.corp.com.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "lead@us.east.corp.com")

    def test_email_10_subdomain_three_levels(self):
        entities = self.rec.find_entities("Alert from node@cluster.prod.dc1.internal.org.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "node@cluster.prod.dc1.internal.org")

    def test_email_11_numbers_only_username(self):
        entities = self.rec.find_entities("Numeric user 12345678@telecom.net pinged.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "12345678@telecom.net")

    def test_email_12_mixed_case_capitalized(self):
        entities = self.rec.find_entities("Reach Alice.Smith@ExampleCorp.Com here.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value.lower(), "alice.smith@examplecorp.com")

    def test_email_13_all_uppercase(self):
        entities = self.rec.find_entities("CONTACT SUPPORT@PARTNER.CO FOR DETAILS.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value.lower(), "support@partner.co")

    def test_email_14_country_tld_uk(self):
        entities = self.rec.find_entities("London office: london.lead@company.co.uk.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "london.lead@company.co.uk")

    def test_email_15_country_tld_india(self):
        entities = self.rec.find_entities("Bangalore hub: contact@startup.co.in.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "contact@startup.co.in")

    def test_email_16_country_tld_germany(self):
        entities = self.rec.find_entities("Berlin office: info@agentur.de.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "info@agentur.de")

    def test_email_17_country_tld_france(self):
        entities = self.rec.find_entities("Paris desk: equipe@entreprise.fr.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "equipe@entreprise.fr")

    def test_email_18_country_tld_canada(self):
        entities = self.rec.find_entities("Toronto branch: service@portal.ca.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "service@portal.ca")

    def test_email_19_modern_tld_tech(self):
        entities = self.rec.find_entities("Founders: founders@deeptech.tech.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "founders@deeptech.tech")

    def test_email_20_modern_tld_io(self):
        entities = self.rec.find_entities("Devops: deployer@infra.io.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "deployer@infra.io")

    def test_email_21_modern_tld_ai(self):
        entities = self.rec.find_entities("Model weights: team@research.ai.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "team@research.ai")

    def test_email_22_modern_tld_app(self):
        entities = self.rec.find_entities("Mobile client: feedback@mobile.app.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "feedback@mobile.app")

    def test_email_23_trailing_period_stripped(self):
        entities = self.rec.find_entities("Message sent to alex@example.com.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "alex@example.com")

    def test_email_24_trailing_comma_stripped(self):
        entities = self.rec.find_entities("Email list: alex@example.com, bob@example.com")
        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[0].value, "alex@example.com")
        self.assertEqual(entities[1].value, "bob@example.com")

    def test_email_25_trailing_semicolon_stripped(self):
        entities = self.rec.find_entities("Recipient: contact@corp.org; next action.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "contact@corp.org")

    def test_email_26_trailing_exclamation_stripped(self):
        entities = self.rec.find_entities("Important message to ceo@corp.com!")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "ceo@corp.com")

    def test_email_27_trailing_parenthesis_stripped(self):
        entities = self.rec.find_entities("Write to (inquiries@corp.com) anytime.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "inquiries@corp.com")

    def test_email_28_surrounded_by_parentheses(self):
        entities = self.rec.find_entities("Please notify (help@domain.net) immediately.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "help@domain.net")

    def test_email_29_surrounded_by_quotes(self):
        entities = self.rec.find_entities("The field 'user@domain.org' was entered.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "user@domain.org")

    def test_email_30_inside_json_sentence(self):
        entities = self.rec.find_entities('{"to": "user123@portal.co", "action": "send"}')
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "user123@portal.co")

    def test_email_31_invalid_missing_at_symbol(self):
        entities = self.rec.find_entities("Invalid string user.example.com without at.")
        self.assertEqual(len(entities), 0)

    def test_email_32_invalid_missing_tld_dot(self):
        entities = self.rec.find_entities("Invalid string user@localhost without domain.")
        self.assertEqual(len(entities), 0)

    def test_email_33_invalid_missing_username(self):
        entities = self.rec.find_entities("Invalid string @domain.com without user.")
        self.assertEqual(len(entities), 0)

    def test_email_34_invalid_space_before_at(self):
        entities = self.rec.find_entities("Invalid string user @domain.com has spaces.")
        self.assertEqual(len(entities), 0)

    def test_email_35_invalid_space_after_at(self):
        entities = self.rec.find_entities("Invalid string user@ domain.com has spaces.")
        self.assertEqual(len(entities), 0)


# =====================================================================
# 2. PHONE SYNTHETIC TEST CASES (38 Cases)
# =====================================================================

class TestSyntheticPhone(unittest.TestCase):
    def setUp(self):
        self.rec = PhoneRecognizer()

    def test_phone_01_us_plus1_dashed(self):
        entities = self.rec.find_entities("Call +1-555-123-4567 now.")
        self.assertEqual(len(entities), 1)
        self.assertIn("555-123-4567", entities[0].value)

    def test_phone_02_us_dashed_no_country_code(self):
        entities = self.rec.find_entities("Reach me at 555-234-5678 today.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "555-234-5678")

    def test_phone_03_us_parentheses_space(self):
        entities = self.rec.find_entities("Direct desk: (555) 345-6789.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "(555) 345-6789")

    def test_phone_04_us_parentheses_dashed(self):
        entities = self.rec.find_entities("Helpline: (555)-456-7890.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "(555)-456-7890")

    def test_phone_05_us_dot_delimited(self):
        entities = self.rec.find_entities("Cell line: 555.567.8901.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "555.567.8901")

    def test_phone_06_us_plus1_parentheses(self):
        entities = self.rec.find_entities("Office: +1 (555) 678-9012.")
        self.assertEqual(len(entities), 1)
        self.assertIn("555", entities[0].value)

    def test_phone_07_us_plus1_dotted(self):
        entities = self.rec.find_entities("Contact: +1.555.789.0123.")
        self.assertEqual(len(entities), 1)
        self.assertIn("555", entities[0].value)

    def test_phone_08_us_plus1_spaced(self):
        entities = self.rec.find_entities("Hotline: +1 555 890 1234.")
        self.assertEqual(len(entities), 1)
        self.assertIn("555", entities[0].value)

    def test_phone_09_india_plus91_spaced_5_5(self):
        entities = self.rec.find_entities("Bangalore: +91 98765 43210.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+91 98765 43210")

    def test_phone_10_india_plus91_dashed_10(self):
        entities = self.rec.find_entities("Mumbai cell: +91-9876543210.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+91-9876543210")

    def test_phone_11_india_plus91_continuous_10(self):
        entities = self.rec.find_entities("Delhi desk: +91 9876543210.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+91 9876543210")

    def test_phone_12_india_starting_with_9(self):
        entities = self.rec.find_entities("Call 9876543210 for KYC.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "9876543210")

    def test_phone_13_india_starting_with_8(self):
        entities = self.rec.find_entities("Mobile is 8765432109.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "8765432109")

    def test_phone_14_india_starting_with_7(self):
        entities = self.rec.find_entities("Mobile is 7654321098.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "7654321098")

    def test_phone_15_india_starting_with_6(self):
        entities = self.rec.find_entities("Mobile is 6543210987.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "6543210987")

    def test_phone_16_india_leading_zero_prefix(self):
        entities = self.rec.find_entities("Landline trunk: 09876543210.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "09876543210")

    def test_phone_17_uk_plus44_spaced(self):
        entities = self.rec.find_entities("London reception: +44 20 7946 0958.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+44 20 7946 0958")

    def test_phone_18_uk_plus44_dashed(self):
        entities = self.rec.find_entities("UK contact: +44-20-7946-0958.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+44-20-7946-0958")

    def test_phone_19_uk_plus44_mobile(self):
        entities = self.rec.find_entities("UK mobile: +44 7911 123456.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+44 7911 123456")

    def test_phone_20_germany_plus49_berlin(self):
        entities = self.rec.find_entities("Berlin desk: +49 30 12345678.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+49 30 12345678")

    def test_phone_21_germany_plus49_munich(self):
        entities = self.rec.find_entities("Munich desk: +49 89 1234567.")
        self.assertEqual(len(entities), 1)
        self.assertIn("+49", entities[0].value)

    def test_phone_22_germany_plus49_dashed(self):
        entities = self.rec.find_entities("Frankfurt desk: +49-69-12345678.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+49-69-12345678")

    def test_phone_23_trailing_period_handling(self):
        entities = self.rec.find_entities("Dial 555-678-1234.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "555-678-1234")

    def test_phone_24_trailing_comma_handling(self):
        entities = self.rec.find_entities("Contacts: 555-678-1234, 555-890-5678")
        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[0].value, "555-678-1234")
        self.assertEqual(entities[1].value, "555-890-5678")

    def test_phone_25_inside_parentheses(self):
        entities = self.rec.find_entities("Call (555-234-5678) anytime.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "555-234-5678")

    def test_phone_26_inside_quotes(self):
        entities = self.rec.find_entities('Stored value "+1-555-345-6789" in DB.')
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+1-555-345-6789")

    def test_phone_27_ignore_iso_date_dash(self):
        entities = self.rec.find_entities("Event date 2026-10-09 scheduled.")
        self.assertEqual(len(entities), 0)

    def test_phone_28_ignore_iso_date_slash(self):
        entities = self.rec.find_entities("Created on 2025/12/31.")
        self.assertEqual(len(entities), 0)

    def test_phone_29_ignore_iso_date_dot(self):
        entities = self.rec.find_entities("Timestamp 2024.01.15.")
        self.assertEqual(len(entities), 0)

    def test_phone_30_ignore_short_5_digits(self):
        entities = self.rec.find_entities("Order id is 12345.")
        self.assertEqual(len(entities), 0)

    def test_phone_31_ignore_short_7_digits(self):
        entities = self.rec.find_entities("Reference code 555-1234.")
        self.assertEqual(len(entities), 0)

    def test_phone_32_ignore_short_order_number(self):
        entities = self.rec.find_entities("Shipping badge #98765.")
        self.assertEqual(len(entities), 0)

    def test_phone_33_ignore_too_long_17_digits(self):
        entities = self.rec.find_entities("Hash token 12345678901234567890.")
        self.assertEqual(len(entities), 0)

    def test_phone_34_ignore_alphanumeric_words(self):
        entities = self.rec.find_entities("Product sku ABC-123-XYZ.")
        self.assertEqual(len(entities), 0)

    def test_phone_35_ignore_plain_words(self):
        entities = self.rec.find_entities("The quick brown fox jumps over the dog.")
        self.assertEqual(len(entities), 0)

    def test_phone_36_multiple_phones_in_string(self):
        text = "Primary 555-111-2222, secondary 555-333-4444, backup +91 98765 43210."
        entities = self.rec.find_entities(text)
        self.assertEqual(len(entities), 3)

    def test_phone_37_phone_with_extension_word_boundary(self):
        entities = self.rec.find_entities("Dial 555-777-8888 ext 402.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "555-777-8888")

    def test_phone_38_phone_in_free_text_paragraph(self):
        text = "Please reach our customer care agent at +1-555-987-6543 immediately."
        entities = self.rec.find_entities(text)
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "+1-555-987-6543")


# =====================================================================
# 3. SSN SYNTHETIC TEST CASES (28 Cases)
# =====================================================================

class TestSyntheticSSN(unittest.TestCase):
    def setUp(self):
        self.rec = SSNRecognizer()

    def test_ssn_01_valid_standard_hyphen(self):
        entities = self.rec.find_entities("SSN is 123-45-6789.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "123-45-6789")

    def test_ssn_02_valid_standard_space(self):
        entities = self.rec.find_entities("SSN is 123 45 6789.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "123 45 6789")

    def test_ssn_03_valid_min_area_001(self):
        entities = self.rec.find_entities("SSN is 001-12-3456.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "001-12-3456")

    def test_ssn_04_valid_area_below_666(self):
        entities = self.rec.find_entities("SSN is 665-99-9999.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "665-99-9999")

    def test_ssn_05_valid_area_above_666(self):
        entities = self.rec.find_entities("SSN is 667-11-2222.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "667-11-2222")

    def test_ssn_06_valid_max_area_899(self):
        entities = self.rec.find_entities("SSN is 899-88-7777.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "899-88-7777")

    def test_ssn_07_valid_group_01(self):
        entities = self.rec.find_entities("SSN is 321-01-5678.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "321-01-5678")

    def test_ssn_08_valid_group_99(self):
        entities = self.rec.find_entities("SSN is 456-99-1234.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "456-99-1234")

    def test_ssn_09_valid_serial_0001(self):
        entities = self.rec.find_entities("SSN is 234-56-0001.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "234-56-0001")

    def test_ssn_10_valid_serial_9999(self):
        entities = self.rec.find_entities("SSN is 345-67-9999.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "345-67-9999")

    def test_ssn_11_valid_repeated_digits(self):
        entities = self.rec.find_entities("SSN is 222-33-4444.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "222-33-4444")

    def test_ssn_12_valid_ssn_in_sentence(self):
        entities = self.rec.find_entities("Identity verified via SSN 567-89-0123 yesterday.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "567-89-0123")

    def test_ssn_13_valid_ssn_in_json_value(self):
        entities = self.rec.find_entities('{"ssn": "432-10-9876"}')
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "432-10-9876")

    def test_ssn_14_valid_two_ssns_in_one_text(self):
        entities = self.rec.find_entities("Primary 123-45-6789 and secondary 987-65-4321.")
        # Note: 987 is in 900-999 SSA invalid area range! So only 123-45-6789 should match!
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "123-45-6789")

    def test_ssn_15_invalid_area_000_rule(self):
        entities = self.rec.find_entities("Bad SSN 000-12-3456.")
        self.assertEqual(len(entities), 0)

    def test_ssn_16_invalid_area_000_high_serial(self):
        entities = self.rec.find_entities("Bad SSN 000-99-9999.")
        self.assertEqual(len(entities), 0)

    def test_ssn_17_invalid_area_666_rule(self):
        entities = self.rec.find_entities("Bad SSN 666-12-3456.")
        self.assertEqual(len(entities), 0)

    def test_ssn_18_invalid_area_666_arbitrary_group(self):
        entities = self.rec.find_entities("Bad SSN 666-45-6789.")
        self.assertEqual(len(entities), 0)

    def test_ssn_19_invalid_area_900_boundary(self):
        entities = self.rec.find_entities("Bad SSN 900-12-3456.")
        self.assertEqual(len(entities), 0)

    def test_ssn_20_invalid_area_950_mid_range(self):
        entities = self.rec.find_entities("Bad SSN 950-45-6789.")
        self.assertEqual(len(entities), 0)

    def test_ssn_21_invalid_area_999_top_boundary(self):
        entities = self.rec.find_entities("Bad SSN 999-99-9999.")
        self.assertEqual(len(entities), 0)

    def test_ssn_22_invalid_group_00_rule(self):
        entities = self.rec.find_entities("Bad SSN 123-00-4567.")
        self.assertEqual(len(entities), 0)

    def test_ssn_23_invalid_group_00_high_area(self):
        entities = self.rec.find_entities("Bad SSN 789-00-1234.")
        self.assertEqual(len(entities), 0)

    def test_ssn_24_invalid_serial_0000_rule(self):
        entities = self.rec.find_entities("Bad SSN 123-45-0000.")
        self.assertEqual(len(entities), 0)

    def test_ssn_25_invalid_serial_0000_high_area(self):
        entities = self.rec.find_entities("Bad SSN 850-22-0000.")
        self.assertEqual(len(entities), 0)

    def test_ssn_26_invalid_continuous_no_delimiters(self):
        entities = self.rec.find_entities("Continuous digits 123456789.")
        self.assertEqual(len(entities), 0)

    def test_ssn_27_invalid_dotted_delimiters(self):
        entities = self.rec.find_entities("Dotted SSN 123.45.6789.")
        self.assertEqual(len(entities), 0)

    def test_ssn_28_invalid_letters_in_ssn(self):
        entities = self.rec.find_entities("Alphanumeric SSN 12A-34-5678.")
        self.assertEqual(len(entities), 0)


# =====================================================================
# 4. CREDIT CARD SYNTHETIC TEST CASES (34 Cases)
# =====================================================================

class TestSyntheticCreditCard(unittest.TestCase):
    def setUp(self):
        self.rec = CreditCardRecognizer(check_luhn=True)

    def test_card_01_visa_16_digits_dashed_luhn_valid(self):
        card = make_luhn_number("400000", 16)
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
        entities = self.rec.find_entities(f"Charged to {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_card_02_visa_16_digits_spaced_luhn_valid(self):
        card = make_luhn_number("411111", 16)
        formatted = f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
        entities = self.rec.find_entities(f"Charged to {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_card_03_visa_16_digits_continuous_luhn_valid(self):
        card = make_luhn_number("422222", 16)
        entities = self.rec.find_entities(f"Charged to {card}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, card)

    def test_card_04_visa_13_digits_continuous_luhn_valid(self):
        card = make_luhn_number("400000", 13)
        entities = self.rec.find_entities(f"Legacy card {card}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, card)

    def test_card_05_mastercard_51_dashed_luhn_valid(self):
        card = make_luhn_number("510000", 16)
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_card_06_mastercard_52_spaced_luhn_valid(self):
        card = make_luhn_number("520000", 16)
        formatted = f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_card_07_mastercard_53_continuous_luhn_valid(self):
        card = make_luhn_number("530000", 16)
        entities = self.rec.find_entities(f"Card {card}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, card)

    def test_card_08_mastercard_54_dashed_luhn_valid(self):
        card = make_luhn_number("540000", 16)
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_card_09_mastercard_55_spaced_luhn_valid(self):
        card = make_luhn_number("550000", 16)
        formatted = f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_card_10_mastercard_2221_series_luhn_valid(self):
        card = make_luhn_number("222100", 16)
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_card_11_mastercard_2720_series_luhn_valid(self):
        card = make_luhn_number("272000", 16)
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_card_12_amex_34_dashed_4_6_5_luhn_valid(self):
        card = make_luhn_number("340000", 15)
        formatted = f"{card[:4]}-{card[4:10]}-{card[10:]}"
        entities = self.rec.find_entities(f"Amex {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_card_13_amex_37_spaced_4_6_5_luhn_valid(self):
        card = make_luhn_number("370000", 15)
        formatted = f"{card[:4]} {card[4:10]} {card[10:]}"
        entities = self.rec.find_entities(f"Amex {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_card_14_amex_15_continuous_luhn_valid(self):
        card = make_luhn_number("341111", 15)
        entities = self.rec.find_entities(f"Amex {card}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, card)

    def test_card_15_discover_6011_dashed_luhn_valid(self):
        card = make_luhn_number("601100", 16)
        formatted = f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
        entities = self.rec.find_entities(f"Discover {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_card_16_discover_65_spaced_luhn_valid(self):
        card = make_luhn_number("650000", 16)
        formatted = f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
        entities = self.rec.find_entities(f"Discover {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_card_17_discover_continuous_luhn_valid(self):
        card = make_luhn_number("601122", 16)
        entities = self.rec.find_entities(f"Discover {card}.")
        self.assertEqual(len(entities), 1)

    def test_card_18_generic_16_digit_dashed_luhn_valid(self):
        card = "4111-1111-1111-1111"
        self.assertTrue(luhn_checksum_valid(card))
        entities = self.rec.find_entities(f"Generic {card}.")
        self.assertEqual(len(entities), 1)

    def test_card_19_generic_16_digit_spaced_luhn_valid(self):
        card = "4111 1111 1111 1111"
        self.assertTrue(luhn_checksum_valid(card))
        entities = self.rec.find_entities(f"Generic {card}.")
        self.assertEqual(len(entities), 1)

    def test_card_20_card_with_trailing_period(self):
        card = "4111-1111-1111-1111"
        entities = self.rec.find_entities(f"Receipt for card {card}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, card)

    def test_card_21_card_inside_parentheses(self):
        card = "4111-1111-1111-1111"
        entities = self.rec.find_entities(f"Account ({card}) verified.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, card)

    def test_card_22_card_in_json_free_text(self):
        card = "4111-1111-1111-1111"
        entities = self.rec.find_entities(f'{{"payment": "card {card} debited"}}')
        self.assertEqual(len(entities), 1)

    def test_card_23_invalid_luhn_visa_rejected(self):
        card = make_luhn_number("400000", 16)
        bad_card = make_invalid_luhn(card)
        formatted = f"{bad_card[:4]}-{bad_card[4:8]}-{bad_card[8:12]}-{bad_card[12:]}"
        entities = self.rec.find_entities(f"Charged to {formatted}.")
        self.assertEqual(len(entities), 0)

    def test_card_24_invalid_luhn_mastercard_rejected(self):
        card = make_luhn_number("510000", 16)
        bad_card = make_invalid_luhn(card)
        formatted = f"{bad_card[:4]}-{bad_card[4:8]}-{bad_card[8:12]}-{bad_card[12:]}"
        entities = self.rec.find_entities(f"Card {formatted}.")
        self.assertEqual(len(entities), 0)

    def test_card_25_invalid_luhn_amex_rejected(self):
        card = make_luhn_number("340000", 15)
        bad_card = make_invalid_luhn(card)
        formatted = f"{bad_card[:4]}-{bad_card[4:10]}-{bad_card[10:]}"
        entities = self.rec.find_entities(f"Amex {formatted}.")
        self.assertEqual(len(entities), 0)

    def test_card_26_invalid_luhn_discover_rejected(self):
        card = make_luhn_number("601100", 16)
        bad_card = make_invalid_luhn(card)
        formatted = f"{bad_card[:4]}-{bad_card[4:8]}-{bad_card[8:12]}-{bad_card[12:]}"
        entities = self.rec.find_entities(f"Discover {formatted}.")
        self.assertEqual(len(entities), 0)

    def test_card_27_invalid_luhn_generic_16_rejected(self):
        bad_card = "4111-1111-1111-1112"
        self.assertFalse(luhn_checksum_valid(bad_card))
        entities = self.rec.find_entities(f"Generic {bad_card}.")
        self.assertEqual(len(entities), 0)

    def test_card_28_invalid_arbitrary_16_digits_rejected(self):
        bad_card = "1234-5678-9012-3456"
        # If this happens to be Luhn-invalid, check it
        if not luhn_checksum_valid(bad_card):
            entities = self.rec.find_entities(f"Arbitrary {bad_card}.")
            self.assertEqual(len(entities), 0)

    def test_card_29_invalid_too_short_12_digits_rejected(self):
        short = "4111-1111-1111"
        entities = self.rec.find_entities(f"Short card {short}.")
        self.assertEqual(len(entities), 0)

    def test_card_30_invalid_too_long_20_digits_rejected(self):
        long_card = "4111-1111-1111-1111-1111"
        entities = self.rec.find_entities(f"Long {long_card}.")
        self.assertEqual(len(entities), 0)

    def test_card_31_luhn_direct_helper_true(self):
        self.assertTrue(luhn_checksum_valid("4111111111111111"))

    def test_card_32_luhn_direct_helper_false(self):
        self.assertFalse(luhn_checksum_valid("4111111111111112"))

    def test_card_33_credit_card_disabled_luhn_validation_mode(self):
        rec_no_luhn = CreditCardRecognizer(check_luhn=False)
        bad_luhn_visa = "4111-1111-1111-1112"
        entities = rec_no_luhn.find_entities(f"Card {bad_luhn_visa}.")
        self.assertEqual(len(entities), 1)

    def test_card_34_multiple_valid_cards_in_single_text(self):
        c1 = "4111-1111-1111-1111"
        c2 = make_luhn_number("510000", 16)
        f2 = f"{c2[:4]}-{c2[4:8]}-{c2[8:12]}-{c2[12:]}"
        entities = self.rec.find_entities(f"Cards: {c1} and {f2}.")
        self.assertEqual(len(entities), 2)


# =====================================================================
# 5. IP ADDRESS SYNTHETIC TEST CASES (28 Cases)
# =====================================================================

class TestSyntheticIPAddress(unittest.TestCase):
    def setUp(self):
        self.rec = IPAddressRecognizer()

    def test_ip_01_private_192_168_0_1(self):
        entities = self.rec.find_entities("Host gateway is 192.168.0.1.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "192.168.0.1")

    def test_ip_02_private_192_168_1_100(self):
        entities = self.rec.find_entities("Internal server at 192.168.1.100.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "192.168.1.100")

    def test_ip_03_private_10_0_0_1(self):
        entities = self.rec.find_entities("Router at 10.0.0.1 online.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "10.0.0.1")

    def test_ip_04_private_10_100_200_254(self):
        entities = self.rec.find_entities("Subnet target 10.100.200.254.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "10.100.200.254")

    def test_ip_05_private_172_16_0_1(self):
        entities = self.rec.find_entities("VPC edge 172.16.0.1.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "172.16.0.1")

    def test_ip_06_private_172_31_255_254(self):
        entities = self.rec.find_entities("VPC max 172.31.255.254.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "172.31.255.254")

    def test_ip_07_loopback_127_0_0_1(self):
        entities = self.rec.find_entities("Localhost at 127.0.0.1.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "127.0.0.1")

    def test_ip_08_dns_google_8_8_8_8(self):
        entities = self.rec.find_entities("Google DNS 8.8.8.8.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "8.8.8.8")

    def test_ip_09_dns_google_secondary_8_8_4_4(self):
        entities = self.rec.find_entities("Google secondary 8.8.4.4.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "8.8.4.4")

    def test_ip_10_dns_cloudflare_1_1_1_1(self):
        entities = self.rec.find_entities("Cloudflare DNS 1.1.1.1.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "1.1.1.1")

    def test_ip_11_dns_cloudflare_secondary_1_0_0_1(self):
        entities = self.rec.find_entities("Cloudflare backup 1.0.0.1.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "1.0.0.1")

    def test_ip_12_dns_quad9_9_9_9_9(self):
        entities = self.rec.find_entities("Quad9 resolver 9.9.9.9.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "9.9.9.9")

    def test_ip_13_all_zeros_0_0_0_0(self):
        entities = self.rec.find_entities("Listen on 0.0.0.0 all interfaces.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "0.0.0.0")

    def test_ip_14_all_max_255_255_255_255(self):
        entities = self.rec.find_entities("Broadcast 255.255.255.255 sent.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "255.255.255.255")

    def test_ip_15_boundary_octet_254_254_254_254(self):
        entities = self.rec.find_entities("Node 254.254.254.254.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "254.254.254.254")

    def test_ip_16_mixed_octets_single_double_triple(self):
        entities = self.rec.find_entities("Endpoint 10.20.130.5.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "10.20.130.5")

    def test_ip_17_ip_inside_url_string(self):
        entities = self.rec.find_entities("Connect to http://192.168.1.50/api now.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "192.168.1.50")

    def test_ip_18_ip_with_trailing_colon_port_text(self):
        entities = self.rec.find_entities("Target 172.20.0.10:8080 active.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "172.20.0.10")

    def test_ip_19_multiple_ips_in_one_string(self):
        text = "Cluster members: 10.0.0.1, 10.0.0.2, and 10.0.0.3."
        entities = self.rec.find_entities(text)
        self.assertEqual(len(entities), 3)

    def test_ip_20_invalid_octet_256_at_start(self):
        entities = self.rec.find_entities("Bad IP 256.1.1.1.")
        self.assertEqual(len(entities), 0)

    def test_ip_21_invalid_octet_256_at_end(self):
        entities = self.rec.find_entities("Bad IP 192.168.1.256.")
        self.assertEqual(len(entities), 0)

    def test_ip_22_invalid_octet_300_in_middle(self):
        entities = self.rec.find_entities("Bad IP 10.300.0.1.")
        self.assertEqual(len(entities), 0)

    def test_ip_23_invalid_all_999(self):
        entities = self.rec.find_entities("Bad IP 999.999.999.999.")
        self.assertEqual(len(entities), 0)

    def test_ip_24_invalid_incomplete_3_octets(self):
        entities = self.rec.find_entities("Incomplete 192.168.1.")
        self.assertEqual(len(entities), 0)

    def test_ip_25_invalid_incomplete_2_octets(self):
        entities = self.rec.find_entities("Incomplete 10.0.")
        self.assertEqual(len(entities), 0)

    def test_ip_26_invalid_single_number(self):
        entities = self.rec.find_entities("Number 12345.")
        self.assertEqual(len(entities), 0)

    def test_ip_27_invalid_alphanumeric_words(self):
        entities = self.rec.find_entities("Host name my.domain.corp.com.")
        self.assertEqual(len(entities), 0)

    def test_ip_28_invalid_empty_string(self):
        entities = self.rec.find_entities("")
        self.assertEqual(len(entities), 0)


# =====================================================================
# 6. API KEY SYNTHETIC TEST CASES (28 Cases)
# =====================================================================

class TestSyntheticAPIKey(unittest.TestCase):
    def setUp(self):
        self.rec = APIKeyRecognizer()

    def test_api_01_openai_sk_32_alpha(self):
        key = "sk-" + "a" * 32
        entities = self.rec.find_entities(f"OpenAI key {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_02_openai_sk_48_alphanumeric(self):
        key = "sk-" + "1234567890abcdef1234567890abcdef12345678"
        entities = self.rec.find_entities(f"API key {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_03_openai_sk_proj_standard(self):
        key = "sk-proj-" + "1234567890abcdef1234567890abcdef1234"
        entities = self.rec.find_entities(f"Secret {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_04_openai_sk_proj_with_hyphens(self):
        key = "sk-proj-abc-def-1234567890abcdef1234567890"
        entities = self.rec.find_entities(f"Secret {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_05_openai_sk_proj_with_underscores(self):
        key = "sk-proj-abc_def_1234567890abcdef1234567890"
        entities = self.rec.find_entities(f"Secret {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_06_aws_akia_standard_example(self):
        key = "AKIAIOSFODNN7EXAMPLE"
        entities = self.rec.find_entities(f"AWS credentials {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_07_aws_akia_all_numbers(self):
        key = "AKIA1234567890123456"
        entities = self.rec.find_entities(f"AWS credentials {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_08_aws_akia_all_letters(self):
        key = "AKIAABCDEFGHIJKLMNOP"
        entities = self.rec.find_entities(f"AWS credentials {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_09_aws_akia_mixed_hex(self):
        key = "AKIA0123456789ABCDEF"
        entities = self.rec.find_entities(f"AWS credentials {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_10_github_ghp_36_chars(self):
        key = "ghp_" + "1234567890abcdef1234567890abcdef1234"
        entities = self.rec.find_entities(f"Token {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_11_github_ghp_mixed_case(self):
        key = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        entities = self.rec.find_entities(f"Token {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_12_github_pat_40_chars(self):
        key = "github_pat_" + "1234567890abcdef1234567890abcdef12345678"
        entities = self.rec.find_entities(f"PAT {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_13_github_pat_with_underscores(self):
        key = "github_pat_" + "abc_def_1234567890abcdef1234567890abcdef"
        entities = self.rec.find_entities(f"PAT {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_14_stripe_sk_live_24_chars(self):
        prefix = "".join(["s", "k", "_", "l", "i", "v", "e", "_"])
        key = prefix + "1234567890abcdef12345678"
        entities = self.rec.find_entities(f"Stripe {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_15_stripe_sk_live_32_chars(self):
        prefix = "".join(["s", "k", "_", "l", "i", "v", "e", "_"])
        key = prefix + "1234567890abcdef1234567890abcdef"
        entities = self.rec.find_entities(f"Stripe {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_16_stripe_sk_test_24_chars(self):
        key = "sk_test_" + "1234567890abcdef12345678"
        entities = self.rec.find_entities(f"Stripe {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_17_stripe_rk_live_24_chars(self):
        prefix = "".join(["r", "k", "_", "l", "i", "v", "e", "_"])
        key = prefix + "1234567890abcdef12345678"
        entities = self.rec.find_entities(f"Stripe {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_18_stripe_rk_test_24_chars(self):
        key = "rk_test_" + "1234567890abcdef12345678"
        entities = self.rec.find_entities(f"Stripe {key}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, key)

    def test_api_19_bearer_token_standard_jwt(self):
        token_str = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        entities = self.rec.find_entities(f"Auth header: {token_str}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, token_str)

    def test_api_20_bearer_token_base64_charset(self):
        token_str = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
        entities = self.rec.find_entities(f"Authorization: {token_str}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, token_str)

    def test_api_21_bearer_token_case_insensitive(self):
        token_str = "bearer abcdefghijklmnopqrstuvwxyz0123456789"
        entities = self.rec.find_entities(f"Header: {token_str}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, token_str)

    def test_api_22_invalid_openai_too_short(self):
        entities = self.rec.find_entities("Key sk-short123.")
        self.assertEqual(len(entities), 0)

    def test_api_23_invalid_aws_akia_too_short(self):
        entities = self.rec.find_entities("Key AKIA12345.")
        self.assertEqual(len(entities), 0)

    def test_api_24_invalid_aws_akia_lowercase(self):
        entities = self.rec.find_entities("Key akiaiosfodnn7example.")
        self.assertEqual(len(entities), 0)

    def test_api_25_invalid_github_ghp_too_short(self):
        entities = self.rec.find_entities("Token ghp_tooshort.")
        self.assertEqual(len(entities), 0)

    def test_api_26_invalid_stripe_too_short(self):
        prefix = "".join(["s", "k", "_", "l", "i", "v", "e", "_"])
        entities = self.rec.find_entities(f"Key {prefix}short.")
        self.assertEqual(len(entities), 0)

    def test_api_27_invalid_bearer_too_short(self):
        entities = self.rec.find_entities("Header Bearer shorttoken.")
        self.assertEqual(len(entities), 0)

    def test_api_28_invalid_unrelated_text(self):
        entities = self.rec.find_entities("Regular text without credentials.")
        self.assertEqual(len(entities), 0)


# =====================================================================
# 7. INDIAN PII SYNTHETIC TEST CASES (30 Cases)
# =====================================================================

class TestSyntheticIndianPII(unittest.TestCase):
    def setUp(self):
        self.pan_rec = PANRecognizer()
        self.aadhaar_rec = AadhaarRecognizer(check_verhoeff=True)

    def test_indian_01_pan_person_p(self):
        pan = "ABCPE1234F"
        entities = self.pan_rec.find_entities(f"Customer PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_02_pan_company_c(self):
        pan = "XYZCA5678K"
        entities = self.pan_rec.find_entities(f"Company PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_03_pan_huf_h(self):
        pan = "AAAHB9012D"
        entities = self.pan_rec.find_entities(f"HUF PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_04_pan_firm_f(self):
        pan = "BKLFA3456M"
        entities = self.pan_rec.find_entities(f"Firm PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_05_pan_aop_a(self):
        pan = "CDETA7890N"
        entities = self.pan_rec.find_entities(f"AOP PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_06_pan_trust_t(self):
        pan = "EFTTB1234P"
        entities = self.pan_rec.find_entities(f"Trust PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_07_pan_boi_b(self):
        pan = "GHIBA5678Q"
        entities = self.pan_rec.find_entities(f"BOI PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_08_pan_local_l(self):
        pan = "JKLLA9012R"
        entities = self.pan_rec.find_entities(f"Local authority PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_09_pan_juridical_j(self):
        pan = "MNOJA3456S"
        entities = self.pan_rec.find_entities(f"Juridical PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_10_pan_gov_g(self):
        pan = "PQRGA7890T"
        entities = self.pan_rec.find_entities(f"Government PAN {pan}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, pan)

    def test_indian_11_pan_invalid_4th_char_x(self):
        pan = "ABCXE1234F"
        entities = self.pan_rec.find_entities(f"Invalid PAN {pan}.")
        self.assertEqual(len(entities), 0)

    def test_indian_12_pan_invalid_4th_char_z(self):
        pan = "XYZZA5678K"
        entities = self.pan_rec.find_entities(f"Invalid PAN {pan}.")
        self.assertEqual(len(entities), 0)

    def test_indian_13_pan_invalid_lowercase(self):
        pan = "abcpe1234f"
        entities = self.pan_rec.find_entities(f"Invalid PAN {pan}.")
        self.assertEqual(len(entities), 0)

    def test_indian_14_pan_invalid_short_digits(self):
        pan = "ABCPE123F"
        entities = self.pan_rec.find_entities(f"Invalid PAN {pan}.")
        self.assertEqual(len(entities), 0)

    def test_indian_15_pan_invalid_extra_digits(self):
        pan = "ABCPE12345F"
        entities = self.pan_rec.find_entities(f"Invalid PAN {pan}.")
        self.assertEqual(len(entities), 0)

    def test_indian_16_aadhaar_spaced_verhoeff_valid(self):
        aadhaar = make_valid_aadhaar("36759834601")
        formatted = f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}"
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_indian_17_aadhaar_dashed_verhoeff_valid(self):
        aadhaar = make_valid_aadhaar("45678901234")
        formatted = f"{aadhaar[:4]}-{aadhaar[4:8]}-{aadhaar[8:]}"
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, formatted)

    def test_indian_18_aadhaar_continuous_verhoeff_valid(self):
        aadhaar = make_valid_aadhaar("56789012345")
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {aadhaar}.")
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, aadhaar)

    def test_indian_19_aadhaar_starting_with_2_valid(self):
        aadhaar = make_valid_aadhaar("23456789012")
        formatted = f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}"
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_indian_20_aadhaar_starting_with_5_valid(self):
        aadhaar = make_valid_aadhaar("59876543210")
        formatted = f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}"
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_indian_21_aadhaar_starting_with_9_valid(self):
        aadhaar = make_valid_aadhaar("98765432109")
        formatted = f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}"
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_indian_22_aadhaar_invalid_verhoeff_checksum_rejected(self):
        aadhaar = make_valid_aadhaar("36759834601")
        bad = make_invalid_aadhaar(aadhaar)
        formatted = f"{bad[:4]} {bad[4:8]} {bad[8:]}"
        entities = self.aadhaar_rec.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 0)

    def test_indian_23_aadhaar_invalid_starting_with_0_rejected(self):
        entities = self.aadhaar_rec.find_entities("Aadhaar 0123 4567 8901.")
        self.assertEqual(len(entities), 0)

    def test_indian_24_aadhaar_invalid_starting_with_1_rejected(self):
        entities = self.aadhaar_rec.find_entities("Aadhaar 1234 5678 9012.")
        self.assertEqual(len(entities), 0)

    def test_indian_25_aadhaar_invalid_too_short_11_digits(self):
        entities = self.aadhaar_rec.find_entities("Aadhaar 2345 6789 012.")
        self.assertEqual(len(entities), 0)

    def test_indian_26_aadhaar_invalid_too_long_13_digits(self):
        entities = self.aadhaar_rec.find_entities("Aadhaar 2345 6789 0123 4.")
        self.assertEqual(len(entities), 0)

    def test_indian_27_aadhaar_disabled_verhoeff_mode(self):
        rec_no_v = AadhaarRecognizer(check_verhoeff=False)
        aadhaar = make_valid_aadhaar("36759834601")
        bad = make_invalid_aadhaar(aadhaar)
        formatted = f"{bad[:4]} {bad[4:8]} {bad[8:]}"
        entities = rec_no_v.find_entities(f"Aadhaar {formatted}.")
        self.assertEqual(len(entities), 1)

    def test_indian_28_verhoeff_direct_checksum_true(self):
        # 3675 9834 6016 is valid Verhoeff Aadhaar
        self.assertTrue(verhoeff_validate("367598346016"))

    def test_indian_29_verhoeff_direct_checksum_false(self):
        self.assertFalse(verhoeff_validate("367598346017"))

    def test_indian_30_combined_pan_and_aadhaar_in_kyc_payload(self):
        pan = "ABCPE1234F"
        aadhaar = "3675 9834 6016"
        p_entities = self.pan_rec.find_entities(f"KYC: {pan} and {aadhaar}")
        a_entities = self.aadhaar_rec.find_entities(f"KYC: {pan} and {aadhaar}")
        self.assertEqual(len(p_entities), 1)
        self.assertEqual(len(a_entities), 1)


# =====================================================================
# 8. COMPLEX JSON & STRUCTURES (18 Cases)
# =====================================================================

class TestSyntheticComplexJSON(unittest.TestCase):
    def setUp(self):
        self.firewall = PIIFirewall()
        self.tool = SimulatedExternalTool()

    def test_json_01_nested_depth_5_with_email_and_phone(self):
        payload = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": {
                                "email": "alex.deep@example.test",
                                "phone": "+1-555-432-1098"
                            }
                        }
                    }
                }
            }
        }
        res, vault = self.firewall.intercept_request(payload)
        l5 = res.sanitized_payload["level1"]["level2"]["level3"]["level4"]["level5"]
        self.assertTrue(l5["email"].startswith("⟦EMAIL_"))
        self.assertTrue(l5["phone"].startswith("⟦PHONE_"))
        self.assertNotIn("alex.deep@example.test", str(res.sanitized_payload))

    def test_json_02_nested_depth_10_single_pii(self):
        cur = {"email": "depth10@security.gov"}
        for i in range(10, 0, -1):
            cur = {f"layer_{i}": cur}
        res, vault = self.firewall.intercept_request(cur)
        self.assertNotIn("depth10@security.gov", str(res.sanitized_payload))
        self.assertIn("⟦EMAIL_", str(res.sanitized_payload))

    def test_json_03_list_of_20_customer_records(self):
        customers = [{"id": i, "email": f"customer_{i}@corp.org"} for i in range(20)]
        payload = {"customers": customers}
        res, vault = self.firewall.intercept_request(payload)
        for c in res.sanitized_payload["customers"]:
            self.assertTrue(c["email"].startswith("⟦EMAIL_"))
        self.assertEqual(res.metrics.total_detected, 20)

    def test_json_04_mixed_types_booleans_preserved(self):
        payload = {"active": True, "archived": False, "email": "bool.check@test.com"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertIs(res.sanitized_payload["active"], True)
        self.assertIs(res.sanitized_payload["archived"], False)

    def test_json_05_mixed_types_null_preserved(self):
        payload = {"notes": None, "secondary_contact": None, "email": "null.check@test.com"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertIsNone(res.sanitized_payload["notes"])
        self.assertIsNone(res.sanitized_payload["secondary_contact"])

    def test_json_06_mixed_types_integers_preserved(self):
        payload = {"count": 42, "retry": 0, "email": "int.check@test.com"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertEqual(res.sanitized_payload["count"], 42)
        self.assertEqual(res.sanitized_payload["retry"], 0)

    def test_json_07_mixed_types_floats_preserved(self):
        payload = {"balance": 99.95, "tax": 0.0825, "email": "float.check@test.com"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertEqual(res.sanitized_payload["balance"], 99.95)
        self.assertEqual(res.sanitized_payload["tax"], 0.0825)

    def test_json_08_unicode_emojis_preserved(self):
        payload = {"status": "Customer 🚀 ordered 💳 for user alex@rocket.space 🔥"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertIn("🚀", res.sanitized_payload["status"])
        self.assertIn("💳", res.sanitized_payload["status"])
        self.assertIn("🔥", res.sanitized_payload["status"])
        self.assertNotIn("alex@rocket.space", res.sanitized_payload["status"])

    def test_json_09_repeated_same_pii_gets_identical_token(self):
        payload = {
            "billing_email": "repeated@acme.corp",
            "shipping_email": "repeated@acme.corp",
            "notes": "Confirm with repeated@acme.corp"
        }
        res, vault = self.firewall.intercept_request(payload)
        tok1 = res.sanitized_payload["billing_email"]
        tok2 = res.sanitized_payload["shipping_email"]
        self.assertEqual(tok1, tok2)
        self.assertIn(tok1, res.sanitized_payload["notes"])
        self.assertEqual(vault.get_token_count(), 1)

    def test_json_10_multiple_pii_in_single_free_text_field(self):
        payload = {
            "message": "Reach alex@test.com or call 555-123-4567, SSN is 123-45-6789."
        }
        res, _ = self.firewall.intercept_request(payload)
        msg = res.sanitized_payload["message"]
        self.assertNotIn("alex@test.com", msg)
        self.assertNotIn("555-123-4567", msg)
        self.assertNotIn("123-45-6789", msg)
        self.assertIn("⟦EMAIL_", msg)
        self.assertIn("⟦PHONE_", msg)
        self.assertIn("⟦SSN_", msg)

    def test_json_11_empty_dict_payload(self):
        res, _ = self.firewall.intercept_request({})
        self.assertEqual(res.sanitized_payload, {})
        self.assertEqual(res.metrics.total_detected, 0)

    def test_json_12_empty_list_payload(self):
        res, _ = self.firewall.intercept_request([])
        self.assertEqual(res.sanitized_payload, [])
        self.assertEqual(res.metrics.total_detected, 0)

    def test_json_13_empty_string_values(self):
        payload = {"k1": "", "k2": "   ", "email": "valid@test.com"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertEqual(res.sanitized_payload["k1"], "")
        self.assertEqual(res.sanitized_payload["k2"], "   ")

    def test_json_14_tuple_data_structures_preserved(self):
        payload = {"coordinates": (12.9716, 77.5946), "agent": ("alex@blr.in", "ACTIVE")}
        res, _ = self.firewall.intercept_request(payload)
        self.assertIsInstance(res.sanitized_payload["coordinates"], tuple)
        self.assertIsInstance(res.sanitized_payload["agent"], tuple)
        self.assertTrue(res.sanitized_payload["agent"][0].startswith("⟦EMAIL_"))

    def test_json_15_large_payload_50_distinct_items(self):
        payload = {
            f"record_{i}": {
                "email": f"user{i}@corp{i}.org",
                "phone": "+1-555-123-4567",
                "ssn": "123-45-6789",
                "ip": f"192.168.1.{i+1}"
            }
            for i in range(50)
        }
        res, _ = self.firewall.intercept_request(payload)
        self.assertEqual(len(res.sanitized_payload), 50)
        self.assertGreater(res.metrics.total_detected, 150)

    def test_json_16_non_dict_string_payload_root(self):
        payload = "Contact admin@secret.net immediately."
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload.startswith("Contact ⟦EMAIL_"))

    def test_json_17_non_dict_list_payload_root(self):
        payload = ["user1@domain.com", "user2@domain.com"]
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload[0].startswith("⟦EMAIL_"))
        self.assertTrue(res.sanitized_payload[1].startswith("⟦EMAIL_"))

    def test_json_18_end_to_end_full_rehydration_roundtrip(self):
        agent_req = {
            "tool": "echo_service",
            "arguments": {
                "client_email": "roundtrip@client.test",
                "client_phone": "+1-555-888-9999"
            }
        }
        result = self.firewall.process_tool_call(agent_req, self.tool.execute)
        # Verify tool never received raw email or phone
        tool_rec = self.tool.received_payloads[-1]
        self.assertNotIn("roundtrip@client.test", str(tool_rec))
        self.assertNotIn("+1-555-888-9999", str(tool_rec))
        # Verify response returned to agent was completely re-hydrated
        restored = result["response"]["echo_arguments"]
        self.assertEqual(restored["client_email"], "roundtrip@client.test")
        self.assertEqual(restored["client_phone"], "+1-555-888-9999")


# =====================================================================
# 9. ADVERSARIAL ATTACKS & POLICY ENGINE (18 Cases)
# =====================================================================

class TestSyntheticAdversarialAndPolicy(unittest.TestCase):
    def setUp(self):
        self.firewall = PIIFirewall()
        self.tool = SimulatedExternalTool()

    def test_adv_01_zero_width_space_in_email(self):
        evasion_email = "a\u200Bl\u200Be\u200Bx@evasion.test"
        payload = {"email": evasion_email}
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload["email"].startswith("⟦EMAIL_"))

    def test_adv_02_zero_width_non_joiner_in_phone(self):
        evasion_phone = "+1\u200C-\u200C555\u200C-\u200C123\u200C-\u200C4567"
        payload = {"phone": evasion_phone}
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload["phone"].startswith("⟦PHONE_"))

    def test_adv_03_zero_width_joiner_in_ssn(self):
        evasion_ssn = "123\u200D-\u200D45\u200D-\u200D6789"
        payload = {"ssn": evasion_ssn}
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload["ssn"].startswith("⟦SSN_"))

    def test_adv_04_byte_order_mark_in_credit_card(self):
        evasion_card = "4111\uFEFF-\uFEFF1111\uFEFF-\uFEFF1111\uFEFF-\uFEFF1111"
        payload = {"card": evasion_card}
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload["card"].startswith("⟦CREDIT_CARD_"))

    def test_adv_05_soft_hyphen_in_pan(self):
        evasion_pan = "ABC\u00ADPE12\u00AD34F"
        payload = {"pan": evasion_pan}
        res, _ = self.firewall.intercept_request(payload)
        self.assertTrue(res.sanitized_payload["pan"].startswith("⟦PAN_CARD_"))

    def test_adv_06_base64_encoded_email_detected_and_tokenized(self):
        raw_email = "stealth.agent@classified.gov"
        b64_str = base64.b64encode(raw_email.encode("utf-8")).decode("utf-8")
        payload = {"encoded_data": f"Forward to {b64_str} urgently."}
        res, _ = self.firewall.intercept_request(payload)
        self.assertNotIn(b64_str, res.sanitized_payload["encoded_data"])
        self.assertIn("⟦EMAIL_", res.sanitized_payload["encoded_data"])

    def test_adv_07_base64_encoded_api_key_detected(self):
        raw_key = "AKIAIOSFODNN7EXAMPLE"
        b64_str = base64.b64encode(raw_key.encode("utf-8")).decode("utf-8")
        payload = {"secret": f"AWS credentials: {b64_str}"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertNotIn(b64_str, res.sanitized_payload["secret"])
        self.assertIn("⟦API_KEY_", res.sanitized_payload["secret"])

    def test_adv_08_base64_encoded_ssn_detected(self):
        raw_ssn = "123-45-6789"
        b64_str = base64.b64encode(raw_ssn.encode("utf-8")).decode("utf-8")
        payload = {"identity": f"Verify SSN {b64_str} now."}
        res, _ = self.firewall.intercept_request(payload)
        self.assertNotIn(b64_str, res.sanitized_payload["identity"])
        self.assertIn("⟦SSN_", res.sanitized_payload["identity"])

    def test_adv_09_base64_encoded_card_detected(self):
        raw_card = "4111-1111-1111-1111"
        b64_str = base64.b64encode(raw_card.encode("utf-8")).decode("utf-8")
        payload = {"payment": f"Debit {b64_str}"}
        res, _ = self.firewall.intercept_request(payload)
        self.assertNotIn(b64_str, res.sanitized_payload["payment"])
        self.assertIn("⟦CREDIT_CARD_", res.sanitized_payload["payment"])

    def test_adv_10_delimiter_smuggling_fake_tokens(self):
        spoofed = "User input contains ⟦EMAIL_malicious_fake_token⟧ in field."
        sanitized = AdversarialDefenseNormalizer.sanitize_delimiters(spoofed)
        self.assertNotIn("⟦", sanitized)
        self.assertIn("[PRE_EXISTING_DELIM_L_", sanitized)

    def test_adv_11_delimiter_smuggling_lone_brackets(self):
        lone = "Unbalanced ⟦ prefix and ⟧ suffix."
        sanitized = AdversarialDefenseNormalizer.sanitize_delimiters(lone)
        self.assertNotIn("⟦", sanitized)
        self.assertNotIn("⟧", sanitized)

    def test_adv_12_policy_engine_block_tool_raises_exception(self):
        policy = PolicyEngine()
        policy.add_rule(ToolPolicyRule(tool_name="untrusted_vendor", blocked_pii_types={PIIType.SSN}))
        strict_fw = PIIFirewall(policy_engine=policy)
        payload = {"tool": "untrusted_vendor", "ssn": "123-45-6789"}
        with self.assertRaises(FirewallBlockedError):
            strict_fw.intercept_request(payload)

    def test_adv_13_policy_engine_redact_action(self):
        policy = PolicyEngine()
        policy.add_rule(ToolPolicyRule(tool_name="public_analytics", pii_actions={PIIType.EMAIL: PolicyAction.REDACT}))
        redacting_fw = PIIFirewall(policy_engine=policy)
        payload = {"tool": "public_analytics", "email": "redact.me@example.test"}
        res, _ = redacting_fw.intercept_request(payload)
        self.assertEqual(res.sanitized_payload["email"], "[REDACTED_EMAIL]")

    def test_adv_14_policy_engine_mask_action(self):
        policy = PolicyEngine()
        policy.add_rule(ToolPolicyRule(tool_name="masked_log", pii_actions={PIIType.CREDIT_CARD: PolicyAction.MASK}))
        masking_fw = PIIFirewall(policy_engine=policy)
        payload = {"tool": "masked_log", "card": "4111-1111-1111-1111"}
        res, _ = masking_fw.intercept_request(payload)
        self.assertEqual(res.sanitized_payload["card"], "****-****-****-1111")

    def test_adv_15_policy_engine_whitelist_field_pass_through(self):
        policy = PolicyEngine()
        policy.add_rule(ToolPolicyRule(tool_name="internal_auth", whitelisted_fields={"authorized_email"}))
        whitelisting_fw = PIIFirewall(policy_engine=policy)
        payload = {
            "tool": "internal_auth",
            "authorized_email": "admin@internal.corp",
            "external_email": "partner@vendor.org"
        }
        res, _ = whitelisting_fw.intercept_request(payload)
        self.assertEqual(res.sanitized_payload["authorized_email"], "admin@internal.corp")
        self.assertTrue(res.sanitized_payload["external_email"].startswith("⟦EMAIL_"))

    def test_adv_16_leakage_verifier_blocks_residual_pii(self):
        vault = RequestTokenVault()
        vault.get_or_create_token("leakage.target@corp.internal", PIIType.EMAIL)
        leaky_payload = {"user": "⟦EMAIL_token⟧", "leak": "leakage.target@corp.internal"}
        with self.assertRaises(PIILeakageDetectedError):
            LeakageVerifier.verify(leaky_payload, vault, fail_safe_strict=True)

    def test_adv_17_leakage_verifier_passes_clean_payload(self):
        vault = RequestTokenVault()
        vault.get_or_create_token("clean.target@corp.internal", PIIType.EMAIL)
        clean_payload = {"user": "⟦EMAIL_token⟧", "status": "APPROVED"}
        is_safe, leaks = LeakageVerifier.verify(clean_payload, vault, fail_safe_strict=True)
        self.assertTrue(is_safe)
        self.assertEqual(leaks, [])

    def test_adv_18_audit_logger_records_safe_events_no_raw_pii(self):
        logger = AuditLogger()
        entry = logger.record_event(
            request_id="req-synthetic-01",
            tool_name="crm_tool",
            action="SANITIZED_AND_FORWARDED",
            counts_by_type={"EMAIL": 1, "PHONE": 1},
            duration_ms=0.45,
            verification_passed=True,
            sanitized_payload={"email": "⟦EMAIL_123⟧", "phone": "⟦PHONE_456⟧"}
        )
        self.assertNotIn("alex.demo@example.test", str(entry))
        self.assertTrue(len(entry["sanitized_payload_sha256"]) == 64)
        self.assertEqual(entry["total_entities_secured"], 2)


if __name__ == "__main__":
    unittest.main()
