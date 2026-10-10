"""
Multi-Type Payload Acceptance & Verification Test Suite.
Tests and verifies simultaneous detection, tokenization, JSON syntax preservation,
and sentence structure integrity across:
1. Deeply nested structured JSON payloads (primitives, arrays, nulls, booleans, nested depths).
2. Free-text / Natural language prompts with 3+, 4+, 5+, and 7+ distinct PII types.
3. Heterogeneous payloads combining Personal Info, Credentials, and Identity Records
   under both authorized tokenization policies and fail-closed strict security controls.
"""

import copy
import json
import os
import sys
import unittest
from pathlib import Path

# Ensure UTF-8 output on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

os.environ["GEMINI_UNIT_TEST_MODE"] = "1"

# Ensure backend directory in sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallConfig,
    FirewallBlockedError,
    PIILeakageDetectedError,
    PIIType,
    SensitivityCategory,
)
from pii_firewall.policy import PolicyAction, PolicyEngine, ToolPolicyRule
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestStructuredMultiTypePayloads(unittest.TestCase):
    """
    Evaluates deeply nested JSON payloads containing arrays, numeric fields,
    boolean flags, nulls, and multiple sensitive fields at various nesting depths.
    """

    def setUp(self):
        self.firewall = PIIFirewall()
        self.simulated_tool = SimulatedExternalTool("data_processor")

    def test_deeply_nested_json_primitives_and_multiple_pii(self):
        """
        Validates deeply nested JSON (6 levels deep) with arrays, integers, floats,
        booleans, null values, and 10+ distinct sensitive fields.
        """
        payload = {
            "request_metadata": {
                "transaction_id": 984021,
                "is_production": True,
                "debug_mode": False,
                "error_rate": 0.0,
                "latency_budget_ms": 125.75,
                "notes": None,
                "tags": ["tier-1", "pci-dss", "audit-ready"],
            },
            "system_infrastructure": {
                "primary_gateway": "192.168.1.100",  # IP_ADDRESS (depth 2)
                "backup_gateway": "10.0.0.45",       # IP_ADDRESS (depth 2)
                "cluster_admins": [
                    {
                        "region": "us-east-1",
                        "admin_email": "sysadmin.us@cybercorp.internal",  # EMAIL (depth 3)
                        "phone_contact": "+1-800-555-0199",              # PHONE (depth 3)
                    },
                    {
                        "region": "ap-south-1",
                        "admin_email": "ops.india@cybercorp.internal",    # EMAIL (depth 3)
                        "phone_contact": "+91 98765 43210",              # PHONE (depth 3)
                    }
                ],
            },
            "enterprise_organization": {
                "billing_vault": {
                    "primary_corporate_card": "4111-1111-1111-1111",     # CREDIT_CARD (depth 3)
                    "tax_compliance": {
                        "us_tax_ssn": "123-45-6789",                     # SSN (depth 4)
                        "in_corporate_pan": "ABCPE1234F",                # PAN_CARD (depth 4)
                        "identity_registry": {
                            "subjects": [                                # depth 5
                                {
                                    "record_index": 0,
                                    "is_active": True,
                                    "flags": [True, False, None],
                                    "score": 99.4,
                                    "holder_profile": {                  # depth 6
                                        "name_note": "Record for Alice Johnson",  # PERSON_NAME
                                        "dob_record": "DOB: 1982-07-15",          # DATE_OF_BIRTH
                                        "aadhaar_num": "3675 9834 6016",          # AADHAAR
                                        "passport_doc": "Passport: Z12345678",    # PASSPORT
                                        "license_id": "Driver's license: DL-998877665", # DRIVERS_LICENSE
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }

        # Keep raw planted sensitive strings for leak verification
        raw_sensitive_values = [
            "192.168.1.100",
            "10.0.0.45",
            "sysadmin.us@cybercorp.internal",
            "+1-800-555-0199",
            "ops.india@cybercorp.internal",
            "+91 98765 43210",
            "4111-1111-1111-1111",
            "123-45-6789",
            "ABCPE1234F",
            "Alice Johnson",
            "1982-07-15",
            "3675 9834 6016",
            "Z12345678",
            "DL-998877665",
        ]

        # 1. Process payload through firewall
        result = self.firewall.process_tool_call(
            request_payload=payload,
            tool_callable=self.simulated_tool.execute,
        )

        # 2. Verify simulated tool received sanitized payload
        tool_received = self.simulated_tool.received_payloads[-1]

        # 3. Assert zero leakage in forwarded payload
        for sensitive_val in raw_sensitive_values:
            self.assertNotIn(
                sensitive_val,
                json.dumps(tool_received),
                f"Leak detected! Raw sensitive value '{sensitive_val}' was found in tool payload."
            )

        # 4. Assert JSON Syntax and Structure Preservation
        # Re-encode and decode to confirm 100% valid JSON syntax
        json_str = json.dumps(tool_received)
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)

        # Verify exact preservation of primitive types and values
        meta = parsed["request_metadata"]
        self.assertEqual(meta["transaction_id"], 984021)
        self.assertIs(meta["is_production"], True)
        self.assertIs(meta["debug_mode"], False)
        self.assertEqual(meta["error_rate"], 0.0)
        self.assertEqual(meta["latency_budget_ms"], 125.75)
        self.assertIsNone(meta["notes"])
        self.assertEqual(meta["tags"], ["tier-1", "pci-dss", "audit-ready"])

        # Verify deeply nested flags and arrays
        subject0 = parsed["enterprise_organization"]["billing_vault"]["tax_compliance"]["identity_registry"]["subjects"][0]
        self.assertEqual(subject0["record_index"], 0)
        self.assertIs(subject0["is_active"], True)
        self.assertEqual(subject0["flags"], [True, False, None])
        self.assertEqual(subject0["score"], 99.4)

        # 5. Verify all tokens are well-formed opaque tokens
        profile = subject0["holder_profile"]
        self.assertTrue(profile["name_note"].startswith("Record for ⟦PERSON_NAME_"))
        self.assertTrue(profile["dob_record"].startswith("DOB: ⟦DATE_OF_BIRTH_"))
        self.assertTrue(profile["aadhaar_num"].startswith("⟦AADHAAR_"))
        self.assertTrue(profile["passport_doc"].startswith("Passport: ⟦PASSPORT_"))
        self.assertTrue(profile["license_id"].startswith("Driver's license: ⟦DRIVERS_LICENSE_"))

        # 6. Verify metrics detection
        metrics = result["metrics"]
        counts = metrics["counts_by_type"]
        self.assertEqual(counts.get("IP_ADDRESS"), 2)
        self.assertEqual(counts.get("EMAIL"), 2)
        self.assertEqual(counts.get("PHONE"), 2)
        self.assertEqual(counts.get("CREDIT_CARD"), 1)
        self.assertEqual(counts.get("SSN"), 1)
        self.assertEqual(counts.get("PAN_CARD"), 1)
        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("DATE_OF_BIRTH"), 1)
        self.assertEqual(counts.get("AADHAAR"), 1)
        self.assertEqual(counts.get("PASSPORT"), 1)
        self.assertEqual(counts.get("DRIVERS_LICENSE"), 1)
        self.assertEqual(metrics["total_detected"], 14)
        self.assertTrue(metrics["verification_passed"])

        # 7. Validate round-trip response restoration fidelity
        restored = result["response"]["echo_arguments"]
        self.assertEqual(restored, payload, "Restoration must exactly match original nested payload")

    def test_token_consistency_in_nested_structures(self):
        """
        Validates that repeated occurrences of the same PII value across different
        nesting depths map to the exact same opaque token.
        """
        repeated_email = "compliance.officer@domain.test"
        repeated_phone = "+1-555-987-6543"

        payload = {
            "department": "Security",
            "lead": {
                "email": repeated_email,
                "phone": repeated_phone,
            },
            "contact_list": [
                {"role": "Primary Escalation", "target_email": repeated_email},
                {"role": "SMS Escalation", "target_phone": repeated_phone},
            ],
            "footer_note": f"In emergency, email {repeated_email} or call {repeated_phone}.",
        }

        res, vault = self.firewall.intercept_request(payload)
        sanitized = res.sanitized_payload

        tok_email_1 = sanitized["lead"]["email"]
        tok_email_2 = sanitized["contact_list"][0]["target_email"]
        tok_phone_1 = sanitized["lead"]["phone"]
        tok_phone_2 = sanitized["contact_list"][1]["target_phone"]

        # Tokens must be identical for identical raw values
        self.assertEqual(tok_email_1, tok_email_2)
        self.assertEqual(tok_phone_1, tok_phone_2)
        self.assertIn(tok_email_1, sanitized["footer_note"])
        self.assertIn(tok_phone_1, sanitized["footer_note"])

        # Exactly 2 unique tokens stored in the vault
        self.assertEqual(vault.get_token_count(), 2)

        # Full round-trip restoration
        restored, _ = self.firewall.intercept_response(sanitized, request_id=res.metrics.request_id)
        self.assertEqual(restored, payload)

    def test_json_syntax_integrity_with_special_characters(self):
        """
        Validates that JSON structures with quotes, brackets, slashes, and special characters
        are tokenized without breaking JSON grammar.
        """
        payload = {
            "query": "Find records with email \"alex.doe@example.com\" and phone '+1-555-123-4567'",
            "regex_filter": "^[a-z0-9]+\\/api\\/v1",
            "nested_list": [
                {"bracket_test": "[user: alex.doe@example.com]"},
                {"escape_test": "line1\nline2\ttabbed email: alex.doe@example.com"}
            ]
        }

        res, vault = self.firewall.intercept_request(payload)
        sanitized = res.sanitized_payload

        # Ensure json.dumps produces valid JSON that parses back
        json_dump = json.dumps(sanitized)
        reparsed = json.loads(json_dump)
        self.assertIsInstance(reparsed, dict)
        self.assertNotIn("alex.doe@example.com", json_dump)
        self.assertNotIn("+1-555-123-4567", json_dump)

        # Round trip
        restored, _ = self.firewall.intercept_response(sanitized, request_id=res.metrics.request_id)
        self.assertEqual(restored, payload)


class TestNaturalLanguageMultiPIIPrompts(unittest.TestCase):
    """
    Evaluates free-text prompts combining 3+, 4+, and 5+ distinct entity types.
    Validates sentence structure, punctuation, and contextual boundaries.
    """

    def setUp(self):
        self.firewall = PIIFirewall()

    def test_benchmark_customer_onboarding_4_pii(self):
        """
        Evaluates the user's exact hackathon benchmark prompt combining 4 distinct PII types:
        Person Name, SSN, DOB, and Driver's License.
        """
        prompt = (
            "Please process the customer onboarding profile for John Michael Doe "
            "(SSN: 123-45-6789, DOB: 1985-04-12, Driver's License: DL-987654321)"
        )
        payload = {"tool": "onboarding_service", "arguments": {"query": prompt}}

        res, vault = self.firewall.intercept_request(payload)

        # 1. Assert detection of all 4 types
        counts = res.metrics.counts_by_type
        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("SSN"), 1)
        self.assertEqual(counts.get("DATE_OF_BIRTH"), 1)
        self.assertEqual(counts.get("DRIVERS_LICENSE"), 1)
        self.assertEqual(res.metrics.total_detected, 4)

        sanitized_query = res.sanitized_payload["arguments"]["query"]

        # 2. Assert zero raw PII leakage
        self.assertNotIn("John Michael Doe", sanitized_query)
        self.assertNotIn("123-45-6789", sanitized_query)
        self.assertNotIn("1985-04-12", sanitized_query)
        self.assertNotIn("DL-987654321", sanitized_query)

        # 3. Assert surrounding sentence structure and punctuation are fully preserved
        self.assertTrue(
            sanitized_query.startswith("Please process the customer onboarding profile for ⟦PERSON_NAME_"),
            f"Sentence prefix corrupted: {sanitized_query}"
        )
        self.assertIn(" (SSN: ⟦SSN_", sanitized_query)
        self.assertIn(", DOB: ⟦DATE_OF_BIRTH_", sanitized_query)
        self.assertIn(", Driver's License: ⟦DRIVERS_LICENSE_", sanitized_query)
        self.assertTrue(sanitized_query.endswith("⟧)"), f"Sentence suffix corrupted: {sanitized_query}")

        # 4. Round-trip restoration exact match
        restored, _ = self.firewall.intercept_response(
            res.sanitized_payload,
            request_id=res.metrics.request_id
        )
        self.assertEqual(restored["arguments"]["query"], prompt)

    def test_customer_onboarding_expanded_6_pii(self):
        """
        Evaluates an expanded onboarding prompt combining 6 distinct PII entities:
        Person Name, SSN, DOB, Driver's License, Email, and Phone Number.
        """
        prompt = (
            "Please process the customer onboarding profile for John Michael Doe "
            "(SSN: 123-45-6789, DOB: 1985-04-12, Driver's License: DL-987654321, "
            "Email: john.doe@cybercorp.com, Phone: +1-555-839-2019)"
        )
        payload = {"tool": "onboarding_service", "arguments": {"query": prompt}}

        res, vault = self.firewall.intercept_request(payload)
        counts = res.metrics.counts_by_type

        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("SSN"), 1)
        self.assertEqual(counts.get("DATE_OF_BIRTH"), 1)
        self.assertEqual(counts.get("DRIVERS_LICENSE"), 1)
        self.assertEqual(counts.get("EMAIL"), 1)
        self.assertEqual(counts.get("PHONE"), 1)
        self.assertEqual(res.metrics.total_detected, 6)

        sanitized_query = res.sanitized_payload["arguments"]["query"]

        # Assert no sensitive data remains
        for pii in ["John Michael Doe", "123-45-6789", "1985-04-12", "DL-987654321", "john.doe@cybercorp.com", "+1-555-839-2019"]:
            self.assertNotIn(pii, sanitized_query)

        # Sentence structure check
        self.assertIn("Email: ⟦EMAIL_", sanitized_query)
        self.assertIn("Phone: ⟦PHONE_", sanitized_query)
        self.assertTrue(sanitized_query.endswith("⟧)"))

        # Exact round-trip restoration
        restored, _ = self.firewall.intercept_response(
            res.sanitized_payload,
            request_id=res.metrics.request_id
        )
        self.assertEqual(restored["arguments"]["query"], prompt)

    def test_kyc_and_international_identity_7_pii(self):
        """
        Evaluates an international KYC travel prompt combining 7 distinct PII types:
        Person Name, DOB, Passport, Indian PAN, Aadhaar, Email, and Phone.
        """
        prompt = (
            "Please verify the customer onboarding profile for Sarah Connor "
            "(DOB: 1965-11-10, Passport: P98765432, PAN card ABCPE1234F, "
            "Aadhaar: 3675 9834 6016, email: sarah.c@resistance.org, phone: +1-800-555-0199)"
        )
        payload = {"tool": "kyc_verifier", "arguments": {"instruction": prompt}}

        res, vault = self.firewall.intercept_request(payload)
        counts = res.metrics.counts_by_type

        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("DATE_OF_BIRTH"), 1)
        self.assertEqual(counts.get("PASSPORT"), 1)
        self.assertEqual(counts.get("PAN_CARD"), 1)
        self.assertEqual(counts.get("AADHAAR"), 1)
        self.assertEqual(counts.get("EMAIL"), 1)
        self.assertEqual(counts.get("PHONE"), 1)
        self.assertEqual(res.metrics.total_detected, 7)

        sanitized_text = res.sanitized_payload["arguments"]["instruction"]

        # Assert zero leaks
        for val in ["Sarah Connor", "1965-11-10", "P98765432", "ABCPE1234F", "3675 9834 6016", "sarah.c@resistance.org", "+1-800-555-0199"]:
            self.assertNotIn(val, sanitized_text)

        # Punctuation structure verification
        self.assertIn("Passport: ⟦PASSPORT_", sanitized_text)
        self.assertIn("PAN card ⟦PAN_CARD_", sanitized_text)
        self.assertIn("Aadhaar: ⟦AADHAAR_", sanitized_text)

        # Full round trip
        restored, _ = self.firewall.intercept_response(
            res.sanitized_payload,
            request_id=res.metrics.request_id
        )
        self.assertEqual(restored["arguments"]["instruction"], prompt)

    def test_financial_support_escalation_5_pii(self):
        """
        Evaluates a financial escalation prompt with 5 distinct PII types:
        Person Name, SSN, Credit Card (Luhn valid), IP Address, and DOB.
        """
        prompt = (
            "Escalation request: customer name: Robert Michael Davis with SSN 456-78-9012, "
            "credit card 4111-1111-1111-1111, IP address 192.168.1.100, DOB: 1978-03-25."
        )
        payload = {"tool": "support_agent", "arguments": {"ticket": prompt}}

        res, vault = self.firewall.intercept_request(payload)
        counts = res.metrics.counts_by_type

        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("SSN"), 1)
        self.assertEqual(counts.get("CREDIT_CARD"), 1)
        self.assertEqual(counts.get("IP_ADDRESS"), 1)
        self.assertEqual(counts.get("DATE_OF_BIRTH"), 1)
        self.assertEqual(res.metrics.total_detected, 5)

        sanitized_ticket = res.sanitized_payload["arguments"]["ticket"]
        self.assertTrue(sanitized_ticket.endswith("."))

        restored, _ = self.firewall.intercept_response(
            res.sanitized_payload,
            request_id=res.metrics.request_id
        )
        self.assertEqual(restored["arguments"]["ticket"], prompt)


class TestHeterogeneousPayloads(unittest.TestCase):
    """
    Evaluates heterogeneous payloads containing personal information alongside
    credentials (API Key, Passwords) and national identity records (PAN, Aadhaar, Passport).
    Verifies behavior under both authorized tokenization policies and fail-closed security.
    """

    def setUp(self):
        self.simulated_tool = SimulatedExternalTool("secure_vault_service")

    def test_heterogeneous_prompt_tokenization_authorized(self):
        """
        Validates simultaneous tokenization of Personal Info + Credentials + Identity Records
        when sending to an authorized destination with full tokenization permissions.
        """
        policy = PolicyEngine(
            default_action=PolicyAction.TOKENIZE,
            destination_allowlists={
                SensitivityCategory.CREDENTIAL: {"*"},
                SensitivityCategory.PERSONAL_INFO: {"*"},
                SensitivityCategory.BUSINESS_CONFIDENTIAL: {"*"},
            }
        )
        fw = PIIFirewall(policy_engine=policy)

        prompt = (
            "Customer onboarding profile for Alice Smith (email: alice.smith@enterprise.org, "
            "phone: +1-555-234-5678, PAN: ABCPE1234F, Aadhaar: 3675 9834 6016, Passport: P98765432) "
            "authorized service using API Key: sk-proj-1234567890abcdef1234567890abcdef123456 "
            "and master login password is MySecretPass123!"
        )
        payload = {"tool": "secure_vault_service", "arguments": {"data": prompt}}

        res, vault = fw.intercept_request(payload)
        counts = res.metrics.counts_by_type

        # Assert simultaneous detection across all 3 tiers
        # Personal info:
        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("EMAIL"), 1)
        self.assertEqual(counts.get("PHONE"), 1)
        # Identity records:
        self.assertEqual(counts.get("PAN_CARD"), 1)
        self.assertEqual(counts.get("AADHAAR"), 1)
        self.assertEqual(counts.get("PASSPORT"), 1)
        # Credentials:
        self.assertEqual(counts.get("API_KEY"), 1)
        self.assertEqual(counts.get("PASSWORD"), 1)
        self.assertEqual(res.metrics.total_detected, 8)

        sanitized_data = res.sanitized_payload["arguments"]["data"]

        # Ensure NO raw personal info, identity records, or credentials remain
        raw_items = [
            "Alice Smith", "alice.smith@enterprise.org", "+1-555-234-5678",
            "ABCPE1234F", "3675 9834 6016", "P98765432",
            "sk-proj-1234567890abcdef1234567890abcdef123456", "MySecretPass123!"
        ]
        for item in raw_items:
            self.assertNotIn(item, sanitized_data, f"Leaked: {item}")

        # Ensure tokens are generated for each type
        self.assertIn("⟦PERSON_NAME_", sanitized_data)
        self.assertIn("⟦EMAIL_", sanitized_data)
        self.assertIn("⟦PHONE_", sanitized_data)
        self.assertIn("⟦PAN_CARD_", sanitized_data)
        self.assertIn("⟦AADHAAR_", sanitized_data)
        self.assertIn("⟦PASSPORT_", sanitized_data)
        self.assertIn("⟦API_KEY_", sanitized_data)
        self.assertIn("⟦PASSWORD_", sanitized_data)

        # Full round-trip restoration
        restored, _ = fw.intercept_response(
            res.sanitized_payload,
            request_id=res.metrics.request_id
        )
        self.assertEqual(restored["arguments"]["data"], prompt)

    def test_heterogeneous_prompt_strict_blocking_unauthorized(self):
        """
        Validates Principle A (Block Credentials by Default): When a heterogeneous prompt
        containing credentials (Password / API Key) is sent to an unauthorized external tool,
        the firewall strictly blocks the tool request and never executes the external tool.
        """
        fw = PIIFirewall()  # Default strict policy: credentials blocked across unauthorized boundaries

        prompt = (
            "Customer onboarding profile for Alice Smith (email: alice.smith@enterprise.org, "
            "phone: +1-555-234-5678, PAN: ABCPE1234F) "
            "and account password is MySecretPass123!"
        )
        payload = {"tool": "unauthorized_external_service", "arguments": {"data": prompt}}

        with self.assertRaises(FirewallBlockedError) as ctx:
            fw.process_tool_call(payload, self.simulated_tool.execute)

        err_msg = str(ctx.exception)
        # Blocked message should state policy violation without revealing secrets
        self.assertIn("strictly prohibited", err_msg)
        self.assertNotIn("MySecretPass123!", err_msg)

        # Tool was NEVER called
        self.assertEqual(len(self.simulated_tool.received_payloads), 0)

    def test_heterogeneous_structured_json_authorized_and_blocked(self):
        """
        Validates heterogeneous structured JSON containing distinct blocks for
        Personal Info, Identity Records, and Credentials.
        """
        hetero_json = {
            "session_id": "sess_88392",
            "personal_info": {
                "name_note": "Record for David Vance",
                "email": "david.vance@company.test",
                "contact_phone": "+1-555-321-7654",
            },
            "identity_records": {
                "pan_number": "ABCPE1234F",
                "aadhaar_number": "3675 9834 6016",
                "passport_number": "Passport: P98765432",
            },
            "system_credentials": {
                "api_access_token": "sk-proj-abcdef1234567890abcdef1234567890123456",
                "db_secret": "password is SuperSecretDatabaseKey99!",
            }
        }

        # 1. Test with authorized credential destination
        policy_auth = PolicyEngine(
            default_action=PolicyAction.TOKENIZE,
            destination_allowlists={
                SensitivityCategory.CREDENTIAL: {"*"},
                SensitivityCategory.PERSONAL_INFO: {"*"},
                SensitivityCategory.BUSINESS_CONFIDENTIAL: {"*"},
            }
        )
        fw_auth = PIIFirewall(policy_engine=policy_auth)

        res, vault = fw_auth.intercept_request(hetero_json)
        counts = res.metrics.counts_by_type

        self.assertEqual(counts.get("PERSON_NAME"), 1)
        self.assertEqual(counts.get("EMAIL"), 1)
        self.assertEqual(counts.get("PHONE"), 1)
        self.assertEqual(counts.get("PAN_CARD"), 1)
        self.assertEqual(counts.get("AADHAAR"), 1)
        self.assertEqual(counts.get("PASSPORT"), 1)
        self.assertEqual(counts.get("API_KEY"), 1)
        self.assertEqual(counts.get("PASSWORD"), 1)
        self.assertEqual(res.metrics.total_detected, 8)

        # Confirm JSON syntax and round trip
        sanitized_dump = json.dumps(res.sanitized_payload)
        reparsed = json.loads(sanitized_dump)
        self.assertIsInstance(reparsed, dict)

        restored, _ = fw_auth.intercept_response(res.sanitized_payload, request_id=res.metrics.request_id)
        self.assertEqual(restored, hetero_json)

        # 2. Test with default strict firewall -> Must block due to credentials
        fw_strict = PIIFirewall()
        with self.assertRaises(FirewallBlockedError):
            fw_strict.intercept_request(
                {"tool": "external_analytics_tool", "arguments": hetero_json}
            )


def run_multi_type_suite_with_report():
    """Executes the test suite and prints a detailed verification report."""
    print("=" * 78)
    print("  🛡️  AGENT 5: MULTI-TYPE PAYLOAD SPECIALIST — VERIFICATION SUITE")
    print("=" * 78)
    print("Testing multi-PII detection, tokenization, JSON syntax preservation,")
    print("and sentence structure integrity across structured & natural language payloads.")
    print("-" * 78)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestStructuredMultiTypePayloads))
    suite.addTests(loader.loadTestsFromTestCase(TestNaturalLanguageMultiPIIPrompts))
    suite.addTests(loader.loadTestsFromTestCase(TestHeterogeneousPayloads))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 78)
    print("  📊 VERIFICATION SUITE EXECUTION SUMMARY")
    print("=" * 78)
    print(f"Total Test Cases Executed:    {result.testsRun}")
    print(f"Passed:                       {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures:                     {len(result.failures)}")
    print(f"Errors:                       {len(result.errors)}")
    pass_pct = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100.0) if result.testsRun else 0.0
    print(f"Pass Rate:                    {pass_pct:.1f}%")
    print("=" * 78)

    if result.wasSuccessful():
        print("✅ ALL MULTI-TYPE PAYLOAD TESTS PASSED CLEANLY (100% SUCCESS)")
        return 0
    else:
        print("❌ SOME MULTI-TYPE PAYLOAD TESTS FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_multi_type_suite_with_report()
    sys.exit(exit_code)
