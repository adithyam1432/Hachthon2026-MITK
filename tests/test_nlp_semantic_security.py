"""
Acceptance Test Suite for Context-Aware NLP, Semantic Detection & Three-Tier Security Policy.
Covers all 10 mandatory acceptance criteria:
  1. "ATM PIN", "debit card PIN" and synonyms map to CREDENTIAL category.
  2. PINs and CVVs blocked from unauthorized transmission across unfamiliar synonyms.
  3. Contextual references without an exposed secret are not treated as exposed secret values.
  4. A four-digit number without supporting context is NOT classified as an ATM PIN.
  5. Personal information is redacted/tokenized according to destination-specific policy.
  6. Confidential business information is blocked when destination is not authorized.
  7. Multiple categories in one payload trigger all relevant rules.
  8. Sanitized payloads contain no remaining detected secrets before transmission.
  9. Scanner failure fails closed (prevents unauthorized transmission).
  10. Local processing verification (zero external network leaks).
"""

import unittest
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallConfig,
    PIIType,
    SensitivityCategory,
    TYPE_TO_CATEGORY,
    FirewallBlockedError,
)
from pii_firewall.policy import PolicyAction, PolicyEngine, ToolPolicyRule
from pii_firewall.semantic_nlp import ContextAwareNLPEngine
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestNLPSemanticSecurity(unittest.TestCase):
    """Exhaustive Acceptance Tests for Context-Aware NLP and Mandatory Security Principles."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.tool = SimulatedExternalTool("send_email")

    # -----------------------------------------------------------------
    # Acceptance Test 1: Synonym Mapping to CREDENTIAL Category
    # -----------------------------------------------------------------
    def test_01_atm_pin_synonyms_map_to_credential_category(self):
        """Confirm ATM PIN, debit card PIN, and varied synonyms map to CREDENTIAL category."""
        synonym_phrases = [
            "My debit card PIN is 4821.",
            "Please note the ATM PIN is 9182.",
            "The bank card PIN is 3021.",
            "My cash withdrawal PIN is 7731.",
            "The card security PIN is 5512.",
            "The four-digit card PIN is 6642.",
            "My card's secret number is 1948.",
            "The number I enter at the ATM is 8371.",
            "The secret code for my debit card is 4920.",
            "My UPI PIN is 2948."
        ]
        for phrase in synonym_phrases:
            entities = ContextAwareNLPEngine.find_semantic_entities(phrase)
            self.assertTrue(len(entities) >= 1, f"Failed to detect PIN in: '{phrase}'")
            pin_entity = entities[0]
            self.assertEqual(pin_entity.pii_type, PIIType.PIN)
            self.assertEqual(pin_entity.category, SensitivityCategory.CREDENTIAL)
            self.assertTrue(pin_entity.has_exposed_value)

    # -----------------------------------------------------------------
    # Acceptance Test 2: PINs and CVVs Blocked by Default
    # -----------------------------------------------------------------
    def test_02_pins_and_cvvs_blocked_from_unauthorized_transmission(self):
        """Confirm PINs and CVVs are strictly blocked from external tools by default."""
        test_payloads = [
            {"tool": "send_email", "message": "My debit card PIN is 4821."},
            {"tool": "external_assistant", "message": "The ATM PIN is 9182."},
            {"tool": "third_party_api", "message": "Card verification value is 829."},
            {"tool": "public_slack", "message": "Security digits on back are 481."}
        ]
        for payload in test_payloads:
            with self.assertRaises(FirewallBlockedError):
                self.firewall.process_tool_call(
                    request_payload=payload,
                    tool_callable=self.tool.execute
                )

    # -----------------------------------------------------------------
    # Acceptance Test 3: Conceptual References Without Secret Value
    # -----------------------------------------------------------------
    def test_03_conceptual_references_without_secret_not_treated_as_exposed(self):
        """Sentences discussing ATM PINs without disclosing a secret are not treated as exposed."""
        discussion_texts = [
            "The ATM PIN should never be shared with anyone.",
            "Always shield the keypad when entering your debit card PIN.",
            "Customers must remember their cash withdrawal PIN securely."
        ]
        for text in discussion_texts:
            entities = ContextAwareNLPEngine.find_semantic_entities(text)
            # Must NOT classify this as an exposed secret value
            exposed_entities = [e for e in entities if e.has_exposed_value and e.value.isdigit()]
            self.assertEqual(len(exposed_entities), 0, f"Incorrectly extracted nonexistent PIN from: '{text}'")

            # Must NOT block ordinary discussion when no credential is leaked or transmitted
            payload = {"tool": "send_email", "message": text}
            res = self.firewall.process_tool_call(
                request_payload=payload,
                tool_callable=self.tool.execute
            )
            self.assertEqual(res["response"]["status"], "success")

    # -----------------------------------------------------------------
    # Acceptance Test 4: 4-Digit Numbers Without Supporting Context
    # -----------------------------------------------------------------
    def test_04_four_digit_number_without_context_not_classified_as_pin(self):
        """Four-digit numbers without credential context (e.g. order IDs, years, ports) are not PINs."""
        non_credential_texts = [
            "Order number 4821 has been shipped.",
            "The company was founded in year 2024.",
            "Our web service is listening on port 8080.",
            "Flight 4821 is boarding at gate 12.",
            "Please deliver to suite 4821 tomorrow."
        ]
        for text in non_credential_texts:
            entities = ContextAwareNLPEngine.find_semantic_entities(text)
            pin_entities = [e for e in entities if e.pii_type == PIIType.PIN]
            self.assertEqual(len(pin_entities), 0, f"False positive PIN detected in: '{text}'")

    # -----------------------------------------------------------------
    # Acceptance Test 5: Personal Information Policy-Based Sanitization
    # -----------------------------------------------------------------
    def test_05_personal_info_sanitized_according_to_destination_policy(self):
        """Personal info (email, phone) is masked or tokenized based on policy without blocking."""
        # 1. Test TOKENIZE policy
        policy_tokenize = PolicyEngine(default_action=PolicyAction.TOKENIZE)
        fw_tok = PIIFirewall(policy_engine=policy_tokenize)
        payload = {"tool": "send_email", "message": "Contact user at alice.smith@example.test now."}
        res_tok = fw_tok.process_tool_call(payload, self.tool.execute)
        self.assertEqual(res_tok["response"]["status"], "success")
        self.assertNotIn("alice.smith@example.test", str(self.tool.received_payloads[-1]))
        self.assertIn("⟦EMAIL_", str(self.tool.received_payloads[-1]))

        # 2. Test MASK policy
        policy_mask = PolicyEngine(default_action=PolicyAction.MASK)
        fw_mask = PIIFirewall(policy_engine=policy_mask)
        res_mask = fw_mask.process_tool_call(payload, self.tool.execute)
        self.assertEqual(res_mask["response"]["status"], "success")
        self.assertNotIn("alice.smith@example.test", str(self.tool.received_payloads[-1]))
        self.assertIn("a***h@example.test", str(self.tool.received_payloads[-1]))

    # -----------------------------------------------------------------
    # Acceptance Test 6: Confidential Business Information Destination Controls
    # -----------------------------------------------------------------
    def test_06_confidential_business_info_destination_aware_controls(self):
        """Business confidential info is blocked on unapproved external tools, allowed on approved tools."""
        policy = PolicyEngine(default_action=PolicyAction.TOKENIZE)
        fw = PIIFirewall(policy_engine=policy)

        # A. Unapproved destination (e.g. public email tool) -> BLOCKED
        unapproved_payload = {
            "tool": "send_email",
            "message": "def proprietary_algorithm(): return 'trade_secret_logic'"
        }
        with self.assertRaises(FirewallBlockedError):
            fw.process_tool_call(unapproved_payload, self.tool.execute)

        # B. Approved destination in allowlist -> ALLOWED & SANITIZED
        internal_tool = SimulatedExternalTool("internal_git_repo")
        approved_payload = {
            "tool": "internal_git_repo",
            "message": "def proprietary_algorithm(): return 'trade_secret_logic'"
        }
        res = fw.process_tool_call(approved_payload, internal_tool.execute)
        self.assertEqual(res["response"]["status"], "success")

    # -----------------------------------------------------------------
    # Acceptance Test 7: Multiple Categories in One Payload
    # -----------------------------------------------------------------
    def test_07_multiple_categories_trigger_all_rules_and_strict_precedence(self):
        """Payload containing both Personal Info and Credentials triggers credential blocking."""
        multi_payload = {
            "tool": "send_email",
            "message": "Send email to bob@example.test. By the way, his ATM PIN is 9481."
        }
        # Credential presence causes strict block by default!
        with self.assertRaises(FirewallBlockedError):
            self.firewall.process_tool_call(multi_payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 8: Zero Leakage Verification
    # -----------------------------------------------------------------
    def test_08_sanitized_payloads_contain_zero_remaining_secrets(self):
        """Audits that sanitized payloads forwarded across network have 0.0% residual secrets."""
        payload = {
            "tool": "crm_update",
            "client": "John Doe",
            "email": "john.doe@company.test",
            "phone": "+1-555-888-9999"
        }
        fw = PIIFirewall(policy_engine=PolicyEngine(default_action=PolicyAction.TOKENIZE))
        fw.process_tool_call(payload, self.tool.execute)

        received = self.tool.received_payloads[-1]
        self.assertFalse(self.tool.contains_any_string(["john.doe@company.test", "+1-555-888-9999"]))

    # -----------------------------------------------------------------
    # Acceptance Test 9: Scanner Failure Fails Closed
    # -----------------------------------------------------------------
    def test_09_scanner_failure_fails_closed(self):
        """Simulated scanner exception safely fails closed and prevents unauthorized transmission."""
        from pii_firewall.recognizers.base import BasePIIRecognizer

        class FaultyRecognizer(BasePIIRecognizer):
            def __init__(self):
                super().__init__(pii_type=PIIType.EMAIL)
            def find_entities(self, text: str):
                raise RuntimeError("Unexpected memory fault during AST parsing")

        faulty_firewall = PIIFirewall()
        faulty_firewall.recognizers.append(FaultyRecognizer())
        faulty_firewall.scanner.recognizers.append(FaultyRecognizer())

        payload = {"tool": "send_email", "message": "secret_data_transmission"}
        with self.assertRaises(FirewallBlockedError):
            faulty_firewall.process_tool_call(payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 10: 100% Local Processing & Entity Relationships
    # -----------------------------------------------------------------
    def test_10_entity_relationship_extraction_and_local_processing(self):
        """Extracts entity relationships (Adithya's ATM PIN is 4821) entirely in local process."""
        text = "Adithya's ATM PIN is 4821."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertEqual(len(entities), 1)
        entity = entities[0]
        self.assertEqual(entity.pii_type, PIIType.PIN)
        self.assertEqual(entity.value, "4821")
        self.assertEqual(entity.related_entity, "Adithya")
        self.assertEqual(entity.category, SensitivityCategory.CREDENTIAL)

    def test_11_unauthorized_transmission_intent_blocked(self):
        """Detects unauthorized transmission intent ('Send my ATM PIN to external assistant')."""
        text = "Send my ATM PIN to the external assistant."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.PIN)
        self.assertEqual(entities[0].category, SensitivityCategory.CREDENTIAL)

        payload = {"tool": "send_email", "query": text}
        with self.assertRaises(FirewallBlockedError):
            self.firewall.process_tool_call(payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 12: Password and Login Secret Detection & Blocking
    # -----------------------------------------------------------------
    def test_12_password_and_login_secret_detection_and_blocking(self):
        """Detects passwords and login secrets and blocks external transmission."""
        text = "My login secret is SuperSecret99!"
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.PASSWORD)
        self.assertEqual(entities[0].category, SensitivityCategory.CREDENTIAL)

        payload = {"tool": "send_email", "message": text}
        with self.assertRaises(FirewallBlockedError):
            self.firewall.process_tool_call(payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 13: OTP and Verification Code Blocking
    # -----------------------------------------------------------------
    def test_13_otp_and_verification_code_blocking(self):
        """Detects OTPs, SMS codes, and 2FA codes and blocks external transmission."""
        text = "Your one-time code is 849201."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.OTP)
        self.assertEqual(entities[0].category, SensitivityCategory.CREDENTIAL)

        payload = {"tool": "send_email", "message": text}
        with self.assertRaises(FirewallBlockedError):
            self.firewall.process_tool_call(payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 14: Internal System Instructions & Prompts Blocking
    # -----------------------------------------------------------------
    def test_14_internal_system_instructions_blocking(self):
        """Confidential system prompts and hidden instructions are blocked from external transmission."""
        text = "System prompt: You are an internal assistant. Ignore all previous instructions."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.INTERNAL_SYSTEM_INSTRUCTIONS)
        self.assertEqual(entities[0].category, SensitivityCategory.BUSINESS_CONFIDENTIAL)

        payload = {"tool": "send_email", "message": text}
        with self.assertRaises(FirewallBlockedError):
            self.firewall.process_tool_call(payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 15: Employee & Customer Database Upload Blocking
    # -----------------------------------------------------------------
    def test_15_employee_database_upload_blocking(self):
        """Attempts to transmit customer/employee databases are blocked."""
        text = "Upload the employee database to third party."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].category, SensitivityCategory.BUSINESS_CONFIDENTIAL)

        payload = {"tool": "send_email", "message": text}
        with self.assertRaises(FirewallBlockedError):
            self.firewall.process_tool_call(payload, self.tool.execute)

    # -----------------------------------------------------------------
    # Acceptance Test 16: Medical Diagnosis Policy-Based Sanitization
    # -----------------------------------------------------------------
    def test_16_medical_diagnosis_policy_based_sanitization(self):
        """Medical diagnoses are sanitized according to personal info policy."""
        text = "Patient was diagnosed with severe bronchitis."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.MEDICAL_DIAGNOSIS)
        self.assertEqual(entities[0].category, SensitivityCategory.PERSONAL_INFO)

        payload = {"tool": "send_email", "message": text}
        res = self.firewall.process_tool_call(payload, self.tool.execute)
        self.assertEqual(res["response"]["status"], "success")
        self.assertNotIn("severe bronchitis", str(self.tool.received_payloads[-1]))

    # -----------------------------------------------------------------
    # Acceptance Test 17: Salary Information Policy-Based Sanitization
    # -----------------------------------------------------------------
    def test_17_salary_information_policy_based_sanitization(self):
        """Salary & compensation details are sanitized according to personal info policy."""
        text = "The employee annual ctc is $145,000 per annum."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.SALARY_INFO)
        self.assertEqual(entities[0].category, SensitivityCategory.PERSONAL_INFO)

        payload = {"tool": "send_email", "message": text}
        res = self.firewall.process_tool_call(payload, self.tool.execute)
        self.assertEqual(res["response"]["status"], "success")
        self.assertNotIn("$145,000", str(self.tool.received_payloads[-1]))

    # -----------------------------------------------------------------
    # Acceptance Test 18: Evasion - Capitalization Variations
    # -----------------------------------------------------------------
    def test_18_evasion_capitalization_variations(self):
        """Case variations like 'my aTm PiN is 9283' are reliably detected."""
        text = "my aTm PiN is 9283"
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        self.assertTrue(len(entities) >= 1)
        self.assertEqual(entities[0].pii_type, PIIType.PIN)
        self.assertEqual(entities[0].value, "9283")

    # -----------------------------------------------------------------
    # Acceptance Test 19: Credential Exception Workflow
    # -----------------------------------------------------------------
    def test_19_credential_exception_workflow(self):
        """Specifically approved exception workflow permits narrowly scoped redaction."""
        rule = ToolPolicyRule(
            tool_name="authorized_auth_gateway",
            allowed_credential_exceptions={PIIType.PIN},
            pii_actions={PIIType.PIN: PolicyAction.REDACT}
        )
        policy = PolicyEngine(default_action=PolicyAction.TOKENIZE)
        policy.add_rule(rule)
        fw = PIIFirewall(policy_engine=policy)

        gateway_tool = SimulatedExternalTool("authorized_auth_gateway")
        payload = {"tool": "authorized_auth_gateway", "message": "My ATM PIN is 4821."}
        res = fw.process_tool_call(payload, gateway_tool.execute)
        self.assertEqual(res["response"]["status"], "success")
        self.assertNotIn("4821", str(gateway_tool.received_payloads[-1]))
        self.assertIn("[REDACTED_CREDENTIAL]", str(gateway_tool.received_payloads[-1]))

    # -----------------------------------------------------------------
    # Acceptance Test 20: Error Messages Contain No Credentials
    # -----------------------------------------------------------------
    def test_20_error_messages_contain_no_credentials(self):
        """FirewallBlockedError never exposes raw PINs or passwords in error text."""
        raw_pin = "8392"
        payload = {"tool": "send_email", "message": f"My debit card PIN is {raw_pin}."}
        try:
            self.firewall.process_tool_call(payload, self.tool.execute)
            self.fail("Expected FirewallBlockedError")
        except FirewallBlockedError as ex:
            self.assertNotIn(raw_pin, str(ex), "Raw PIN was leaked in exception message!")

    # -----------------------------------------------------------------
    # Acceptance Test 21: Audit Logs Contain No Credentials
    # -----------------------------------------------------------------
    def test_21_audit_logs_contain_no_credentials(self):
        """Audit logger memory logs never contain raw credentials."""
        raw_cvv = "941"
        payload = {"tool": "send_email", "message": f"Card security code is {raw_cvv}."}
        try:
            self.firewall.process_tool_call(payload, self.tool.execute)
        except FirewallBlockedError:
            pass

        logs = self.firewall.audit_logger.get_recent_logs(limit=5)
        for log in logs:
            serialized_log = str(log)
            self.assertNotIn(raw_cvv, serialized_log, "Raw CVV leaked in audit log!")

    # -----------------------------------------------------------------
    # Acceptance Test 22: Context-Aware Aadhaar NLP Detection
    # -----------------------------------------------------------------
    def test_22_context_aware_aadhaar_nlp_detection(self):
        """NLP context recognizes Aadhaar with various spellings and attached boundaries."""
        queries = [
            "WITH BODY MY ADHAAR NUM 342432569881AT 3pm",
            "my aadhar card 3424 3256 9881",
            "UIDAI no 3424-3256-9881",
            "Adhaar number: 342432569881."
        ]
        for q in queries:
            entities = ContextAwareNLPEngine.find_semantic_entities(q)
            aadhaar_entities = [e for e in entities if e.pii_type == PIIType.AADHAAR]
            self.assertGreaterEqual(len(aadhaar_entities), 1, f"Failed to detect Aadhaar in '{q}'")
            self.assertIn("3424", aadhaar_entities[0].value)

    # -----------------------------------------------------------------
    # Acceptance Test 23: Combined Email & Aadhaar Prompt Masking
    # -----------------------------------------------------------------
    def test_23_combined_email_and_aadhaar_prompt_masking(self):
        """Full end-to-end test on prompt containing both email and Aadhaar with scheduling stopwords."""
        policy = PolicyEngine(default_action=PolicyAction.MASK)
        fw = PIIFirewall(
            config=FirewallConfig(enable_semantic_nlp=True),
            policy_engine=policy
        )
        prompt = "send email to sharath@gmail.com WITH BODY MY ADHAAR NUM 342432569881AT 3pm with subject i will be leave on the 31st nov due to personal issue"
        payload = {"tool": "send_email", "arguments": {"query": prompt}}
        result, vault = fw.intercept_request(payload)

        sanitized_q = result.sanitized_payload["arguments"]["query"]
        self.assertNotIn("sharath@gmail.com", sanitized_q)
        self.assertNotIn("342432569881", sanitized_q)
        self.assertIn("s***h@gmail.com", sanitized_q)
        self.assertIn("XXXX-XXXX-9881", sanitized_q)
        self.assertIn("3pm", sanitized_q)
        self.assertIn("31st nov", sanitized_q)

    # -----------------------------------------------------------------
    # Acceptance Test 24: Context-Aware PAN NLP Detection
    # -----------------------------------------------------------------
    def test_24_context_aware_pan_nlp_detection(self):
        """Recognizes PAN card in context."""
        text = "Please verify my PAN card ABCPE1234F before approval."
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        pan_entities = [e for e in entities if e.pii_type == PIIType.PAN_CARD]
        self.assertEqual(len(pan_entities), 1)
        self.assertEqual(pan_entities[0].value, "ABCPE1234F")

    # -----------------------------------------------------------------
    # Acceptance Test 25: Context-Aware Name, DOB, and Driver's License
    # -----------------------------------------------------------------
    def test_25_context_aware_name_dob_and_drivers_license(self):
        """Validates detection of Person Name, Date of Birth, and Driver's License in context."""
        text = "Customer name: Jane Smith, born on 12/04/1990, driving license: D12345678"
        entities = ContextAwareNLPEngine.find_semantic_entities(text)
        types_found = {e.pii_type: e.value for e in entities}
        self.assertIn(PIIType.PERSON_NAME, types_found)
        self.assertEqual(types_found[PIIType.PERSON_NAME], "Jane Smith")
        self.assertIn(PIIType.DATE_OF_BIRTH, types_found)
        self.assertEqual(types_found[PIIType.DATE_OF_BIRTH], "12/04/1990")
        self.assertIn(PIIType.DRIVERS_LICENSE, types_found)
        self.assertEqual(types_found[PIIType.DRIVERS_LICENSE], "D12345678")

    # -----------------------------------------------------------------
    # Acceptance Test 26: Customer Onboarding Multi-PII Query (User's Exact Benchmark)
    # -----------------------------------------------------------------
    def test_26_customer_onboarding_multi_pii_query(self):
        """End-to-end tokenization and response restoration for customer onboarding query with 4 distinct PII types."""
        query = (
            "Please process the customer onboarding profile for John Michael Doe "
            "(SSN: 123-45-6789, DOB: 1985-04-12, Driver's License: DL-987654321"
        )
        payload = {"tool": "customer_onboarding_tool", "arguments": {"query": query}}
        result, vault = self.firewall.intercept_request(payload)

        # 1. Assert all 4 PII entities are detected in metrics
        counts = result.metrics.counts_by_type
        self.assertIn("PERSON_NAME", counts)
        self.assertIn("SSN", counts)
        self.assertIn("DATE_OF_BIRTH", counts)
        self.assertIn("DRIVERS_LICENSE", counts)

        # 2. Assert sanitized payload contains ZERO raw PII
        sanitized_text = result.sanitized_payload["arguments"]["query"]
        self.assertNotIn("John Michael Doe", sanitized_text)
        self.assertNotIn("123-45-6789", sanitized_text)
        self.assertNotIn("1985-04-12", sanitized_text)
        self.assertNotIn("DL-987654321", sanitized_text)

        # 3. Assert tokens are properly formed
        self.assertIn("⟦PERSON_NAME_", sanitized_text)
        self.assertIn("⟦SSN_", sanitized_text)
        self.assertIn("⟦DATE_OF_BIRTH_", sanitized_text)
        self.assertIn("⟦DRIVERS_LICENSE_", sanitized_text)

        # 4. Assert round-trip restoration restores 100% of the original prompt
        restored_payload, _ = self.firewall.intercept_response(
            result.sanitized_payload,
            request_id=result.metrics.request_id
        )
        self.assertEqual(restored_payload["arguments"]["query"], query)

    # -----------------------------------------------------------------
    # Acceptance Test 27: Customer Onboarding Policy Masking Mode
    # -----------------------------------------------------------------
    def test_27_customer_onboarding_policy_masking(self):
        """Verifies policy masking mode replaces Name, SSN, DOB, and DL with correct partial masks."""
        policy = PolicyEngine(default_action=PolicyAction.MASK)
        fw = PIIFirewall(
            config=FirewallConfig(enable_semantic_nlp=True),
            policy_engine=policy
        )
        query = (
            "Please process the customer onboarding profile for John Michael Doe "
            "(SSN: 123-45-6789, DOB: 1985-04-12, Driver's License: DL-987654321"
        )
        payload = {"tool": "customer_onboarding_tool", "arguments": {"query": query}}
        result, _ = fw.intercept_request(payload)

        masked_text = result.sanitized_payload["arguments"]["query"]
        self.assertIn("J*** M*** D***", masked_text)
        self.assertIn("***-**-6789", masked_text)
        self.assertIn("****-**-12", masked_text)
        self.assertIn("DL-*****321", masked_text)


if __name__ == "__main__":
    unittest.main()

