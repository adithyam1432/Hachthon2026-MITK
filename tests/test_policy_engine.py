"""
Tests for Granular Policy Engine:
Per-tool, per-field actions (Tokenize, Redact, Mask, Block).
"""

import unittest
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import FirewallBlockedError, PIIType
from pii_firewall.policy import PolicyAction, PolicyEngine, ToolPolicyRule
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.policy_engine = PolicyEngine(default_action=PolicyAction.TOKENIZE)
        self.firewall = PIIFirewall(policy_engine=self.policy_engine)
        self.mock_tool = SimulatedExternalTool("CustomService")

    def test_per_tool_redaction(self):
        # Rule: for tool 'analytics_logger', emails should be REDACTED permanently, not tokenized
        self.policy_engine.add_rule(
            ToolPolicyRule(
                tool_name="analytics_logger",
                pii_actions={PIIType.EMAIL: PolicyAction.REDACT}
            )
        )

        request = {
            "tool": "analytics_logger",
            "arguments": {
                "user_email": "analyst@metrics.test",
                "action": "page_view"
            }
        }

        result = self.firewall.process_tool_call(request, self.mock_tool.execute)
        received = self.mock_tool.received_payloads[-1]

        # Verify it was replaced with [REDACTED_EMAIL], not a token
        self.assertEqual(received["arguments"]["user_email"], "[REDACTED_EMAIL]")
        self.assertNotIn("analyst@metrics.test", str(received))

    def test_per_tool_masking(self):
        # Rule: for tool 'display_portal', credit cards should be partially MASKED
        self.policy_engine.add_rule(
            ToolPolicyRule(
                tool_name="display_portal",
                pii_actions={PIIType.CREDIT_CARD: PolicyAction.MASK}
            )
        )

        request = {
            "tool": "display_portal",
            "arguments": {
                "card": "4111-1111-1111-1111"
            }
        }

        result = self.firewall.process_tool_call(request, self.mock_tool.execute)
        received = self.mock_tool.received_payloads[-1]

        # Verify masked representation ****-****-****-1111
        self.assertEqual(received["arguments"]["card"], "****-****-****-1111")

    def test_tool_blocked_for_sensitive_type(self):
        # Rule: 'send_public_email' must NEVER be sent a Social Security Number or Credit Card
        self.policy_engine.add_rule(
            ToolPolicyRule(
                tool_name="send_public_email",
                blocked_pii_types={PIIType.SSN, PIIType.CREDIT_CARD}
            )
        )

        forbidden_request = {
            "tool": "send_public_email",
            "arguments": {
                "body": "Your SSN on file is 123-45-6789."
            }
        }

        with self.assertRaises(FirewallBlockedError) as ctx:
            self.firewall.process_tool_call(forbidden_request, self.mock_tool.execute)

        self.assertIn("strictly prohibited", str(ctx.exception))
        # Tool was never called
        self.assertEqual(len(self.mock_tool.received_payloads), 0)

    def test_field_level_whitelist(self):
        # Rule: 'public_author' field is whitelisted and passed through untouched
        self.policy_engine.add_rule(
            ToolPolicyRule(
                tool_name="blog_publisher",
                whitelisted_fields={"public_contact"}
            )
        )

        request = {
            "tool": "blog_publisher",
            "arguments": {
                "public_contact": "author@publicdomain.com",
                "secret_backup": "private@publicdomain.com"
            }
        }

        result = self.firewall.process_tool_call(request, self.mock_tool.execute)
        received = self.mock_tool.received_payloads[-1]

        # Whitelisted field passed untouched
        self.assertEqual(received["arguments"]["public_contact"], "author@publicdomain.com")
        # Non-whitelisted field tokenized
        self.assertTrue(received["arguments"]["secret_backup"].startswith("⟦EMAIL_"))

    def test_dynamic_pii_rules_dual_mode_profile_change(self):
        """Validates simultaneous Tokenization (Name) and Redaction (Passport) from rules config."""
        rules = {
            "PII_RULES": {
                "NAME": "TOKENIZE",
                "PASSPORT_NUMBER": "REDACT"
            }
        }
        policy = PolicyEngine.from_rules_dict(rules, simple_redaction=True)
        fw = PIIFirewall(policy_engine=policy)

        request = {
            "tool": "profile_updater",
            "arguments": {
                "query": "Update account profile. Name: David Miller, Passport: A12345678, Status: Active."
            }
        }
        res, vault = fw.intercept_request(request)
        sent = res.sanitized_payload["arguments"]["query"]

        # 1. Name is tokenized and stored in vault
        self.assertIn("⟦PERSON_NAME_", sent)
        self.assertNotIn("David Miller", sent)
        self.assertEqual(len(vault._token_to_value), 1)

        # 2. Passport is redacted and NOT stored in vault
        self.assertIn("[REDACTED]", sent)
        self.assertNotIn("A12345678", sent)

        # 3. Simulate tool response and verify restoration
        mock_response = {
            "status": "success",
            "message": f"Profile updated for {list(vault._token_to_value.keys())[0]} with [REDACTED]."
        }
        restored, _ = fw.intercept_response(mock_response, request_id=res.metrics.request_id)
        self.assertIn("David Miller", restored["message"])
        self.assertIn("[REDACTED]", restored["message"])
        self.assertNotIn("A12345678", restored["message"])

    def test_dynamic_pii_rules_dual_mode_visual_comparison(self):
        """Validates side-by-side demo: Name tokenized & re-hydrated, SSN redacted permanently."""
        rules = {
            "PII_RULES": {
                "NAME": "TOKENIZE",
                "SSN": "REDACT"
            }
        }
        policy = PolicyEngine.from_rules_dict(rules, simple_redaction=True)
        fw = PIIFirewall(policy_engine=policy)

        raw_query = "Send a welcome note to David Miller and delete expired file containing SSN 999-12-3456."
        request = {"tool": "crm_tool", "arguments": {"query": raw_query}}
        res, vault = fw.intercept_request(request)
        sent = res.sanitized_payload["arguments"]["query"]

        self.assertIn("⟦PERSON_NAME_", sent)
        self.assertIn("[REDACTED]", sent)
        self.assertNotIn("David Miller", sent)
        self.assertNotIn("999-12-3456", sent)

        token = list(vault._token_to_value.keys())[0]
        tool_reply = {
            "msg": f"Task complete for {token}. File referenced with [REDACTED] has been scrubbed."
        }
        restored, _ = fw.intercept_response(tool_reply, request_id=res.metrics.request_id)
        self.assertEqual(
            restored["msg"],
            "Task complete for David Miller. File referenced with [REDACTED] has been scrubbed."
        )

    def test_backend_native_classification_rules(self):
        """Verifies PolicyEngine loads classification rules natively from backend configuration."""
        policy = PolicyEngine.create_default_backend_policy(simple_redaction=True)
        self.assertIsNotNone(policy)
        
        # Verify Tokenized entities
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.PERSON_NAME), PolicyAction.TOKENIZE)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.EMAIL), PolicyAction.TOKENIZE)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.PHONE), PolicyAction.TOKENIZE)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.DATE_OF_BIRTH), PolicyAction.TOKENIZE)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.HOME_ADDRESS), PolicyAction.TOKENIZE)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.STUDENT_ID), PolicyAction.TOKENIZE)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.EMPLOYEE_ID), PolicyAction.TOKENIZE)
        
        # Verify Redacted entities (High-risk IDs, Location, Biometrics)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.PASSPORT), PolicyAction.REDACT)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.SSN), PolicyAction.REDACT)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.AADHAAR), PolicyAction.REDACT)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.PAN_CARD), PolicyAction.REDACT)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.DRIVERS_LICENSE), PolicyAction.REDACT)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.GPS_COORDINATES), PolicyAction.REDACT)
        
        # Verify Masked entities
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.IP_ADDRESS), PolicyAction.MASK)
        
        # Verify Blocked credentials
        self.assertEqual(policy.get_action_for_entity("any_tool", "PASSWORD"), PolicyAction.BLOCK_TOOL)
        self.assertEqual(policy.get_action_for_entity("any_tool", PIIType.API_KEY), PolicyAction.BLOCK_TOOL)


if __name__ == "__main__":
    unittest.main()

