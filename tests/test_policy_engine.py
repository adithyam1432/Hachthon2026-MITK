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


if __name__ == "__main__":
    unittest.main()
