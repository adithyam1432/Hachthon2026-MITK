"""
End-to-End tests for PII Firewall middleware.
Covers Functional Requirements: FR-1 through FR-11, FR-15 through FR-21.
"""

import unittest
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import FirewallConfig, PIIType
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestFirewallE2E(unittest.TestCase):

    def setUp(self):
        self.firewall = PIIFirewall()
        self.tool = SimulatedExternalTool("TestService")

    def test_prd_example_flow(self):
        """Tests exact PRD section 3 workflow."""
        agent_request = {
            "tool": "send_email",
            "arguments": {
                "to": "alex.demo@example.test",
                "message": "Your appointment is at 3 PM."
            }
        }

        result = self.firewall.process_tool_call(
            request_payload=agent_request,
            tool_callable=self.tool.execute,
        )

        # Verify tool received tokenized payload, not real email
        tool_received = self.tool.received_payloads[-1]
        received_to = tool_received["arguments"]["to"]
        self.assertTrue(received_to.startswith("⟦EMAIL_"), f"Unexpected token: {received_to}")
        self.assertNotIn("alex.demo@example.test", str(tool_received))

        # Verify non-sensitive message content preserved
        self.assertEqual(tool_received["arguments"]["message"], "Your appointment is at 3 PM.")

        # Verify response restoration restored the original email in response
        restored_response = result["response"]
        echo_to = restored_response["echo_arguments"]["to"]
        self.assertEqual(echo_to, "alex.demo@example.test")

        # Verify safe metrics do not contain raw email
        metrics = result["metrics"]
        self.assertEqual(metrics["counts_by_type"].get("EMAIL"), 1)
        self.assertNotIn("alex.demo@example.test", str(metrics))

    def test_nested_json_and_multiple_pii(self):
        """Tests FR-2, FR-3, FR-4 with nested dictionaries, lists, and primitives."""
        payload = {
            "metadata": {
                "request_id": 1002,
                "is_urgent": True,
                "null_field": None,
                "score": 98.6
            },
            "recipients": [
                {
                    "name": "Jane",
                    "email": "jane.doe@acme.corp",
                    "contact_phone": "+1-555-432-1098"
                },
                {
                    "name": "Bob",
                    "notes": "Escalate to alex.demo@example.test or call (555) 345-6789."
                }
            ],
            "billing": {
                "tax_id": "123-45-6789"
            }
        }

        planted_pii = [
            "jane.doe@acme.corp",
            "+1-555-432-1098",
            "alex.demo@example.test",
            "(555) 345-6789",
            "123-45-6789"
        ]

        result = self.firewall.process_tool_call(
            request_payload=payload,
            tool_callable=self.tool.execute,
        )

        # Verify simulated tool NEVER received any planted PII
        self.assertFalse(self.tool.contains_any_string(planted_pii))

        # Verify primitives preserved
        received = self.tool.received_payloads[-1]
        self.assertEqual(received["metadata"]["request_id"], 1002)
        self.assertIs(received["metadata"]["is_urgent"], True)
        self.assertIsNone(received["metadata"]["null_field"])
        self.assertEqual(received["metadata"]["score"], 98.6)

        # Verify total detected count
        metrics = result["metrics"]
        self.assertEqual(metrics["total_detected"], 5)

    def test_token_consistency_within_request(self):
        """Tests FR-9: Repeated occurrences of same value map to same token."""
        payload = {
            "primary_email": "repeated.user@example.test",
            "confirmation_email": "repeated.user@example.test",
            "summary": "Sending alert to repeated.user@example.test now."
        }

        res, vault = self.firewall.intercept_request(payload)
        sanitized = res.sanitized_payload

        tok1 = sanitized["primary_email"]
        tok2 = sanitized["confirmation_email"]
        self.assertEqual(tok1, tok2)
        self.assertIn(tok1, sanitized["summary"])
        # Exactly 1 unique token generated for repeated value
        self.assertEqual(vault.get_token_count(), 1)

    def test_token_isolation_across_requests(self):
        """Tests FR-10: Different requests generate distinct opaque tokens for same value."""
        payload = {"email": "alex.demo@example.test"}

        res1, _ = self.firewall.intercept_request(payload)
        res2, _ = self.firewall.intercept_request(payload)

        tok1 = res1.sanitized_payload["email"]
        tok2 = res2.sanitized_payload["email"]
        self.assertNotEqual(tok1, tok2, "Tokens between distinct requests must be salted and isolated")

    def test_disabled_restoration_policy(self):
        """Tests FR-18: Ability to disable response restoration."""
        config = FirewallConfig(allow_restoration=False)
        fw = PIIFirewall(config)

        payload = {"tool": "send_email", "arguments": {"to": "secret@company.test"}}
        result = fw.process_tool_call(payload, self.tool.execute)

        echo = result["response"]["echo_arguments"]["to"]
        self.assertTrue(echo.startswith("⟦EMAIL_"))

    def test_selective_field_restoration(self):
        """Tests FR-18: Response restoration limited to approved fields only."""
        config = FirewallConfig(
            allow_restoration=True,
            allowed_restoration_fields=["restored_field"]
        )
        fw = PIIFirewall(config)

        res, vault = fw.intercept_request({"email": "alex.demo@example.test"})
        token = res.sanitized_payload["email"]

        raw_response = {
            "restored_field": token,
            "blocked_field": token
        }

        restored, metrics = fw.intercept_response(raw_response, res.request_id)
        self.assertEqual(restored["restored_field"], "alex.demo@example.test")
        self.assertEqual(restored["blocked_field"], token)


if __name__ == "__main__":
    unittest.main()
