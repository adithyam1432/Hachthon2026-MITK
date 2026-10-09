"""
Tests for Agent SDK Adapter & Decorators.
"""

import unittest
from pii_firewall.agent_adapter import AgentToolAdapter
from pii_firewall.middleware import PIIFirewall


class TestAgentToolAdapter(unittest.TestCase):

    def setUp(self):
        self.firewall = PIIFirewall()
        self.adapter = AgentToolAdapter(self.firewall)

    def test_protect_tool_decorator(self):
        # A simulated external service function that receives parameters
        received_args = {}

        @self.adapter.protect_tool
        def send_slack_notification(recipient_email: str, message: str) -> dict:
            received_args["recipient_email"] = recipient_email
            received_args["message"] = message
            return {
                "delivered": True,
                "sent_to": recipient_email,
                "msg_preview": message,
            }

        # Agent calls the python function with real PII
        result = send_slack_notification(
            recipient_email="vip.user@client.test",
            message="Your token verification code is sent."
        )

        # 1. Verify the tool inside received the TOKEN, not the raw email!
        self.assertTrue(received_args["recipient_email"].startswith("⟦EMAIL_"))
        self.assertNotIn("vip.user@client.test", received_args["recipient_email"])

        # 2. Verify return value to agent has been safely re-hydrated with original email!
        self.assertEqual(result["sent_to"], "vip.user@client.test")
        self.assertTrue(result["delivered"])

    def test_openai_tool_call_interception(self):
        # Simulated OpenAI tool call schema
        tool_call_dict = {
            "id": "call_98765",
            "type": "function",
            "function": {
                "name": "lookup_customer",
                "arguments": '{"phone": "+1-555-987-6543", "query": "find orders"}'
            }
        }

        captured_args = {}

        def mock_tool_runner(name: str, args: dict):
            captured_args.update(args)
            return {"status": "found", "contact": args.get("phone")}

        output = self.adapter.intercept_openai_tool_call(
            tool_call_dict=tool_call_dict,
            tool_runner=mock_tool_runner,
        )

        # External tool runner received token
        self.assertTrue(captured_args["phone"].startswith("⟦PHONE_"))
        # Returned output restored back to original phone
        self.assertEqual(output["restored_output"]["contact"], "+1-555-987-6543")
        self.assertEqual(output["metrics"]["total_detected"], 1)


if __name__ == "__main__":
    unittest.main()
