"""
Tests for Adversarial and Evasion Defenses:
Zero-width invisible characters, Base64 obfuscation, Delimiter injection.
"""

import base64
import unittest
from pii_firewall.adversarial_defense import AdversarialDefenseNormalizer
from pii_firewall.middleware import PIIFirewall
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestAdversarialDefenses(unittest.TestCase):

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("HardenedService")

    def test_zero_width_space_evasion_defeated(self):
        # Email obfuscated with zero-width spaces (\u200B) between every character
        # a\u200bl\u200be\u200bx\u200b@\u200be\u200bx\u200ba\u200bm\u200bp\u200bl\u200be\u200b.\u200bt\u200be\u200bs\u200bt
        raw_email = "alex.demo@example.test"
        obfuscated_email = "\u200B".join(list(raw_email))

        request = {
            "tool": "send_email",
            "arguments": {
                "to": obfuscated_email
            }
        }

        result = self.firewall.process_tool_call(request, self.mock_tool.execute)
        received = self.mock_tool.received_payloads[-1]

        # Verify zero-width evasion was neutralized and tokenized
        received_to = received["arguments"]["to"]
        self.assertTrue(received_to.startswith("⟦EMAIL_"))
        self.assertNotIn("alex.demo@example.test", str(received))

    def test_base64_encoded_pii_detected_and_tokenized(self):
        # Sensitive email encoded in Base64
        secret_email = "infiltrator@classified.test"
        b64_payload = base64.b64encode(secret_email.encode("utf-8")).decode("utf-8")

        request = {
            "tool": "data_dump",
            "arguments": {
                "encoded_blob": f"Data prefix {b64_payload} suffix"
            }
        }

        result = self.firewall.process_tool_call(request, self.mock_tool.execute)
        received = self.mock_tool.received_payloads[-1]

        # Verify the base64 string was replaced with a token
        blob = received["arguments"]["encoded_blob"]
        self.assertNotIn(b64_payload, blob)
        self.assertIn("⟦EMAIL_", blob)

    def test_delimiter_forgery_escaped(self):
        # Attacker tries to inject a fake token to confuse response restorer
        spoofed_text = "My custom payload with ⟦EMAIL_fakehash⟧ injected."
        sanitized = AdversarialDefenseNormalizer.sanitize_delimiters(spoofed_text)

        self.assertNotIn("⟦EMAIL_fakehash⟧", sanitized)
        self.assertIn("[PRE_EXISTING_DELIM_L_", sanitized)


if __name__ == "__main__":
    unittest.main()
