"""
Tests for Leakage Prevention & Fail-Safe Blocking.
Covers Functional Requirements: FR-12, FR-13, FR-14.
"""

import unittest
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import PIILeakageDetectedError, PIIType
from pii_firewall.simulated_tool import SimulatedExternalTool
from pii_firewall.vault import RequestTokenVault
from pii_firewall.verifier import LeakageVerifier


class TestLeakagePrevention(unittest.TestCase):

    def setUp(self):
        self.firewall = PIIFirewall()
        self.tool = SimulatedExternalTool("SecureBackend")

    def test_direct_leakage_detection_raises_error(self):
        """Verifies that LeakageVerifier blocks when original detected PII remains in payload."""
        vault = RequestTokenVault()
        secret_email = "victim@domain.test"
        vault.get_or_create_token(secret_email, PIIType.EMAIL)

        # Incomplete sanitized payload where raw secret was accidentally retained
        leaky_payload = {
            "tokenized": "⟦EMAIL_123456⟧",
            "leaked_copy": secret_email,
        }

        with self.assertRaises(PIILeakageDetectedError) as ctx:
            LeakageVerifier.verify(leaky_payload, vault, fail_safe_strict=True)

        err_msg = str(ctx.exception)
        # FR-14 & FR-21: Error message MUST NOT contain the raw PII!
        self.assertNotIn(secret_email, err_msg)
        self.assertIn("Leakage verification failed", err_msg)

    def test_tool_not_called_on_verification_failure(self):
        """Ensures external tool is NEVER invoked if verification fails."""
        # Custom mock that simulates an internal tokenizer defect
        class BrokenScanner:
            def scan_and_tokenize(self, payload, vault, *args, **kwargs):
                # Register secret in vault but fail to replace it in payload
                vault.get_or_create_token("leak@test.com", PIIType.EMAIL)
                return payload, {"EMAIL": 1}

        self.firewall.scanner = BrokenScanner()

        leaky_request = {"data": "leak@test.com"}
        with self.assertRaises(PIILeakageDetectedError):
            self.firewall.process_tool_call(leaky_request, self.tool.execute)

        # Confirm tool call count is exactly 0
        self.assertEqual(len(self.tool.received_payloads), 0)


if __name__ == "__main__":
    unittest.main()
