"""
Unit & Integration Tests for Google Gemini Free API PII Analyzer & Recognizer.
Tests offline behavior, mocked LLM responses, offset calculations, and firewall integration.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from pii_firewall.gemini_analyzer import (
    GeminiPIIAnalyzer,
    GeminiPIIRecognizer,
    GEMINI_TYPE_MAP,
)
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallConfig,
    PIIType,
    SensitivityCategory,
)
from pii_firewall.policy import PolicyAction, PolicyEngine


class TestGeminiPIIAnalyzer(unittest.TestCase):
    """Test suite for Gemini PII Analyzer."""

    def test_01_init_and_availability(self):
        """Analyzer reports availability correctly based on API key presence."""
        analyzer_empty = GeminiPIIAnalyzer(api_key="")
        self.assertFalse(analyzer_empty.is_available)
        self.assertEqual(analyzer_empty.analyze_prompt("test prompt"), [])

        analyzer_active = GeminiPIIAnalyzer(api_key="AIzaSyTestMockKey123", model="gemini-1.5-flash")
        self.assertTrue(analyzer_active.is_available)
        self.assertEqual(analyzer_active.model, "gemini-1.5-flash")

    def test_02_type_mapping_coverage(self):
        """Verifies that all standard PII categories map correctly from Gemini strings."""
        self.assertEqual(GEMINI_TYPE_MAP["EMAIL"], PIIType.EMAIL)
        self.assertEqual(GEMINI_TYPE_MAP["AADHAAR"], PIIType.AADHAAR)
        self.assertEqual(GEMINI_TYPE_MAP["ADHAAR"], PIIType.AADHAAR)
        self.assertEqual(GEMINI_TYPE_MAP["PAN"], PIIType.PAN_CARD)
        self.assertEqual(GEMINI_TYPE_MAP["PAN_CARD"], PIIType.PAN_CARD)
        self.assertEqual(GEMINI_TYPE_MAP["PHONE"], PIIType.PHONE)
        self.assertEqual(GEMINI_TYPE_MAP["PIN"], PIIType.PIN)
        self.assertEqual(GEMINI_TYPE_MAP["PASSWORD"], PIIType.PASSWORD)
        self.assertEqual(GEMINI_TYPE_MAP["API_KEY"], PIIType.API_KEY)

    @patch("requests.post")
    def test_03_mocked_gemini_detection_success(self, mock_post):
        """Simulates successful Gemini API JSON response and tests entity extraction."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_gemini_json = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps({
                                    "entities": [
                                        {
                                            "value": "sharath@gmail.com",
                                            "type": "EMAIL",
                                            "confidence": 0.99,
                                            "context": "Recipient email address"
                                        },
                                        {
                                            "value": "342432569881",
                                            "type": "AADHAAR",
                                            "confidence": 0.98,
                                            "context": "Indian national identity number"
                                        }
                                    ]
                                })
                            }
                        ]
                    }
                }
            ]
        }
        mock_response.json.return_value = mock_gemini_json
        mock_post.return_value = mock_response

        analyzer = GeminiPIIAnalyzer(api_key="AIzaMockKey", model="gemini-1.5-flash")
        prompt = "send email to sharath@gmail.com WITH BODY MY ADHAAR NUM 342432569881AT 3pm"
        entities = analyzer.analyze_prompt(prompt)

        self.assertEqual(len(entities), 2)

        email_ent = [e for e in entities if e.pii_type == PIIType.EMAIL][0]
        self.assertEqual(email_ent.value, "sharath@gmail.com")
        self.assertEqual(prompt[email_ent.start:email_ent.end], "sharath@gmail.com")
        self.assertIn("Gemini AI", email_ent.context_evidence)

        aadhaar_ent = [e for e in entities if e.pii_type == PIIType.AADHAAR][0]
        self.assertEqual(aadhaar_ent.value, "342432569881")
        self.assertEqual(prompt[aadhaar_ent.start:aadhaar_ent.end], "342432569881")
        self.assertIn("gemini-1.5-flash", aadhaar_ent.context_evidence)

    @patch("requests.post")
    def test_04_http_error_graceful_fallback(self, mock_post):
        """HTTP errors (e.g. 403 Invalid Key or 429 Quota Exceeded) do not raise exceptions."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "API key not valid."
        mock_post.return_value = mock_response

        analyzer = GeminiPIIAnalyzer(api_key="AIzaBadKey")
        entities = analyzer.analyze_prompt("send email to test@domain.com")

        self.assertEqual(entities, [])
        self.assertIsNotNone(analyzer.last_error)
        self.assertIn("HTTP 403", analyzer.last_error)

    @patch("requests.post")
    def test_05_firewall_integration_with_gemini(self, mock_post):
        """Tests end-to-end PIIFirewall request sanitization with Gemini recognizer active."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps({
                                    "entities": [
                                        {
                                            "value": "alice@company.com",
                                            "type": "EMAIL",
                                            "confidence": 0.99,
                                            "context": "Internal work email"
                                        }
                                    ]
                                })
                            }
                        ]
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        fw_config = FirewallConfig(
            gemini_api_key="AIzaMockKey",
            gemini_model="gemini-1.5-flash"
        )
        policy = PolicyEngine(default_action=PolicyAction.MASK)
        firewall = PIIFirewall(config=fw_config, policy_engine=policy)

        # Verify recognizer list contains GeminiPIIRecognizer
        has_gemini_rec = any(isinstance(r, GeminiPIIRecognizer) for r in firewall.recognizers)
        self.assertTrue(has_gemini_rec, "GeminiPIIRecognizer was not loaded into firewall recognizers!")

        payload = {"tool": "send_email", "arguments": {"query": "notify alice@company.com now"}}
        res, vault = firewall.intercept_request(payload)

        sanitized_query = res.sanitized_payload["arguments"]["query"]
        self.assertNotIn("alice@company.com", sanitized_query)
        self.assertIn("a***e@company.com", sanitized_query)


if __name__ == "__main__":
    unittest.main()
