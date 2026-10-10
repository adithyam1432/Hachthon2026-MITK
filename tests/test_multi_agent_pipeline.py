"""
Tests for Multi-Agent PII Firewall Pipeline.
Verifies the complete 7-agent architecture from prompt formulation to response re-hydration.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from pii_firewall.multi_agent_pipeline import (
    ClientAgent,
    NLPAgent,
    DetectionAgent,
    ClassificationAgent,
    TransformationAgent,
    SimulatedToolAgent,
    RehydrationAgent,
    MultiAgentPipeline,
)
from pii_firewall.models import PIIType


class TestMultiAgentPipeline(unittest.TestCase):
    """Test suite for the 7-agent PII Firewall Pipeline."""

    def test_01_client_agent_payload_extraction(self):
        agent = ClientAgent()
        prompt = "Update account profile. Name: David Miller, Passport: A12345678, Status: Active."
        step, payload = agent.execute(prompt)
        self.assertEqual(step.status, "SUCCESS")
        self.assertEqual(step.step_number, 1)
        self.assertIn("tool", payload)
        self.assertIn("arguments", payload)

    def test_02_nlp_agent_stopword_isolation(self):
        agent = NLPAgent(enable_cloud_gemini=False)
        prompt = "Send email to sarah@example.com at 3pm with schedule for 31st nov"
        step, data = agent.execute(prompt)
        self.assertEqual(step.status, "SUCCESS")
        self.assertEqual(step.step_number, 2)
        self.assertIn("3pm", data["operational_stopwords_verified"])
        self.assertTrue(data["temporal_noise_isolated"])

    def test_03_detection_agent_finds_pii(self):
        agent = DetectionAgent(enable_cloud_gemini=False)
        prompt = "Contact David Miller at david@test.com with passport A12345678"
        step, entities = agent.execute(prompt)
        self.assertEqual(step.status, "SUCCESS")
        self.assertEqual(step.step_number, 3)
        types = {e.pii_type for e in entities}
        self.assertIn(PIIType.EMAIL, types)

    def test_04_classification_agent_assigns_rules(self):
        agent = ClassificationAgent()
        detection_agent = DetectionAgent(enable_cloud_gemini=False)
        prompt = "Profile: Name: David Miller, Passport: A12345678, SSN: 123-45-6789"
        _, entities = detection_agent.execute(prompt)
        step, classifications = agent.execute(entities, tool_name="kyc_verify")
        self.assertEqual(step.status, "SUCCESS")
        self.assertEqual(step.step_number, 4)
        for c in classifications:
            self.assertIn("recommended_action", c)
            self.assertIn("rationale", c)

    def test_05_end_to_end_multi_agent_pipeline(self):
        pipeline = MultiAgentPipeline(enable_cloud_gemini=False)
        prompt = "Update account profile. Name: David Miller, Passport: A12345678, Status: Active."
        trace = pipeline.run(prompt)
        self.assertTrue(trace.success, f"Pipeline failed: {trace.status_message}")
        self.assertEqual(len(trace.steps), 7)
        self.assertEqual(trace.wire_leakage_percentage, 0.0)
        self.assertGreater(trace.total_execution_ms, 0)
        # Verify all 7 steps are present
        step_names = [s.agent_id for s in trace.steps]
        expected_steps = [
            "client_agent",
            "nlp_agent",
            "detection_agent",
            "classification_agent",
            "transformation_agent",
            "tool_agent",
            "rehydration_agent",
        ]
        self.assertEqual(step_names, expected_steps)

    def test_06_dual_mode_simultaneous_execution(self):
        pipeline = MultiAgentPipeline(enable_cloud_gemini=False)
        prompt = "Send a welcome note to David Miller and delete expired file containing SSN 999-12-3456."
        trace = pipeline.run(prompt)
        self.assertTrue(trace.success)
        self.assertGreater(trace.vault_token_count, 0)
        self.assertGreater(trace.redacted_count, 0)
        # Check that SSN is never in outgoing wire or restored payload
        if isinstance(trace.final_response, dict):
            resp_str = str(trace.final_response)
            self.assertNotIn("999-12-3456", resp_str)


if __name__ == "__main__":
    unittest.main()
