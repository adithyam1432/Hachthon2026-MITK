"""
Tests for REST API Microservice & Endpoints.
"""

import json
import unittest
from pii_firewall.server import create_app


class TestServerEndpoints(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("EMAIL", data["active_recognizers"])

    def test_intercept_endpoint(self):
        payload = {
            "tool": "send_email",
            "arguments": {"to": "alex.demo@example.test", "msg": "Hi"}
        }
        resp = self.client.post("/v1/intercept", json={"payload": payload})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["sanitized_payload"]["arguments"]["to"].startswith("⟦EMAIL_"))
        self.assertEqual(data["metrics"]["total_detected"], 1)

    def test_process_and_restore_workflow(self):
        payload = {
            "tool": "send_email",
            "arguments": {"to": "alex.demo@example.test", "msg": "Hi"}
        }
        resp = self.client.post("/v1/process", json={"payload": payload})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        # Verify response restored original email
        self.assertEqual(data["response"]["echo_arguments"]["to"], "alex.demo@example.test")
        # Verify sanitized payload sent to tool had token
        self.assertTrue(data["sanitized_payload_sent"]["arguments"]["to"].startswith("⟦EMAIL_"))

    def test_metrics_endpoint(self):
        resp = self.client.get("/v1/metrics")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total_audit_events", data)


if __name__ == "__main__":
    unittest.main()
