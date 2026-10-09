"""
Unit tests for high-performance batch processing and dynamic custom recognizers.
"""

import re
import time
import unittest
from typing import Any, Dict, List

from pii_firewall.batch import (
    BatchItemResult,
    BatchPIIFirewall,
    BatchProcessResult,
)
from pii_firewall.custom_recognizer import (
    CustomFunctionRecognizer,
    CustomRegexRecognizer,
    create_custom_recognizer,
)
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallBlockedError,
    FirewallConfig,
    PIIEntity,
    PIIType,
)
from pii_firewall.policy import PolicyAction, PolicyEngine, ToolPolicyRule
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestCustomRecognizers(unittest.TestCase):
    """Tests for dynamic custom regex and function-based PII recognizers."""

    def test_custom_regex_recognizer_basic(self):
        # Recognizer for Internal Employee ID: e.g. EMP-12345
        rec = CustomRegexRecognizer(
            pii_type="EMPLOYEE_ID",
            pattern=r"\bEMP-\d{5}\b",
            confidence=0.95,
        )
        text = "Hello EMP-10293, your supervisor EMP-99881 is waiting."
        entities = rec.find_entities(text)

        self.assertEqual(len(entities), 2)
        self.assertEqual(entities[0].pii_type, "EMPLOYEE_ID")
        self.assertEqual(entities[0].value, "EMP-10293")
        self.assertEqual(entities[0].start, 6)
        self.assertEqual(entities[0].end, 15)
        self.assertEqual(entities[0].confidence, 0.95)

        self.assertEqual(entities[1].value, "EMP-99881")

    def test_custom_regex_with_validator(self):
        # Project code pattern PRJ-XXXX where sum of digits must be even
        def even_sum_validator(val: str) -> bool:
            digits = [int(c) for c in val if c.isdigit()]
            return sum(digits) % 2 == 0

        rec = CustomRegexRecognizer(
            pii_type="PROJECT_CODE",
            pattern=r"\bPRJ-\d{4}\b",
            validator=even_sum_validator,
        )

        # 1+1+1+1 = 4 (even) -> should match
        # 1+1+1+2 = 5 (odd) -> should be filtered out
        text = "Reviewing PRJ-1111 and PRJ-1112 today."
        entities = rec.find_entities(text)

        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "PRJ-1111")

    def test_custom_regex_with_context_words(self):
        # Tracking number requiring context keywords
        rec = CustomRegexRecognizer(
            pii_type="TRACKING_ID",
            pattern=r"\bTRK-[0-9]{6}\b",
            context_words=["shipment", "package", "delivery"],
        )

        no_context = "Random ID TRK-123456 generated."
        self.assertEqual(len(rec.find_entities(no_context)), 0)

        with_context = "Your delivery tracking is TRK-123456 via express."
        entities = rec.find_entities(with_context)
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "TRK-123456")

    def test_custom_function_recognizer_tuples(self):
        # Detector returning (start, end, value)
        def detector(text: str):
            results = []
            for m in re.finditer(r"\bSECRET_[a-z0-9]{4}\b", text):
                results.append((m.start(), m.end(), m.group(0)))
            return results

        rec = CustomFunctionRecognizer(pii_type="SECRET_TOKEN", detector=detector)
        text = "The key is SECRET_ab12 in production."
        entities = rec.find_entities(text)

        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "SECRET_ab12")
        self.assertEqual(entities[0].pii_type, "SECRET_TOKEN")

    def test_custom_function_recognizer_strings(self):
        # Detector returning list of raw strings
        sensitive_keywords = ["ProjectTitan", "CodenameApollo"]

        def detector(text: str):
            return [kw for kw in sensitive_keywords if kw in text]

        rec = CustomFunctionRecognizer(pii_type="CONFIDENTIAL_PROJECT", detector=detector)
        text = "Meeting regarding ProjectTitan and CodenameApollo."
        entities = rec.find_entities(text)

        self.assertEqual(len(entities), 2)
        values = [e.value for e in entities]
        self.assertIn("ProjectTitan", values)
        self.assertIn("CodenameApollo", values)

    def test_custom_function_recognizer_dicts(self):
        # Detector returning dictionaries with start/end
        def detector(text: str):
            matches = []
            for m in re.finditer(r"\bAPIKEY:[a-zA-Z0-9]{8}\b", text):
                matches.append({
                    "start": m.start(),
                    "end": m.end(),
                    "value": m.group(0),
                    "confidence": 0.99,
                })
            return matches

        rec = CustomFunctionRecognizer(pii_type="CUSTOM_KEY", detector=detector)
        text = "Check APIKEY:abcdef12 before sending."
        entities = rec.find_entities(text)
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0].value, "APIKEY:abcdef12")
        self.assertEqual(entities[0].confidence, 0.99)

    def test_create_custom_recognizer_factory(self):
        regex_rec = create_custom_recognizer(
            pii_type="COUPON_CODE",
            pattern=r"\bCOUPON-[A-Z0-9]{6}\b",
        )
        self.assertIsInstance(regex_rec, CustomRegexRecognizer)

        func_rec = create_custom_recognizer(
            pii_type="CUSTOM_CHECK",
            detector=lambda t: [],
        )
        self.assertIsInstance(func_rec, CustomFunctionRecognizer)

        with self.assertRaises(ValueError):
            create_custom_recognizer(pii_type="INVALID")

    def test_firewall_register_custom_recognizer_and_e2e_cycle(self):
        firewall = PIIFirewall()
        mock_tool = SimulatedExternalTool(name="TicketAPI")

        # Register custom recognizer for support tickets
        rec = firewall.register_custom_recognizer(
            pii_type="TICKET_REF",
            pattern=r"\bTICKET-\d{6}\b",
        )
        self.assertIsInstance(rec, CustomRegexRecognizer)

        raw_request = {
            "tool": "TicketAPI",
            "message": "Update customer ticket TICKET-987654 for user alice@corp.test.",
        }

        # Intercept and process
        result = firewall.process_tool_call(
            request_payload=raw_request,
            tool_callable=mock_tool.execute,
        )

        # 1. Verify external tool received NO raw PII or ticket ref
        received = mock_tool.received_payloads[-1]
        self.assertNotIn("TICKET-987654", str(received))
        self.assertNotIn("alice@corp.test", str(received))
        self.assertIn("⟦TICKET_REF_", str(received))
        self.assertIn("⟦EMAIL_", str(received))

        # 2. Verify restored response received by agent has original values
        restored = result["response"]
        restored_str = str(restored)
        self.assertIn("TICKET-987654", restored_str)
        self.assertIn("alice@corp.test", restored_str)
        self.assertGreaterEqual(result["metrics"]["total_detected"], 2)

    def test_firewall_register_custom_recognizer_shorthand(self):
        firewall = PIIFirewall()

        # Positional pattern registration
        firewall.register_custom_recognizer(
            "DEVICE_MAC",
            pattern=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
        )

        payload = {"device_id": "Printer MAC is 00:1B:44:11:3A:B7 on network."}
        fw_res, vault = firewall.intercept_request(payload)

        self.assertNotIn("00:1B:44:11:3A:B7", str(fw_res.sanitized_payload))
        self.assertIn("⟦DEVICE_MAC_", str(fw_res.sanitized_payload))

        # Test restoration
        restored, _ = firewall.intercept_response(
            fw_res.sanitized_payload,
            request_id=fw_res.request_id,
        )
        self.assertEqual(restored["device_id"], payload["device_id"])

    def test_custom_recognizer_with_policy(self):
        policy_engine = PolicyEngine()
        # Define REDACT policy for custom type
        rule = ToolPolicyRule(
            tool_name="PublicExport",
            pii_actions={"INTERNAL_TOKEN": PolicyAction.REDACT},
        )
        policy_engine.add_rule(rule)

        firewall = PIIFirewall(policy_engine=policy_engine)
        firewall.register_custom_recognizer(
            pii_type="INTERNAL_TOKEN",
            pattern=r"\bTOK-[0-9]{4}\b",
        )

        payload = {"tool": "PublicExport", "auth": "Token TOK-8899 generated."}
        fw_res, _ = firewall.intercept_request(payload)

        # Policy specified REDACT -> should be [REDACTED_INTERNAL_TOKEN]
        self.assertIn("[REDACTED_INTERNAL_TOKEN]", str(fw_res.sanitized_payload))
        self.assertNotIn("TOK-8899", str(fw_res.sanitized_payload))

    def test_custom_recognizer_block_policy(self):
        policy_engine = PolicyEngine()
        # Define BLOCK rule for custom type
        rule = ToolPolicyRule(
            tool_name="UntrustedTool",
            blocked_pii_types={"CONFIDENTIAL_KEY"},
        )
        policy_engine.add_rule(rule)

        firewall = PIIFirewall(policy_engine=policy_engine)
        firewall.register_custom_recognizer(
            pii_type="CONFIDENTIAL_KEY",
            pattern=r"\bKEY-[A-Z]{4}\b",
        )

        payload = {"tool": "UntrustedTool", "data": "Using KEY-WXYZ for access."}
        with self.assertRaises(FirewallBlockedError):
            firewall.intercept_request(payload)


class TestBatchPIIFirewall(unittest.TestCase):
    """Tests for BatchPIIFirewall concurrent processing, throughput, and order preservation."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.batch_fw = BatchPIIFirewall(firewall=self.firewall, max_workers=8)

    def test_batch_empty(self):
        result = self.batch_fw.process_batch([])
        self.assertEqual(len(result), 0)
        self.assertEqual(result.total_items, 0)
        self.assertEqual(result.successful_items, 0)
        self.assertEqual(result.failed_items, 0)
        self.assertFalse(result.has_errors)

    def test_batch_single_item(self):
        requests = [{"query": "User email is john.doe@example.org."}]
        result = self.batch_fw.process_batch(requests)

        self.assertEqual(len(result), 1)
        self.assertEqual(result.total_items, 1)
        self.assertEqual(result.successful_items, 1)
        self.assertEqual(result.total_detected_pii, 1)
        self.assertIn("⟦EMAIL_", str(result.sanitized_payloads[0]))
        self.assertNotIn("john.doe@example.org", str(result.sanitized_payloads[0]))

    def test_batch_sanitize_concurrent_multi_items(self):
        # 15 distinct items with varied PII
        requests = [
            {"id": i, "text": f"Customer {i} email: user_{i}@corp.test, phone: +1-555-010-{i:04d}."}
            for i in range(15)
        ]

        batch_result = self.batch_fw.sanitize_batch(requests)

        self.assertEqual(len(batch_result), 15)
        self.assertEqual(batch_result.successful_items, 15)
        self.assertEqual(batch_result.failed_items, 0)
        self.assertFalse(batch_result.has_errors)
        self.assertGreaterEqual(batch_result.total_detected_pii, 30)  # 2 per item

        # Verify strict order preservation
        for i, item_res in enumerate(batch_result):
            self.assertEqual(item_res.index, i)
            payload = item_res.sanitized_payload
            self.assertEqual(payload["id"], i)
            self.assertNotIn(f"user_{i}@corp.test", payload["text"])
            self.assertIn("⟦EMAIL_", payload["text"])
            self.assertIn("⟦PHONE_", payload["text"])

    def test_batch_end_to_end_tool_execution(self):
        mock_tool = SimulatedExternalTool(name="CRM_Batch_Service")

        requests = [
            {
                "tool": "CRM_Batch_Service",
                "arguments": {
                    "account_id": f"ACC-{idx}",
                    "email": f"client_{idx}@finance.test",
                    "card": "4111-1111-1111-1111",  # Valid Luhn Visa
                },
            }
            for idx in range(10)
        ]

        batch_res = self.batch_fw.process_batch(
            requests=requests,
            tool_callable=mock_tool.execute,
        )

        self.assertEqual(len(batch_res), 10)
        self.assertEqual(batch_res.successful_items, 10)
        self.assertGreaterEqual(batch_res.total_detected_pii, 20)
        self.assertGreaterEqual(batch_res.total_restored_pii, 20)

        # Audit external tool: ensure ZERO raw PII ever touched the mock service
        for raw_rcvd in mock_tool.received_payloads:
            rcvd_str = str(raw_rcvd)
            for idx in range(10):
                self.assertNotIn(f"client_{idx}@finance.test", rcvd_str)
            self.assertNotIn("4111-1111-1111-1111", rcvd_str)
            self.assertIn("⟦EMAIL_", rcvd_str)
            self.assertIn("⟦CREDIT_CARD_", rcvd_str)

        # Audit responses: ensure all responses were safely restored
        for idx, restored_resp in enumerate(batch_res.responses):
            resp_str = str(restored_resp)
            self.assertIn(f"client_{idx}@finance.test", resp_str)
            self.assertIn("4111-1111-1111-1111", resp_str)

    def test_batch_order_preservation_under_variable_delays(self):
        # A mock tool with variable artificial latency
        def variable_latency_tool(payload: Dict[str, Any]) -> Dict[str, Any]:
            item_id = payload.get("id", 0)
            # Invert latency: early items take longer, later items finish faster
            sleep_time = (10 - item_id) * 0.005
            time.sleep(max(0.001, sleep_time))
            return {"status": "ok", "echo_id": item_id, "data": payload.get("data")}

        requests = [
            {"id": i, "data": f"Secret email {i}: test{i}@domain.test"}
            for i in range(10)
        ]

        batch_res = self.batch_fw.process_batch(
            requests=requests,
            tool_callable=variable_latency_tool,
        )

        # Verify results match input order 0..9 precisely
        self.assertEqual(len(batch_res), 10)
        for i in range(10):
            item = batch_res[i]
            self.assertEqual(item.index, i)
            self.assertEqual(item.sanitized_payload["id"], i)
            self.assertEqual(item.response["echo_id"], i)
            self.assertIn(f"test{i}@domain.test", item.response["data"])

    def test_batch_resilience_stop_on_error_false(self):
        # Setup policy to block one specific tool request
        policy_engine = PolicyEngine()
        policy_engine.add_rule(
            ToolPolicyRule(
                tool_name="DangerousTool",
                blocked_pii_types={PIIType.EMAIL},
            )
        )
        fw = PIIFirewall(policy_engine=policy_engine)
        batch_processor = BatchPIIFirewall(firewall=fw)

        requests = [
            {"tool": "SafeTool", "payload": "Valid request alice@corp.test"},
            {"tool": "DangerousTool", "payload": "Forbidden request bob@corp.test"},
            {"tool": "SafeTool", "payload": "Valid request charlie@corp.test"},
        ]

        result = batch_processor.process_batch(requests, stop_on_error=False)

        self.assertEqual(len(result), 3)
        self.assertEqual(result.successful_items, 2)
        self.assertEqual(result.failed_items, 1)
        self.assertTrue(result.has_errors)

        # Item 0 succeeded
        self.assertTrue(result[0].success)
        self.assertIn("⟦EMAIL_", str(result[0].sanitized_payload))

        # Item 1 failed with FirewallBlockedError
        self.assertFalse(result[1].success)
        self.assertEqual(result[1].error_type, "FirewallBlockedError")
        self.assertIsNotNone(result[1].error)

        # Item 2 succeeded
        self.assertTrue(result[2].success)
        self.assertIn("⟦EMAIL_", str(result[2].sanitized_payload))

    def test_batch_stop_on_error_true_raises(self):
        policy_engine = PolicyEngine()
        policy_engine.add_rule(
            ToolPolicyRule(
                tool_name="BlockedTool",
                blocked_pii_types={PIIType.EMAIL},
            )
        )
        fw = PIIFirewall(policy_engine=policy_engine)
        batch_processor = BatchPIIFirewall(firewall=fw)

        requests = [
            {"tool": "BlockedTool", "payload": "Forbidden user@corp.test"},
        ]

        with self.assertRaises(FirewallBlockedError):
            batch_processor.process_batch(requests, stop_on_error=True)

    def test_batch_restore_batch_method(self):
        # First sanitize 5 requests
        requests = [f"Contact user_{i}@corp.test" for i in range(5)]
        req_ids = [f"req-batch-{i}" for i in range(5)]
        sanitize_res = self.batch_fw.sanitize_batch(requests, request_ids=req_ids)

        # Prepare tool responses containing the opaque tokens
        tool_responses = [
            (f"Service acknowledged: {sanitize_res[i].sanitized_payload}", req_ids[i])
            for i in range(5)
        ]

        # Restore concurrently
        restored_list = self.batch_fw.restore_batch(tool_responses)
        self.assertEqual(len(restored_list), 5)

        for i, (restored_payload, metrics) in enumerate(restored_list):
            self.assertEqual(restored_payload, f"Service acknowledged: Contact user_{i}@corp.test")
            self.assertEqual(metrics.restored_count, 1)

    def test_batch_result_properties_and_protocols(self):
        requests = ["Hello alex@corp.test", "Call +1-555-234-5678"]
        batch_res = self.batch_fw.process_batch(requests)

        # __len__
        self.assertEqual(len(batch_res), 2)

        # Indexing and slicing
        self.assertIsInstance(batch_res[0], BatchItemResult)
        self.assertEqual(len(batch_res[:1]), 1)

        # Iteration
        items = list(iter(batch_res))
        self.assertEqual(len(items), 2)

        # Dictionary export
        d = batch_res.to_dict()
        self.assertIn("throughput_items_per_sec", d)
        self.assertIn("total_duration_ms", d)
        self.assertEqual(d["total_items"], 2)
        self.assertEqual(d["successful_items"], 2)

    def test_firewall_convenience_process_batch(self):
        # PIIFirewall has direct .process_batch(...) method
        requests = ["Testing direct fw process_batch with alice@test.com"]
        res = self.firewall.process_batch(requests)
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0].success)
        self.assertIn("⟦EMAIL_", str(res[0].sanitized_payload))

    def test_batch_combined_with_custom_recognizer(self):
        # Register custom recognizer on batch processor
        self.batch_fw.register_custom_recognizer(
            pii_type="DEVICE_SERIAL",
            pattern=r"\bSN-[A-Z0-9]{8}\b",
        )

        mock_tool = SimulatedExternalTool(name="InventoryService")
        requests = [
            {
                "tool": "InventoryService",
                "serial": f"SN-ABCD{i:04d}",
                "contact": f"admin_{i}@devices.internal",
            }
            for i in range(6)
        ]

        res = self.batch_fw.process_batch(requests, tool_callable=mock_tool.execute)
        self.assertEqual(len(res), 6)
        self.assertEqual(res.successful_items, 6)

        # Verify tool got tokens for both custom PII and email
        for rcvd in mock_tool.received_payloads:
            rcvd_str = str(rcvd)
            self.assertIn("⟦DEVICE_SERIAL_", rcvd_str)
            self.assertIn("⟦EMAIL_", rcvd_str)

        # Verify agent got back original values
        for i, resp in enumerate(res.responses):
            resp_str = str(resp)
            self.assertIn(f"SN-ABCD{i:04d}", resp_str)
            self.assertIn(f"admin_{i}@devices.internal", resp_str)


if __name__ == "__main__":
    unittest.main()
