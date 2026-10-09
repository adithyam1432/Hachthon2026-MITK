"""
High-Throughput Concurrency & Thread-Safety Stress Test.
Validates multi-threaded isolation and performance under concurrent agent requests.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import unittest
from pii_firewall.middleware import PIIFirewall
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestConcurrencyAndThreadSafety(unittest.TestCase):

    def setUp(self):
        self.firewall = PIIFirewall()
        self.simulated_tool = SimulatedExternalTool("ConcurrentService")

    def test_multi_threaded_isolation_and_restoration(self):
        """Simulates 50 concurrent agent threads firing simultaneous tool calls."""
        num_threads = 50
        results = []

        def _worker(worker_id: int):
            worker_email = f"agent_worker_{worker_id}@cluster.test"
            worker_phone = f"+1-555-010-{worker_id:04d}"
            payload = {
                "tool": "concurrent_dispatch",
                "arguments": {
                    "worker_id": worker_id,
                    "email": worker_email,
                    "phone": worker_phone,
                    "task": f"Process background batch {worker_id}"
                }
            }

            envelope = self.firewall.process_tool_call(
                request_payload=payload,
                tool_callable=self.simulated_tool.execute,
            )
            return worker_id, worker_email, worker_phone, envelope

        start_time = time.perf_counter()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_worker, i) for i in range(num_threads)]
            for future in as_completed(futures):
                results.append(future.result())
        elapsed_total = time.perf_counter() - start_time

        self.assertEqual(len(results), num_threads)

        # Audit each concurrent thread execution
        for w_id, w_email, w_phone, envelope in results:
            # 1. Verify response re-hydration restored this exact worker's PII
            restored = envelope["response"]
            self.assertEqual(restored["echo_arguments"]["email"], w_email)
            self.assertEqual(restored["echo_arguments"]["phone"], w_phone)

            # 2. Verify payload sent to tool did NOT contain raw PII
            sanitized = envelope["sanitized_payload_sent"]
            self.assertNotIn(w_email, str(sanitized))
            self.assertNotIn(w_phone, str(sanitized))
            self.assertTrue(sanitized["arguments"]["email"].startswith("⟦EMAIL_"))

        # Verify simulated tool never received any worker's PII
        all_emails = [r[1] for r in results]
        self.assertFalse(self.simulated_tool.contains_any_string(all_emails))

        throughput = num_threads / elapsed_total
        print(f"\n[Concurrency Benchmark] {num_threads} concurrent requests processed in {elapsed_total:.3f}s ({throughput:.1f} req/sec)")
        self.assertGreater(throughput, 50.0, "Concurrent throughput is healthy")


if __name__ == "__main__":
    unittest.main()
