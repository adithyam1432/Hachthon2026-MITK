"""
Performance and Latency Benchmark Tests.
Covers Non-functional Requirements & Section 6 Metrics (average, p95 processing time).
"""

import statistics
import time
import unittest
from pii_firewall.middleware import PIIFirewall
from pii_firewall.simulated_tool import SimulatedExternalTool


class TestPerformanceBenchmarks(unittest.TestCase):

    def setUp(self):
        self.firewall = PIIFirewall()
        self.tool = SimulatedExternalTool("BenchService")

    def test_processing_overhead_benchmark(self):
        """Runs 100 iterations of complex request to establish latency distribution."""
        sample_payload = {
            "action": "dispatch_support_ticket",
            "customer": {
                "id": "CUST-9921",
                "email": "customer.primary@enterprise.test",
                "phone": "+1-555-876-5432",
                "backup_email": "customer.secondary@enterprise.test",
            },
            "conversation_history": [
                {"role": "user", "text": "Hi, my phone is +1-555-876-5432 and SSN on file is 123-45-6789."},
                {"role": "assistant", "text": "Got it, checking payment card 4532-0150-1234-5678."},
                {"role": "user", "text": "Thanks, contact me back at customer.primary@enterprise.test."}
            ]
        }

        latencies_ms = []
        iterations = 100

        # Warm up
        for _ in range(5):
            self.firewall.process_tool_call(sample_payload, self.tool.execute)

        # Timed benchmark
        for _ in range(iterations):
            start = time.perf_counter()
            self.firewall.process_tool_call(sample_payload, self.tool.execute)
            duration_ms = (time.perf_counter() - start) * 1000.0
            latencies_ms.append(duration_ms)

        avg_latency = statistics.mean(latencies_ms)
        p95_latency = statistics.quantiles(latencies_ms, n=20)[18]  # 95th percentile
        median_latency = statistics.median(latencies_ms)

        print("\n" + "=" * 50)
        print("PII FIREWALL PERFORMANCE BENCHMARK (100 runs)")
        print("=" * 50)
        print(f"Iterations: {iterations}")
        print(f"Average latency:  {avg_latency:.3f} ms")
        print(f"Median latency:   {median_latency:.3f} ms")
        print(f"P95 latency:      {p95_latency:.3f} ms")
        print(f"Min / Max:        {min(latencies_ms):.3f} ms / {max(latencies_ms):.3f} ms")
        print("=" * 50)

        # Baseline criteria: Should easily complete well under 25ms per call locally
        self.assertLess(avg_latency, 25.0, f"Average latency too high: {avg_latency} ms")


if __name__ == "__main__":
    unittest.main()
