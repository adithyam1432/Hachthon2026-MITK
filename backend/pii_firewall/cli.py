"""
Command-Line Interface (CLI) for PII Firewall for AI Agents.
Usage:
  python -m pii_firewall.cli scan '{"email": "alex@test.com"}'
  python -m pii_firewall.cli benchmark --runs 200
  python -m pii_firewall.cli serve --port 5000
"""

import argparse
import json
import statistics
import sys
import time
from pii_firewall.middleware import PIIFirewall
from pii_firewall.simulated_tool import SimulatedExternalTool


def main():
    parser = argparse.ArgumentParser(
        description="🛡️ PII Firewall for AI Agents — CLI Utility"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Scan and sanitize a JSON payload")
    scan_parser.add_argument("payload", nargs="+", help="Raw JSON string or file path to inspect")

    # Command: benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Run latency and throughput benchmark")
    bench_parser.add_argument("--runs", type=int, default=100, help="Number of benchmark iterations")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Start the REST API proxy server")
    serve_parser.add_argument("--port", type=int, default=5000, help="Port to listen on")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    firewall = PIIFirewall()

    if args.command == "scan":
        raw_text = " ".join(args.payload)
        if raw_text == "-":
            raw_text = sys.stdin.read().strip()

        try:
            # Check if file path
            with open(raw_text, "r", encoding="utf-8") as f:
                parsed = json.load(f)
        except Exception:
            try:
                parsed = json.loads(raw_text)
            except Exception:
                try:
                    import ast
                    parsed = ast.literal_eval(raw_text)
                except Exception:
                    try:
                        # Auto-repair unquoted keys from PowerShell (e.g., {tool: send_email, ...})
                        import re
                        repaired = re.sub(r'([{,]\s*)([a-zA-Z_]\w*)\s*:', r'\1"\2":', raw_text)
                        repaired = re.sub(r':\s*([a-zA-Z_]\w*)([,\s}])', r': "\1"\2', repaired)
                        parsed = json.loads(repaired)
                    except Exception as e:
                        print(f"Error parsing JSON input: {e}")
                        sys.exit(1)

        sim_tool = SimulatedExternalTool("CLI_Tool")
        envelope = firewall.process_tool_call(parsed, sim_tool.execute)
        print("\n--- SANITIZED PAYLOAD SENT TO TOOL ---")
        print(json.dumps(envelope["sanitized_payload_sent"], indent=2))
        print("\n--- RESTORED RESPONSE TO AGENT ---")
        print(json.dumps(envelope["response"], indent=2))
        print("\n--- SAFE METRICS ---")
        print(json.dumps(envelope["metrics"], indent=2))

    elif args.command == "benchmark":
        runs = args.runs
        sim_tool = SimulatedExternalTool("Bench_Tool")
        sample_payload = {
            "tool": "dispatch_support_ticket",
            "arguments": {
                "client": {
                    "email": "customer@company.test",
                    "phone": "+1-555-876-5432",
                    "ssn": "123-45-6789",
                    "card": "4111-1111-1111-1111"
                },
                "notes": "Verify Aadhaar 3675 9834 6016 and PAN ABCPE1234F before dispatch."
            }
        }

        print(f"Running PII Firewall performance benchmark ({runs} iterations)...")
        durations = []
        for _ in range(runs):
            t0 = time.perf_counter()
            firewall.process_tool_call(sample_payload, sim_tool.execute)
            durations.append((time.perf_counter() - t0) * 1000.0)

        print("\n" + "=" * 50)
        print(f"BENCHMARK RESULTS ({runs} iterations)")
        print("=" * 50)
        print(f"Average: {statistics.mean(durations):.3f} ms")
        print(f"Median:  {statistics.median(durations):.3f} ms")
        print(f"P95:     {statistics.quantiles(durations, n=20)[18]:.3f} ms")
        print(f"Min/Max: {min(durations):.3f} ms / {max(durations):.3f} ms")
        print("=" * 50)

    elif args.command == "serve":
        from pii_firewall.server import create_app
        app = create_app(firewall)
        print(f"Starting PII Firewall REST Server on port {args.port}...")
        app.run(host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
