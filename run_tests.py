"""
Automated Test Runner for PII Firewall Test Suite.
Executes all unit, E2E, leakage, adversarial, and massive synthetic test cases with structured reporting.
"""

import sys
import unittest
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def run_all_tests():
    import os
    os.environ["GEMINI_UNIT_TEST_MODE"] = "1"

    # Ensure backend directory is in sys.path
    backend_dir = Path(__file__).resolve().parent / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    # Discover all test modules in the tests directory
    loader = unittest.TestLoader()
    tests_dir = Path(__file__).resolve().parent / "tests"
    suite = loader.discover(str(tests_dir), pattern="test_*.py")

    start_time = time.perf_counter()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    elapsed = time.perf_counter() - start_time

    total_run = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    successes = total_run - failures - errors

    print("\n" + "=" * 70)
    print("  🛡️  PII FIREWALL — EXHAUSTIVE TEST MATRIX SUMMARY")
    print("=" * 70)
    print(f"Total Tests Discovered & Executed: {total_run} tests")
    print(f"Successes:                         {successes}")
    print(f"Failures:                          {failures}")
    print(f"Errors:                            {errors}")
    if total_run > 0:
        print(f"Pass Rate:                         {(successes / total_run * 100):.1f}%")
    print(f"Total Test Execution Time:         {elapsed:.3f}s")
    print("=" * 70)

    if str(tests_dir) not in sys.path:
        sys.path.insert(0, str(tests_dir))

    if total_run >= 500:
        print(f"🔥 STRESS MILESTONE ACHIEVED: 500+ Automated Stress Matrix Executed ({total_run} tests).")
    elif total_run >= 250:
        print(f"✅ MILESTONE ACHIEVED: Massive synthetic test matrix exceeds 250+ cases ({total_run} tests).")

    try:
        from test_500_stress_iterations import print_formatted_report
        print_formatted_report()
    except Exception:
        pass

    if result.wasSuccessful() and total_run > 0:
        print(">>> ALL TEST CASES PASSED CLEANLY (100% SUCCESS) <<<")
        return 0
    else:
        print(">>> SOME TESTS FAILED <<<")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
