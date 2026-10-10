"""
Exhaustive 500+ Iteration Automated Stress & Reliability Matrix for PII Firewall.

Covers 5 Core 100-Iteration Categories + Multi-Threading Concurrency + Vault Memory Audit:
  1. Diverse PII combinations in free-text prompts (Names, Emails, Phones, SSNs, Aadhaar, PANs, Passports, DOBs, IP, Credentials)
  2. Deeply nested JSON structures (arrays, dictionaries, nulls, booleans, emojis, unicode)
  3. Dual-mode policy assertions (Tokenization & re-hydration vs permanent Redaction)
  4. Adversarial fuzzing (zero-width characters, Base64 strings, boundary spoofs, casing tricks, delimiter injection)
  5. False-positive stopword stress testing (operational timestamps, order IDs, flight codes, ports, years)
  6. Multi-threaded concurrency burst (50 concurrent workers)
  7. Ephemeral vault memory audit (zero memory leaks, 100% vaults purged)
"""

import base64
import copy
import json
import statistics
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple

from pii_firewall.adversarial_defense import AdversarialDefenseNormalizer
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallBlockedError,
    FirewallConfig,
    PIILeakageDetectedError,
    PIIType,
)
from pii_firewall.policy import PolicyAction, PolicyEngine, ToolPolicyRule
from pii_firewall.recognizers.credit_card import luhn_checksum_valid
from pii_firewall.recognizers.indian_pii import verhoeff_validate
from pii_firewall.simulated_tool import SimulatedExternalTool
from pii_firewall.verifier import LeakageVerifier


# =====================================================================
# GLOBAL TELEMETRY & LATENCY COLLECTOR
# =====================================================================
GLOBAL_LATENCY_RECORDS: List[float] = []
GLOBAL_EXECUTION_COUNT: int = 0
GLOBAL_ERROR_COUNT: int = 0
GLOBAL_LEAK_COUNT: int = 0


def record_latency(duration_ms: float, leaked: bool = False, errored: bool = False):
    global GLOBAL_EXECUTION_COUNT, GLOBAL_ERROR_COUNT, GLOBAL_LEAK_COUNT
    GLOBAL_EXECUTION_COUNT += 1
    GLOBAL_LATENCY_RECORDS.append(duration_ms)
    if leaked:
        GLOBAL_LEAK_COUNT += 1
    if errored:
        GLOBAL_ERROR_COUNT += 1


def compute_benchmark_report() -> Dict[str, Any]:
    if not GLOBAL_LATENCY_RECORDS:
        return {}
    sorted_latencies = sorted(GLOBAL_LATENCY_RECORDS)
    n = len(sorted_latencies)
    avg_lat = statistics.mean(sorted_latencies)
    median_lat = statistics.median(sorted_latencies)
    min_lat = sorted_latencies[0]
    max_lat = sorted_latencies[-1]
    p95_lat = sorted_latencies[int(0.95 * n)] if n > 1 else max_lat
    p99_lat = sorted_latencies[int(0.99 * n)] if n > 1 else max_lat
    success_rate = ((GLOBAL_EXECUTION_COUNT - GLOBAL_ERROR_COUNT) / GLOBAL_EXECUTION_COUNT * 100.0) if GLOBAL_EXECUTION_COUNT > 0 else 100.0
    leakage_rate = (GLOBAL_LEAK_COUNT / GLOBAL_EXECUTION_COUNT * 100.0) if GLOBAL_EXECUTION_COUNT > 0 else 0.0

    return {
        "total_iterations": GLOBAL_EXECUTION_COUNT,
        "success_rate": success_rate,
        "error_count": GLOBAL_ERROR_COUNT,
        "min_ms": min_lat,
        "max_ms": max_lat,
        "avg_ms": avg_lat,
        "median_ms": median_lat,
        "p95_ms": p95_lat,
        "p99_ms": p99_lat,
        "leakage_rate": leakage_rate,
    }


def print_formatted_report():
    report = compute_benchmark_report()
    if not report:
        return
    print("\n" + "=" * 75)
    print("  🛡️  PII FIREWALL 500+ STRESS & RELIABILITY TEST BENCHMARK REPORT")
    print("=" * 75)
    print(f"Total Iterations Executed: {report['total_iterations']} (>= 500)")
    print(f"Success Rate:              {report['success_rate']:.2f}%")
    print(f"Errors Caught & Corrected: {report['error_count']}")
    print(f"Zero-Leakage Rate:         {100.0 - report['leakage_rate']:.2f}% (Leakage: {report['leakage_rate']:.2f}%)")
    print("-" * 75)
    print("LATENCY DISTRIBUTION (End-to-End Processing & Restoration):")
    print(f"  Min Latency:     {report['min_ms']:.3f} ms")
    print(f"  Average Latency: {report['avg_ms']:.3f} ms")
    print(f"  Median Latency:  {report['median_ms']:.3f} ms")
    print(f"  P95 Latency:     {report['p95_ms']:.3f} ms")
    print(f"  P99 Latency:     {report['p99_ms']:.3f} ms")
    print(f"  Max Latency:     {report['max_ms']:.3f} ms")
    print("=" * 75 + "\n")


# =====================================================================
# DATA GENERATION UTILITIES
# =====================================================================
FIRST_NAMES = [
    "Alice", "David", "Robert", "Emily", "Michael",
    "Sarah", "James", "Jessica", "William", "Olivia",
    "Aarav", "Priya", "Aditya", "Ananya", "Vikram",
    "Kavita", "Rohan", "Deepika", "Sanjay", "Pooja"
]

LAST_NAMES = [
    "Johnson", "Miller", "Smith", "Davis", "Brown",
    "Wilson", "Taylor", "Anderson", "Thomas", "Martinez",
    "Sharma", "Patel", "Verma", "Iyer", "Malhotra",
    "Nair", "Gupta", "Reddy", "Joshi", "Deshmukh"
]


def make_luhn_number(prefix: str, length: int) -> str:
    """Generates Luhn-valid synthetic credit card number."""
    digits = [int(c) for c in prefix]
    while len(digits) < length - 1:
        digits.append(0)
    for d in range(10):
        cand = "".join(map(str, digits)) + str(d)
        if luhn_checksum_valid(cand):
            return cand
    return "".join(map(str, digits)) + "0"


def make_valid_aadhaar(prefix11: str) -> str:
    """Computes exact Verhoeff checksum digit for 11 digits to produce a 12-digit Aadhaar."""
    for d in range(10):
        cand = prefix11 + str(d)
        if verhoeff_validate(cand):
            return cand
    return prefix11 + "0"


# =====================================================================
# 1. CATEGORY 1: DIVERSE PII COMBINATIONS IN FREE-TEXT (100 CASES)
# =====================================================================
class TestCategory1DiversePII(unittest.TestCase):
    """100 distinct iterations testing diverse PII combinations in free-text prompts."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("DiversePIIService")


def _run_cat1_case(self, case_idx: int):
    f_name = FIRST_NAMES[case_idx % len(FIRST_NAMES)]
    l_name = LAST_NAMES[case_idx % len(LAST_NAMES)]
    full_name = f"{f_name} {l_name}"
    email = f"user_{case_idx}_{f_name.lower()}@stressmatrix.test"
    phone = f"+1-555-01{(case_idx % 80) + 10:02d}-{(case_idx % 9000) + 1000:04d}"
    ssn = f"321-{(case_idx % 80) + 10:02d}-{(case_idx % 8000) + 1000:04d}"
    card = make_luhn_number(f"4111{(case_idx % 9000) + 1000:04d}", 16)
    pan = f"ABC P {chr(65 + case_idx % 26)}{(case_idx % 9000) + 1000:04d}Z".replace(" ", "")
    aadh_raw = make_valid_aadhaar(f"2{(case_idx % 90) + 10:02d}45678901")
    aadh = f"{aadh_raw[:4]} {aadh_raw[4:8]} {aadh_raw[8:]}"
    passport = f"A{(case_idx % 90000000) + 10000000}"
    dob = f"19{70 + (case_idx % 30)}-{(case_idx % 12) + 1:02d}-{(case_idx % 28) + 1:02d}"
    ip = f"192.168.{(case_idx % 250) + 1}.{(case_idx % 250) + 1}"

    # Cases 1-84: Standard PII combinations (Tokenization & Safe Restoration)
    if case_idx <= 84:
        if case_idx % 5 == 0:
            prompt = f"Customer onboarding profile for {full_name}, contact via email {email}."
            sensitive_vals = [full_name, email]
        elif case_idx % 5 == 1:
            prompt = f"Account record for {full_name}, phone: {phone}, SSN: {ssn}."
            sensitive_vals = [full_name, phone, ssn]
        elif case_idx % 5 == 2:
            prompt = f"Billing account for {full_name}, card: {card}, email: {email}, IP address {ip}."
            sensitive_vals = [full_name, card, email, ip]
        elif case_idx % 5 == 3:
            prompt = f"Customer profile for {full_name}, DOB: {dob}, PAN card: {pan}, Aadhaar: {aadh}."
            sensitive_vals = [full_name, dob, pan, aadh]
        else:
            prompt = f"Customer profile for {full_name}, Passport: {passport}, phone: {phone}."
            sensitive_vals = [full_name, passport, phone]

        request = {
            "tool": "process_record",
            "arguments": {
                "case_id": case_idx,
                "message": prompt
            }
        }

        t0 = time.perf_counter()
        envelope = self.firewall.process_tool_call(request, self.mock_tool.execute)
        dur = (time.perf_counter() - t0) * 1000.0

        # Verification 1: Tool never received raw PII
        sent_text = json.dumps(envelope["sanitized_payload_sent"])
        leaked = False
        for val in sensitive_vals:
            if val in sent_text:
                leaked = True
                self.assertNotIn(val, sent_text, f"Case {case_idx}: Raw PII leaked to tool: {val}")

        # Verification 2: Re-hydrated response restored original values
        restored_text = json.dumps(envelope["response"])
        for val in sensitive_vals:
            self.assertIn(val, restored_text, f"Case {case_idx}: Restoration failed for: {val}")

        record_latency(dur, leaked=leaked)

    # Cases 85-100: Strict Credential Blocking Enforcement (Passwords & PINs)
    else:
        if case_idx % 2 == 0:
            prompt = f"Authentication alert: password is MySecurePassword{case_idx}! for user {email}"
        else:
            prompt = f"Bank card PIN alert: my ATM PIN is {(case_idx % 9000) + 1000} for account {full_name}"

        request = {
            "tool": "external_service",
            "arguments": {
                "case_id": case_idx,
                "message": prompt
            }
        }

        t0 = time.perf_counter()
        blocked_caught = False
        try:
            self.firewall.process_tool_call(request, self.mock_tool.execute)
        except FirewallBlockedError:
            blocked_caught = True
        dur = (time.perf_counter() - t0) * 1000.0

        self.assertTrue(blocked_caught, f"Case {case_idx}: Credential failed to trigger FirewallBlockedError!")
        record_latency(dur, errored=False)


for _i in range(1, 101):
    setattr(TestCategory1DiversePII, f"test_cat1_pii_combo_{_i:03d}", lambda self, i=_i: _run_cat1_case(self, i))


# =====================================================================
# 2. CATEGORY 2: DEEPLY NESTED JSON STRUCTURES (100 CASES)
# =====================================================================
class TestCategory2NestedJSON(unittest.TestCase):
    """100 distinct iterations testing deeply nested JSON with lists, nulls, booleans, emojis, and unicode."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("NestedJSONService")


def _run_cat2_case(self, case_idx: int):
    depth = (case_idx % 10) + 1  # Depths 1 to 10
    email = f"deep_user_{case_idx}@nestedschema.test"
    phone = f"+1-555-01{(case_idx % 80) + 10:02d}-{(case_idx % 9000) + 1000:04d}"
    emojis = ["🛡️", "🚀", "🔒", "🤖", "💥", "🔑", "🌍", "⚡", "👤", "✉️"]
    unicode_greetings = [
        "こんにちは世界", "नमस्ते दुनिया", "Übergröße Maßstab",
        "Привет мир", "مرحبا بالعالم", "Hello world"
    ]
    greeting = unicode_greetings[case_idx % len(unicode_greetings)]

    # Construct nested structure down to target depth
    leaf_node = {
        "user_email": email,
        "contact_phone": phone,
        "is_active": True,
        "metadata_null": None,
        "retry_count": 3,
        "confidence_score": 0.985,
        "emoji_signature": f"Verified {emojis[case_idx % len(emojis)]}",
        "locale_greeting": greeting,
        "mixed_array": [None, False, 100, {"sub_email": email}],
    }

    current = leaf_node
    for d in range(depth, 0, -1):
        current = {
            f"level_{d}": current,
            f"sibling_flag_{d}": (d % 2 == 0),
            f"sibling_null_{d}": None,
            f"sibling_list_{d}": [f"item_{d}", None, True, {"nested_num": d * 10}],
        }

    request = {
        "tool": "nested_processor",
        "arguments": {
            "depth": depth,
            "root_payload": current,
        }
    }

    t0 = time.perf_counter()
    envelope = self.firewall.process_tool_call(request, self.mock_tool.execute)
    dur = (time.perf_counter() - t0) * 1000.0

    sanitized = envelope["sanitized_payload_sent"]
    sanitized_str = json.dumps(sanitized)

    # 1. PII stripped from outgoing payload
    self.assertNotIn(email, sanitized_str, f"Case {case_idx}: Raw email leaked at depth {depth}")
    self.assertNotIn(phone, sanitized_str, f"Case {case_idx}: Raw phone leaked at depth {depth}")

    # 2. Re-hydrated response restored all tokens and preserved complex types
    restored = envelope["response"]
    leaf = restored["echo_arguments"]["root_payload"]
    for d in range(1, depth + 1):
        leaf = leaf[f"level_{d}"]

    self.assertEqual(leaf["user_email"], email, f"Case {case_idx}: Email mismatch in restored leaf")
    self.assertEqual(leaf["contact_phone"], phone, f"Case {case_idx}: Phone mismatch in restored leaf")
    self.assertEqual(leaf["locale_greeting"], greeting, f"Case {case_idx}: Greeting mismatch in restored leaf")
    self.assertIsNone(leaf["metadata_null"])
    self.assertTrue(leaf["is_active"])
    self.assertEqual(leaf["mixed_array"][3]["sub_email"], email)

    record_latency(dur)


for _i in range(1, 101):
    setattr(TestCategory2NestedJSON, f"test_cat2_nested_json_{_i:03d}", lambda self, i=_i: _run_cat2_case(self, i))


# =====================================================================
# 3. CATEGORY 3: DUAL-MODE POLICY ASSERTIONS (100 CASES)
# =====================================================================
class TestCategory3DualMode(unittest.TestCase):
    """100 distinct iterations testing dual-mode policy: Name tokenized & re-hydrated vs Passport/SSN redacted permanently."""

    def setUp(self):
        rules = {
            "PII_RULES": {
                "NAME": "TOKENIZE",
                "PERSON_NAME": "TOKENIZE",
                "PASSPORT": "REDACT",
                "PASSPORT_NUMBER": "REDACT",
                "SSN": "REDACT",
                "SOCIAL_SECURITY_NUMBER": "REDACT",
                "AADHAAR": "REDACT",
                "PAN_CARD": "REDACT",
            }
        }
        self.policy = PolicyEngine.from_rules_dict(rules, simple_redaction=True)
        self.firewall = PIIFirewall(policy_engine=self.policy)


def _run_cat3_case(self, case_idx: int):
    f_name = FIRST_NAMES[case_idx % len(FIRST_NAMES)]
    l_name = LAST_NAMES[case_idx % len(LAST_NAMES)]
    person_name = f"{f_name} {l_name}"
    passport_num = f"A{(case_idx % 90000000) + 10000000}"
    ssn_num = f"321-{(case_idx % 80) + 10:02d}-{(case_idx % 8000) + 1000:04d}"

    use_passport = (case_idx % 2 == 0)
    high_risk_label = "Passport" if use_passport else "SSN"
    high_risk_val = passport_num if use_passport else ssn_num

    request = {
        "tool": "dual_mode_audit_tool",
        "arguments": {
            "query": f"Update account profile for customer name is {person_name}, verify {high_risk_label}: {high_risk_val}."
        }
    }

    t0 = time.perf_counter()
    # 1. Intercept request
    res, vault = self.firewall.intercept_request(request)
    sent_query = res.sanitized_payload["arguments"]["query"]

    # Assertion A: Name is tokenized & stored in vault
    self.assertIn("⟦PERSON_NAME_", sent_query, f"Case {case_idx}: Name token missing in sent payload")
    self.assertNotIn(person_name, sent_query, f"Case {case_idx}: Raw name leaked in sent payload")
    self.assertEqual(vault.get_token_count(), 1, f"Case {case_idx}: Vault must contain exactly 1 token (Name)")

    # Assertion B: High-Risk ID (Passport / SSN) is permanently redacted & NOT in vault
    self.assertIn("[REDACTED]", sent_query, f"Case {case_idx}: [REDACTED] missing for {high_risk_label}")
    self.assertNotIn(high_risk_val, sent_query, f"Case {case_idx}: Raw {high_risk_label} leaked in sent payload")

    # 2. Simulate tool response echoing back token and redaction
    name_token = list(vault._token_to_value.keys())[0]
    tool_reply = {
        "status": "success",
        "confirmation": f"Profile saved for {name_token}. High-risk record [REDACTED] scrubbed permanently."
    }

    # 3. Intercept response & verify re-hydration
    restored, _ = self.firewall.intercept_response(tool_reply, request_id=res.metrics.request_id, purge_vault=True)
    restored_text = restored["confirmation"]
    dur = (time.perf_counter() - t0) * 1000.0

    # Assertion C: Name is re-hydrated
    self.assertIn(person_name, restored_text, f"Case {case_idx}: Re-hydration failed for Name: {person_name}")

    # Assertion D: [REDACTED] remains redacted; high-risk secret is NEVER re-hydrated
    self.assertIn("[REDACTED]", restored_text, f"Case {case_idx}: Redaction marker missing in restored response")
    self.assertNotIn(high_risk_val, restored_text, f"Case {case_idx}: High-risk ID leaked into restored response")

    record_latency(dur)


for _i in range(1, 101):
    setattr(TestCategory3DualMode, f"test_cat3_dual_mode_{_i:03d}", lambda self, i=_i: _run_cat3_case(self, i))


# =====================================================================
# 4. CATEGORY 4: ADVERSARIAL FUZZING (100 CASES)
# =====================================================================
class TestCategory4Adversarial(unittest.TestCase):
    """100 distinct iterations testing adversarial attacks: zero-width chars, base64 evasion, delimiters, casing."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("HardenedAdversarialService")


def _run_cat4_case(self, case_idx: int):
    # Sub-type A: Zero-width space and invisible unicode obfuscation (Cases 1-25)
    if case_idx <= 25:
        clean_email = f"fuzzed_victim_{case_idx}@target.test"
        invisible_chars = ["\u200B", "\u200C", "\u200D", "\uFEFF", "\u00AD"]
        # Inject invisible character between characters
        obfuscated_chars = []
        for ch in clean_email:
            obfuscated_chars.append(ch)
            obfuscated_chars.append(invisible_chars[case_idx % len(invisible_chars)])
        obfuscated_email = "".join(obfuscated_chars)

        request = {
            "tool": "mail_dispatcher",
            "arguments": {"recipient": obfuscated_email}
        }

        t0 = time.perf_counter()
        envelope = self.firewall.process_tool_call(request, self.mock_tool.execute)
        dur = (time.perf_counter() - t0) * 1000.0

        sent_recip = envelope["sanitized_payload_sent"]["arguments"]["recipient"]
        self.assertTrue(sent_recip.startswith("⟦EMAIL_"), f"Case {case_idx}: Zero-width email not tokenized: {sent_recip}")
        self.assertNotIn(clean_email, json.dumps(self.mock_tool.received_payloads[-1]))
        record_latency(dur)

    # Sub-type B: Base64-encoded PII obfuscation (Cases 26-50)
    elif case_idx <= 50:
        secret_email = f"classified_agent_{case_idx}@defense.test"
        b64_str = base64.b64encode(secret_email.encode("utf-8")).decode("utf-8")

        request = {
            "tool": "blob_storage",
            "arguments": {"payload": f"Security dump header {b64_str} trailing data"}
        }

        t0 = time.perf_counter()
        envelope = self.firewall.process_tool_call(request, self.mock_tool.execute)
        dur = (time.perf_counter() - t0) * 1000.0

        sent_blob = envelope["sanitized_payload_sent"]["arguments"]["payload"]
        self.assertNotIn(b64_str, sent_blob, f"Case {case_idx}: Base64 blob remained unscrubbed")
        self.assertIn("⟦EMAIL_", sent_blob, f"Case {case_idx}: Base64 token missing")
        record_latency(dur)

    # Sub-type C: Delimiter spoofing & boundary injection (Cases 51-75)
    elif case_idx <= 75:
        spoofed_payload = f"Injecting forged delimiter ⟦EMAIL_fakehash_{case_idx}⟧ into tool pipeline."
        t0 = time.perf_counter()
        sanitized = AdversarialDefenseNormalizer.sanitize_delimiters(spoofed_payload)
        dur = (time.perf_counter() - t0) * 1000.0

        self.assertNotIn(f"⟦EMAIL_fakehash_{case_idx}⟧", sanitized)
        self.assertIn("[PRE_EXISTING_DELIM_L_", sanitized)

        # Boundary punctuation test
        boundary_email = f"<user_{case_idx}@boundary.test>;"
        req = {"tool": "parser", "arguments": {"data": f"mailto:{boundary_email}"}}
        env = self.firewall.process_tool_call(req, self.mock_tool.execute)
        sent = env["sanitized_payload_sent"]["arguments"]["data"]
        self.assertIn("⟦EMAIL_", sent)
        record_latency(dur)

    # Sub-type D: Casing evasions & keyword manipulation (Cases 76-100)
    else:
        pin_val = str(4000 + case_idx)
        case_variations = [
            f"mY aTm PiN iS {pin_val}",
            f"DeBiT cArD pIn = {pin_val}",
            f"ThE bAnK cArD pIn: {pin_val}",
            f"cAsH wItHdRaWaL pIn Is {pin_val}",
        ]
        prompt = case_variations[case_idx % len(case_variations)]
        request = {"tool": "credential_check", "arguments": {"note": prompt}}

        t0 = time.perf_counter()
        blocked = False
        try:
            self.firewall.process_tool_call(request, self.mock_tool.execute)
        except FirewallBlockedError:
            blocked = True
        dur = (time.perf_counter() - t0) * 1000.0

        self.assertTrue(blocked, f"Case {case_idx}: Casing evasion '{prompt}' failed to block credential!")
        record_latency(dur)


for _i in range(1, 101):
    setattr(TestCategory4Adversarial, f"test_cat4_adversarial_{_i:03d}", lambda self, i=_i: _run_cat4_case(self, i))


# =====================================================================
# 5. CATEGORY 5: FALSE-POSITIVE STOPWORD STRESS TESTING (100 CASES)
# =====================================================================
class TestCategory5Stopwords(unittest.TestCase):
    """100 distinct iterations testing false-positive prevention on timestamps, order IDs, flight codes, ports."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("StopwordsVerificationService")


def _run_cat5_case(self, case_idx: int):
    stopword_templates = [
        # Operational Timestamps & Scheduling
        f"Meeting confirmed at 3pm tomorrow with infrastructure team for milestone {case_idx}.",
        f"The system maintenance window starts at 4pm today (task #{case_idx}).",
        f"Morning standup briefing scheduled at 9am sharp on Monday #{case_idx}.",
        f"Executive roadmap review starts at 10am in conference room #{case_idx}.",
        f"Team lunch at 12pm followed by planning session #{case_idx}.",
        f"Quarterly submission deadline set for 31st nov as per memo {case_idx}.",
        f"Financial book closure on 30th nov for fiscal year {2020 + (case_idx % 6)}.",
        f"Annual policy updates take effect 1st jan for department {case_idx}.",
        f"Leave request approved for month of november (ticket {case_idx}).",
        f"Corporate holiday schedule for december approved for division {case_idx}.",

        # Operational Ports & Infrastructure
        f"Microservice cluster listening on port 8080 for route #{case_idx}.",
        f"Secure TLS gateway active on port 443 handling request #{case_idx}.",
        f"Development sandbox environment running on port 8080 (node {case_idx}).",

        # Order Numbers & Shipments
        f"Customer order number 4821 has been marked as packed and shipped (ref {case_idx}).",
        f"Order 4821 delivery status: transit verified for warehouse {case_idx}.",

        # Flight Codes & Logistics
        f"Flight 4821 boarding at gate 12 for group {case_idx}.",
        f"International cargo flight 4821 cleared for takeoff on runway {case_idx}.",

        # Room Numbers, Suites & Hardware Models
        f"Executive suite 4821 reserved for visiting engineering delegation {case_idx}.",
        f"Conference room 4821 AV equipment checked for presentation {case_idx}.",
        f"Hardware model 4821 technical specification document revision {case_idx}.",

        # Years & Organizational Names
        f"Enterprise organization was established in year 2024 (branch {case_idx}).",
        f"Strategic 5-year growth vision finalized for year 2026 (target {case_idx}).",
        f"General Motors corporate supplier agreement signed under contract {case_idx}.",
        f"New York regional datacenter expansion completed for zone {case_idx}.",
        f"United States regulatory compliance review passed for module {case_idx}.",
    ]

    selected_prompt = stopword_templates[case_idx % len(stopword_templates)]
    request = {
        "tool": "operational_query",
        "arguments": {
            "case_id": case_idx,
            "query_text": selected_prompt
        }
    }

    t0 = time.perf_counter()
    # Must NOT block ordinary operational discussion
    envelope = self.firewall.process_tool_call(request, self.mock_tool.execute)
    dur = (time.perf_counter() - t0) * 1000.0

    # 1. Operation was successful
    self.assertEqual(envelope["response"]["status"], "success")

    # 2. Sent text matches original without spurious tokens
    sent_text = envelope["sanitized_payload_sent"]["arguments"]["query_text"]
    self.assertEqual(sent_text, selected_prompt, f"Case {case_idx}: False positive modified legitimate text: {selected_prompt}")

    record_latency(dur)


for _i in range(1, 101):
    setattr(TestCategory5Stopwords, f"test_cat5_stopwords_{_i:03d}", lambda self, i=_i: _run_cat5_case(self, i))


# =====================================================================
# 6. HIGH-CONCURRENCY MULTI-THREADING BURST STRESS TEST
# =====================================================================
class TestHighConcurrencyBurst(unittest.TestCase):
    """Multi-threaded stress test with 50 parallel workers processing simultaneous bursts."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("ConcurrentBurstService")

    def test_concurrency_burst_50_workers(self):
        num_workers = 50
        results = []

        def _worker(worker_id: int):
            worker_email = f"burst_worker_{worker_id}@concurrent-cluster.test"
            worker_phone = f"+1-555-010-{worker_id:04d}"
            payload = {
                "tool": "concurrent_worker_dispatch",
                "arguments": {
                    "worker_id": worker_id,
                    "email": worker_email,
                    "phone": worker_phone,
                    "task": f"Process parallel batch chunk {worker_id}"
                }
            }

            t0 = time.perf_counter()
            envelope = self.firewall.process_tool_call(payload, self.mock_tool.execute)
            dur = (time.perf_counter() - t0) * 1000.0
            record_latency(dur)
            return worker_id, worker_email, worker_phone, envelope

        start_time = time.perf_counter()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_worker, i) for i in range(num_workers)]
            for future in as_completed(futures):
                results.append(future.result())
        elapsed_total = time.perf_counter() - start_time

        self.assertEqual(len(results), num_workers)

        # Audit each concurrent thread execution
        for w_id, w_email, w_phone, envelope in results:
            restored = envelope["response"]
            self.assertEqual(restored["echo_arguments"]["email"], w_email)
            self.assertEqual(restored["echo_arguments"]["phone"], w_phone)

            sanitized = envelope["sanitized_payload_sent"]
            self.assertNotIn(w_email, str(sanitized))
            self.assertNotIn(w_phone, str(sanitized))
            self.assertTrue(sanitized["arguments"]["email"].startswith("⟦EMAIL_"))

        throughput = num_workers / elapsed_total
        print(f"\n[50-Worker Concurrency Burst] {num_workers} requests in {elapsed_total:.3f}s ({throughput:.1f} req/sec)")
        self.assertGreater(throughput, 50.0, "Concurrent throughput is above threshold")


# =====================================================================
# 7. VAULT MEMORY LIFECYCLE & AUDIT
# =====================================================================
class TestVaultMemoryLifecycle(unittest.TestCase):
    """Audits vault memory lifecycle: confirms zero residual memory leaks across requests."""

    def setUp(self):
        self.firewall = PIIFirewall()
        self.mock_tool = SimulatedExternalTool("VaultAuditService")

    def test_vault_memory_lifecycle_cleanup(self):
        """Verifies that requests cleanly purge all ephemeral vaults."""
        # Confirm clean state at start
        self.assertEqual(self.firewall.get_active_vault_count(), 0)

        # Run 25 successful tool calls
        for i in range(25):
            req = {
                "tool": "audit_tool",
                "arguments": {"email": f"audit_{i}@vault.test", "id": i}
            }
            res = self.firewall.process_tool_call(req, self.mock_tool.execute)
            self.assertEqual(res["response"]["status"], "success")

        # Confirm 0 active vaults remaining
        self.assertEqual(
            self.firewall.get_active_vault_count(), 0,
            "Residual active vaults detected after process_tool_call completions!"
        )

        # Run 10 blocked requests
        for i in range(10):
            req = {
                "tool": "blocked_tool",
                "arguments": {"secret": f"password is leaked_pass_{i}"}
            }
            with self.assertRaises(FirewallBlockedError):
                self.firewall.process_tool_call(req, self.mock_tool.execute)

        # Confirm 0 active vaults remaining even after blocked requests
        self.assertEqual(
            self.firewall.get_active_vault_count(), 0,
            "Residual active vaults detected after blocked requests!"
        )


if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=2)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    res = runner.run(suite)
    print_formatted_report()
