# Architecture & System Design: PII Firewall for AI Agents

## 1. Executive Summary
The **PII Firewall for AI Agents** is an enterprise-grade privacy middleware that sits between AI agents and external tools (APIs, third-party services, databases). It guarantees that sensitive Personally Identifiable Information (PII) is intercepted, converted into reversible opaque tokens, audited for zero leakage, and safely re-hydrated upon response arrival—all with sub-millisecond latency.

---

## 2. System Architecture & End-to-End Data Pipeline

```
  ┌─────────────────┐
  │    AI Agent     │
  └────────┬────────┘
           │ 1. Outgoing Tool Call (Raw payload with PII)
           ▼
  ┌────────────────────────────────────────────────────────┐
  │                 PII FIREWALL MIDDLEWARE                │
  │                                                        │
  │  [Recursive JSON & Text Scanner]                       │
  │    ├── EmailRecognizer                                 │
  │    ├── PhoneRecognizer (International & Domestic)       │
  │    ├── SSNRecognizer (SSA Structure Validated)         │
  │    └── CreditCardRecognizer (Luhn Mod-10 Validated)    │
  │           │                                            │
  │           ▼                                            │
  │  [Request-Scoped Token Vault]                          │
  │    ├── Deterministic Salted Hashing (HMAC/SHA-256)     │
  │    ├── Consistency: Same PII -> Same Token             │
  │    └── Ephemeral Memory (Never Logged / Never Leaked)  │
  │           │                                            │
  │           ▼                                            │
  │  [Post-Sanitization Leakage Verifier]                  │
  │    ├── Full Substring Scan against Original Values     │
  │    └── FAIL-SAFE: Any detected residue BLOCKS call    │
  └────────┬───────────────────────────────────────────────┘
           │ 2. Sanitized Payload (Opaque Tokens only: ⟦TYPE_hash⟧)
           ▼
  ┌─────────────────┐
  │  External Tool  │ (e.g. Email Service, CRM API, Stripe)
  │ (Simulated Mock)│  [Audited: ZERO real PII received]
  └────────┬────────┘
           │ 3. Tool Response (Contains echoed tokens)
           ▼
  ┌────────────────────────────────────────────────────────┐
  │                 PII FIREWALL MIDDLEWARE                │
  │                                                        │
  │  [Response Re-hydration Engine]                        │
  │    ├── Request-Scoped Token Resolution                 │
  │    ├── Selective Field Policy Filters                  │
  │    └── Ephemeral Vault Memory Purge                    │
  └────────┬───────────────────────────────────────────────┘
           │ 4. Restored Response (Original context preserved)
           ▼
  ┌─────────────────┐
  │    AI Agent     │
  └─────────────────┘
```

---

## 3. Core Functional Components

### A. Recognizer Engine (`pii_firewall/recognizers/`)
- **Email Recognizer**: RFC-compliant regex with sentence boundary stripping.
- **Phone Recognizer**: Detects international E.164 (`+1`, `+91`, `+44`) and domestic formatted phones (`(555) 123-4567`, `555-123-4567`), filtering out short IDs and dates.
- **SSN Recognizer**: Validates US SSN syntax and enforces SSA rules (rejects invalid area codes `000`, `666`, `900+`, group `00`, serial `0000`).
- **Credit Card Recognizer**: Matches Visa, Mastercard, Amex, Discover and validates via **Luhn checksum algorithm (Mod 10)** to eliminate false positives on arbitrary order numbers.

### B. Request-Scoped Token Vault (`pii_firewall/vault.py`)
- **Format**: `⟦<TYPE>_<HASH>⟧` (e.g., `⟦EMAIL_a1b2c3⟧`).
- **Request Isolation**: Salted per-request with cryptographic randomness; same PII produces different tokens across requests.
- **Within-Request Consistency**: Repeated instances of the same PII in a single request map to the exact same token (FR-9).
- **Zero-Exposure Policy**: Mapping table remains strictly internal; it is never forwarded to external tools or logged.

### C. Recursive JSON Scanner (`pii_firewall/scanner.py`)
- Recursively traverses dictionaries, lists, and preserves primitive datatypes (ints, floats, bools, nulls).
- Scans arbitrary natural language text inside strings and replaces detected entities right-to-left to preserve span indices.

### D. Leakage Verifier (`pii_firewall/verifier.py`)
- Audits the entire outgoing serialized payload against the vault's original value registry.
- **Fail-Safe Principle**: If any original detected substring is found, immediately raises `PIILeakageDetectedError`, blocking tool execution.
- Privacy-preserving error messages (redacts raw values from logs/traces).

### E. Response Re-hydrator (`pii_firewall/restoration.py`)
- Replaces tokens in responses with original values.
- Supports field-level security policies (`allowed_restoration_fields`).
- Leaves malformed or unknown tokens untouched (FR-19).

---

## 4. Requirement Traceability Matrix

| Requirement | Implementation Detail | Test Case | Status |
|:---|:---|:---|:---|
| **FR-1**: Single request path | `PIIFirewall.process_tool_call()` / `intercept_request()` | `test_prd_example_flow` | Verified |
| **FR-2 & FR-3**: Recursive JSON & Free Text | `JSONPIIScanner.scan_and_tokenize()` | `test_nested_json_and_multiple_pii` | Verified |
| **FR-4**: Structure Preservation | Primitive values & nesting preserved | `test_nested_json_and_multiple_pii` | Verified |
| **FR-5 & FR-6**: PII Types (Email, Phone, SSN, Card) | `EmailRecognizer`, `PhoneRecognizer`, `SSNRecognizer`, `CreditCardRecognizer` | `test_recognizers.py` | Verified |
| **FR-8 & FR-9**: Opaque & Consistent Tokens | `RequestTokenVault.get_or_create_token()` | `test_token_consistency_within_request` | Verified |
| **FR-10**: Scoped Vault Isolation | Unique request salt per vault | `test_token_isolation_across_requests` | Verified |
| **FR-12 & FR-13**: Leakage Audit & Blocking | `LeakageVerifier.verify()` | `test_leakage_prevention.py` | Verified |
| **FR-14 & FR-21**: Safe Metrics (No PII in logs) | `FirewallMetrics` emits counts & latency only | `test_prd_example_flow` | Verified |
| **FR-15**: Simulated External Tool | `SimulatedExternalTool` records exact received payloads | `test_firewall_e2e.py` | Verified |
| **FR-16 - FR-19**: Response Restoration | `ResponseRestorer.restore()` | `test_selective_field_restoration` | Verified |
| **FR-20**: Latency Measurement | Sub-millisecond tracking (`time.perf_counter()`) | `test_performance.py` | Verified |
