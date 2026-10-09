# 🛡️ PII Firewall — Backend Engine & Services

## Overview
This folder contains the **Core Backend Engine, Security Middleware, REST API, and Recognizer Suite** for the PII Firewall project.

## Structure
```
backend/
├── pii_firewall/               # Core PII Firewall Python Package
│   ├── middleware.py           # Core interception & restoration middleware
│   ├── models.py               # Data models, SensitivityCategory, PIIType
│   ├── policy.py               # Mandatory 3-tier security policy engine
│   ├── semantic_nlp.py         # Context-Aware NLP & Semantic Classification
│   ├── scanner.py              # Recursive JSON payload scanner
│   ├── vault.py                # Reversible token vault with cryptographic salting
│   ├── verifier.py             # Strict mathematical leakage verification
│   ├── restoration.py          # Response re-hydration engine
│   ├── adversarial_defense.py  # Zero-width Unicode & Base64 defense
│   ├── audit_logger.py         # Zero-PII compliance audit logging
│   ├── batch.py                # Concurrent high-throughput batch processor
│   ├── custom_recognizer.py    # Runtime custom recognizer registration API
│   ├── simulated_tool.py       # Simulated external tool & wire auditor
│   ├── server.py               # Flask REST API endpoints
│   ├── cli.py                  # CLI command runner
│   └── recognizers/            # Pattern and NLP recognizers suite
├── run_server.py               # REST API server launcher (Port 5000)
└── README.md                   # Backend documentation
```

## Security Principles Enforced
1. **Principle A: Credentials — Block by Default**
   - Automatically halts external transmission of passwords, ATM/Debit Card PINs, CVVs, OTPs, API keys, access tokens, and private keys.
   - Mathematically barred from error messages, previews, and audit logs.
2. **Principle B: Personal Information — Policy-Based Transformation**
   - Detects personal data (emails, phones, SSNs, Aadhaar, PAN) and applies `MASK`, `TOKENIZE`, or `REDACT` based on destination policy.
3. **Principle C: Confidential Business Information — Destination Allowlists**
   - Evaluates proprietary code, internal system prompts, and databases against destination allowlists.

## Running the REST API Gateway
```bash
python backend/run_server.py
```
Starts the API on `http://localhost:5000`. Available endpoints:
- `GET /health`: Health and status check
- `POST /intercept`: Intercept and sanitize tool request
- `POST /restore`: Restore tokens in tool response
- `POST /process`: End-to-end tool call interception
- `GET /metrics`: Observability and latency metrics
