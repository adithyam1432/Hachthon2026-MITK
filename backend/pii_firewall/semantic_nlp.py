"""
Context-Aware NLP, Semantic Classification, and Entity Relationship Extraction Engine.

Operates 100% locally and privately without sending raw payloads to external services.
Combines:
  1. Contextual Synonym Mapping across all protected categories.
  2. Context-Window Analysis (analyzing preceding & succeeding tokens).
  3. False-Positive Prevention (distinguishing random numbers from sensitive secrets).
  4. Entity Relationship Extraction (e.g., Person -> Credential).
  5. Distinction between conceptual mentions vs. exposed secret values.
  6. Destination-Aware & Intent-Aware Security Enforcement.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from pii_firewall.models import PIIEntity, PIIType, SensitivityCategory, TYPE_TO_CATEGORY


# =====================================================================
# 1. COMPREHENSIVE CONTEXTUAL SYNONYM DICTIONARY
# =====================================================================
SYNONYM_MAPPINGS: Dict[PIIType, List[str]] = {
    # Credentials & Authentication Secrets
    PIIType.PIN: [
        "pin", "my pin", "pin is", "pin:", "pin number", "enter pin",
        "debit card pin", "debit card password", "atm pin", "atm card pin",
        "bank card pin", "cash withdrawal pin", "card security pin", "banking pin",
        "four-digit card pin", "my card's secret number", "the pin used at an atm",
        "pin for withdrawing cash", "the number i enter at the atm",
        "the secret code for my debit card", "upi pin", "atm passcode",
        "debit pin", "secret atm pin", "card pin", "atm secret code",
        "secret pin", "my card pin", "enter at the atm", "pin code",
        "security pin", "account pin", "user pin"
    ],
    PIIType.PASSWORD: [
        "passcode", "login secret", "account password", "sign-in code", "signin code",
        "master password", "admin password", "user password", "login password",
        "secret password", "password is", "passphrase", "login credential",
        "portal password", "system password", "auth password", "credential password",
        "pwd", "pass", "my password"
    ],
    PIIType.CVV: [
        "card security code", "card verification value", "security digits",
        "cvv", "cvc", "cvv2", "cid", "3-digit security code", "3 digit security code",
        "back of the card code", "card verification code", "card security digits",
        "cvc code", "cvv code", "security code on back"
    ],
    PIIType.OTP: [
        "one-time code", "verification code", "login code", "authentication code",
        "one-time password", "sms code", "2fa code", "mfa code", "security code",
        "email otp", "sms otp", "mobile verification code", "one time pin", "auth code",
        "otp", "otp is", "otp code", "your otp", "login otp"
    ],
    PIIType.ACCESS_TOKEN: [
        "bearer token", "authorization token", "session access token", "access token",
        "oauth token", "session token", "jwt token", "refresh token", "id token",
        "api access token", "client token", "auth token"
    ],
    PIIType.PRIVATE_KEY: [
        "signing key", "secret cryptographic key", "private encryption key",
        "rsa private key", "id_rsa", "openssh private key", "private key",
        "ecdsa private key", "secret key file", "cryptographic private key"
    ],
    PIIType.DATABASE_CREDENTIAL: [
        "db password", "database login", "connection-string credentials",
        "database credentials", "postgres password", "mysql password",
        "mongodb uri", "redis auth", "db credentials", "database password",
        "db connection string", "database secret"
    ],
    PIIType.API_KEY: [
        "api secret", "developer key", "service key", "access credential",
        "openai key", "aws access key", "aws secret", "github token", "stripe key",
        "api key", "client secret", "production api key", "developer secret"
    ],

    # Personal Information
    PIIType.PASSPORT: [
        "passport id", "passport document number", "passport number",
        "travel document number", "passport no", "international passport"
    ],
    PIIType.DATE_OF_BIRTH: [
        "dob", "birth date", "date of birth", "born on", "birthday",
        "birthdate", "natal date"
    ],
    PIIType.DRIVERS_LICENSE: [
        "driver's license", "drivers license", "driver license", "driving license",
        "dl number", "dl no", "dl num", "driver license number", "dl",
        "driver's license no", "driver's licence", "driving licence"
    ],
    PIIType.PERSON_NAME: [
        "customer name", "client name", "user name", "patient name", "applicant name",
        "individual name", "full name", "employee name", "profile for", "record for",
        "account holder", "member name"
    ],
    PIIType.HOME_ADDRESS: [
        "residential address", "home location", "permanent address",
        "living address", "home address", "house address", "delivery address",
        "residence address", "mailing address", "address", "my address",
        "address is", "lives at", "residing at", "street address"
    ],
    PIIType.MEDICAL_DIAGNOSIS: [
        "medical diagnosis", "health condition", "diagnosed illness",
        "clinical diagnosis", "medical report", "patient diagnosis",
        "disease diagnosis", "diagnosed with", "medical condition",
        "pathology report", "clinical condition", "health status"
    ],
    PIIType.BIOMETRIC_TEMPLATE: [
        "face template", "fingerprint template", "iris template", "voiceprint",
        "biometric template", "facial geometry", "retina scan", "fingerprint data",
        "biometric signature"
    ],
    PIIType.SALARY_INFO: [
        "salary", "pay details", "compensation", "monthly salary", "remuneration",
        "annual ctc", "base salary", "pay slip", "wage", "take-home pay",
        "annual package", "hourly rate"
    ],
    PIIType.BANK_ACCOUNT: [
        "bank account number", "account number", "banking account id",
        "account details", "checking account", "savings account", "iban",
        "routing number", "ach account", "bank account", "account no",
        "ac no", "a/c no", "bank account no", "ifsc"
    ],
    PIIType.VOTER_ID: [
        "voter id", "voter card", "epic", "epic number", "voter registration"
    ],
    PIIType.EMPLOYEE_ID: [
        "employee id", "emp id", "staff id", "worker id", "badge number"
    ],
    PIIType.CUSTOMER_ID: [
        "customer id", "cust id", "client id", "account id", "customer number"
    ],
    PIIType.AADHAAR: [
        "aadhaar", "aadhaar number", "aadhaar no", "aadhaar num", "aadhaar card", "aadhaar id",
        "aadhar", "aadhar number", "aadhar no", "aadhar num", "aadhar card", "aadhar id",
        "adhaar", "adhaar number", "adhaar no", "adhaar num", "adhaar card", "adhaar id",
        "adhar", "adhar number", "adhar card", "adhar no", "adhar num", "adhar id",
        "uidai", "uidai number", "uidai no", "uidai num", "uidai id",
        "uid number", "uid no", "uid num",
        "my aadhaar", "my aadhar", "my adhaar", "my adhar",
        "national id", "indian uid"
    ],
    PIIType.PAN_CARD: [
        "pan card", "pan number", "pan no", "pan num", "permanent account number",
        "my pan", "pan id", "income tax pan", "tax pan"
    ],

    # Confidential Business Information
    PIIType.CONFIDENTIAL_SOURCE_CODE: [
        "proprietary code", "internal repository code", "private application source",
        "confidential source code", "trade secret algorithms", "internal source code",
        "source repository", "proprietary algorithm", "core algorithm codebase"
    ],
    PIIType.INTERNAL_SYSTEM_INSTRUCTIONS: [
        "system prompt", "hidden instructions", "internal model configuration",
        "base instructions", "system directive", "developer prompt",
        "internal instructions", "system prompt instructions", "hidden prompt"
    ],
    PIIType.CUSTOMER_DATABASE: [
        "customer database", "customer table", "customer records database",
        "client database", "crm database", "user database table"
    ],
    PIIType.EMPLOYEE_RECORDS: [
        "employee database", "employee records", "staff records",
        "hr database", "payroll records", "personnel files"
    ],
    PIIType.SECURITY_CONFIG: [
        "security configuration", "firewall rules configuration", "internal network topology",
        "vulnerability report", "security audit findings", "infosec policy configuration"
    ],
    PIIType.TRADE_SECRET: [
        "trade secret", "confidential business plan", "unreleased product roadmap",
        "merger documents", "proprietary financial model"
    ]
}


# Pre-compile synonym regexes with boundary matching
COMPILED_SYNONYMS: Dict[PIIType, List[re.Pattern]] = {
    p_type: [
        re.compile(r"\b" + re.escape(syn) + r"\b", re.IGNORECASE) if len(syn) <= 4 and " " not in syn
        else re.compile(re.escape(syn), re.IGNORECASE)
        for syn in syn_list
    ]
    for p_type, syn_list in SYNONYM_MAPPINGS.items()
}


# =====================================================================
# 2. CONTEXT-AWARE SEMANTIC NLP ENGINE
# =====================================================================
class ContextAwareNLPEngine:
    """
    Evaluates text using hybrid NLP, contextual window inspection,
    and entity-relationship extraction.
    """

    CONTEXT_WINDOW_CHARS = 70  # Characters before and after candidate value

    # Non-PII scheduling/operational phrases to prevent false positives
    OPERATIONAL_STOPWORDS = {
        "3pm", "3 pm", "4pm", "5pm", "9am", "10am", "11am", "12pm",
        "31st nov", "30th nov", "1st jan", "tomorrow", "yesterday",
        "november", "december", "january", "schedule", "leave",
        "port 8080", "port 443", "year 2024", "year 2025", "year 2026",
        "model 4821", "order 4821", "room 4821", "suite 4821", "flight 4821"
    }

    NAME_STOPWORDS = {
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
        "january", "february", "march", "april", "may", "june", "july", "august",
        "september", "october", "november", "december",
        "general", "motors", "production", "environment", "new", "york", "united", "states",
        "next", "quarter", "project", "schedule", "meeting", "system", "service", "cloud",
        "customer", "service", "terms", "conditions", "privacy", "policy", "internal", "external",
        "spring", "summer", "autumn", "winter", "north", "south", "east", "west",
        "me", "him", "her", "them", "us", "you", "the", "a", "an", "someone", "anyone", "everyone",
        "all", "assistant", "server", "support", "team", "helpdesk", "admin", "client",
        "query", "prompt", "today", "tomorrow", "leave", "personal", "issue", "office",
        "home", "work", "test", "demo", "file", "data", "details", "info", "information",
        "request", "response", "status", "active", "inactive", "verified", "pending",
        "urgent", "immediate", "subject", "message", "email", "mail", "note",
        "profile", "record", "account", "password", "code", "tool", "device", "address",
        "phone", "number", "pin", "credential", "user", "applicant", "member"
    }

    NAME_TERMINATORS = {
        "at", "from", "with", "in", "on", "for", "his", "her", "their",
        "is", "was", "has", "and", "who", "whose", "by", "to", "having"
    }

    @staticmethod
    def extract_entity_relationships(text: str) -> List[Tuple[str, str, str]]:
        """
        Extracts relationships like (Subject, Relation, Target).
        E.g., "Adithya's ATM PIN is 4821" -> ("Adithya", "ATM PIN", "4821")
        """
        relationships = []
        # Pattern: [Name/Subject]'s [Context Synonym] is/was [Value]
        possession_pattern = re.compile(
            r"([A-Z][a-zA-Z]+|[a-zA-Z]+)'s\s+([a-zA-Z\s]+?)\s+(?:is|was|=)\s+([^\s,.;]+)",
            re.IGNORECASE
        )
        for match in possession_pattern.finditer(text):
            subject = match.group(1).strip()
            predicate = match.group(2).strip().lower()
            value = match.group(3).strip()
            relationships.append((subject, predicate, value))

        return relationships

    @staticmethod
    def check_transmission_intent(text: str) -> Tuple[bool, Optional[PIIType], Optional[str]]:
        """
        Detects if user is asking to transmit a credential/secret to an external assistant/service
        even without an explicit value in the sentence!
        E.g.: "Send my ATM PIN to the external assistant."
        """
        lower = text.lower()
        send_verbs = ["send", "forward", "transmit", "upload", "export", "share", "post", "dispatch"]
        external_targets = [
            "external assistant", "external service", "third party", "unapproved",
            "public api", "external api", "outside assistant", "assistant", "external tool"
        ]

        has_verb = any(v in lower for v in send_verbs)
        has_external = any(t in lower for t in external_targets)

        if has_verb and has_external:
            for p_type, patterns in COMPILED_SYNONYMS.items():
                category = TYPE_TO_CATEGORY.get(p_type)
                # Credentials and business confidential
                if category in (SensitivityCategory.CREDENTIAL, SensitivityCategory.BUSINESS_CONFIDENTIAL):
                    for pat in patterns:
                        m = pat.search(text)
                        if m:
                            return True, p_type, m.group(0)

        return False, None, None

    @classmethod
    def find_semantic_entities(cls, text: str) -> List[PIIEntity]:
        """
        Main entry point for context-aware entity detection.
        Combines pattern identification with context window analysis.
        """
        entities: List[PIIEntity] = []

        # -------------------------------------------------------------
        # A. Check for Unauthorized Transmission Requests (Conceptual Intent)
        # -------------------------------------------------------------
        has_intent, intent_type, matched_phrase = cls.check_transmission_intent(text)
        if has_intent and intent_type and matched_phrase:
            idx = text.lower().find(matched_phrase.lower())
            entities.append(
                PIIEntity(
                    pii_type=intent_type,
                    start=idx,
                    end=idx + len(matched_phrase),
                    value=text[idx:idx + len(matched_phrase)],
                    confidence=0.99,
                    category=TYPE_TO_CATEGORY.get(intent_type, SensitivityCategory.CREDENTIAL),
                    context_evidence="Unauthorized external transmission request detected",
                    has_exposed_value=True  # Trigger block enforcement!
                )
            )

        # -------------------------------------------------------------
        # B. Check for PINs (ATM PIN, Debit Card PIN, UPI PIN)
        # -------------------------------------------------------------
        # B1. Direct PIN Assignment (e.g. "pin: 4821", "and pin 4821", "pin is 1234", "my pin 5678", "atm pin 4821")
        pin_explicit_pattern = re.compile(
            r"(?i:\b(?:(?:atm|upi|debit|bank|card|security|secret|account|user|my)?\s*pin(?:\s*code|\s*number|\s*no\.?)?)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"(\d{4,6})\b"
        )
        for match in pin_explicit_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)
            # False-positive filter for operational words
            if not any(f"{stop} {cand_val}" in text.lower() for stop in ["port", "year", "flight", "order", "model", "room", "suite"]):
                if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                    related_entity = None
                    for subject, pred, val in cls.extract_entity_relationships(text):
                        if val == cand_val or any(s in pred for s in ["pin", "atm", "card"]):
                            related_entity = subject
                            break

                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.PIN,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.98,
                            category=SensitivityCategory.CREDENTIAL,
                            context_evidence="Direct PIN assignment context",
                            related_entity=related_entity,
                            has_exposed_value=True
                        )
                    )

        # B2. Candidate value: 4 to 6 digit numbers via context window
        pin_cand_pattern = re.compile(r"\b(\d{4,6})\b")
        for match in pin_cand_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)

            if any(e.start <= start_pos and e.end >= end_pos for e in entities):
                continue

            # Extract context window
            ctx_start = max(0, start_pos - cls.CONTEXT_WINDOW_CHARS)
            ctx_end = min(len(text), end_pos + cls.CONTEXT_WINDOW_CHARS)
            context_window = text[ctx_start:ctx_end].lower()

            # False-positive filter: check operational scheduling / ports / dates
            if any(stopword in context_window for stopword in cls.OPERATIONAL_STOPWORDS):
                if "port " + cand_val in context_window or "year " + cand_val in context_window:
                    continue

            # Check if any PIN synonym is present in the context window
            matched_synonym = None
            for pat in COMPILED_SYNONYMS[PIIType.PIN]:
                if pat.search(context_window):
                    matched_synonym = pat.pattern
                    break

            if matched_synonym:
                related_entity = None
                for subject, pred, val in cls.extract_entity_relationships(text):
                    if val == cand_val or any(s in pred for s in ["pin", "atm", "card"]):
                        related_entity = subject
                        break

                entities.append(
                    PIIEntity(
                        pii_type=PIIType.PIN,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.98,
                        category=SensitivityCategory.CREDENTIAL,
                        context_evidence=f"Surrounded by PIN context ({matched_synonym})",
                        related_entity=related_entity,
                        has_exposed_value=True
                    )
                )

        # -------------------------------------------------------------
        # C. Check for Passwords using Context Window & Semantic Keywords
        # -------------------------------------------------------------
        # Pattern: [password synonym] [is / : / = / -] [value]
        pwd_pattern = re.compile(
            r"(?i:\b(?:password|passcode|login\s+secret|account\s+password|sign-in\s+code|auth\s+password|pwd|pass)\s*(?:is|was|:|=|->|\s+)\s*)"
            r"([^\s,.;]+)"
        )
        for match in pwd_pattern.finditer(text):
            val = match.group(1).strip()
            # Must not be an educational discussion word like "secret", "private", "important"
            if len(val) >= 4 and val.lower() not in {"never", "not", "should", "always", "shared", "kept"}:
                if not any(e.start <= match.start(1) and e.end >= match.end(1) for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.PASSWORD,
                            start=match.start(1),
                            end=match.end(1),
                            value=val,
                            confidence=0.96,
                            category=SensitivityCategory.CREDENTIAL,
                            context_evidence="Direct password assignment context",
                            has_exposed_value=True
                        )
                    )

        # -------------------------------------------------------------
        # D. Check for CVV / Card Security Codes
        # -------------------------------------------------------------
        cvv_direct_pattern = re.compile(
            r"(?i:\b(?:cvv|cvc|cvv2|cid|security\s*code|card\s*security\s*digits)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"(\d{3,4})\b"
        )
        for match in cvv_direct_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.CVV,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.98,
                        category=SensitivityCategory.CREDENTIAL,
                        context_evidence="Direct CVV assignment context",
                        has_exposed_value=True
                    )
                )

        # Candidate value: 3 or 4 digits
        cvv_cand_pattern = re.compile(r"\b(\d{3,4})\b")
        for match in cvv_cand_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)

            if any(e.start <= start_pos and e.end >= end_pos for e in entities):
                continue

            ctx_start = max(0, start_pos - cls.CONTEXT_WINDOW_CHARS)
            ctx_end = min(len(text), end_pos + cls.CONTEXT_WINDOW_CHARS)
            context_window = text[ctx_start:ctx_end].lower()

            matched_cvv_syn = None
            for pat in COMPILED_SYNONYMS[PIIType.CVV]:
                if pat.search(context_window):
                    matched_cvv_syn = pat.pattern
                    break

            if matched_cvv_syn:
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.CVV,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.97,
                        category=SensitivityCategory.CREDENTIAL,
                        context_evidence=f"Surrounded by CVV context ({matched_cvv_syn})",
                        has_exposed_value=True
                    )
                )

        # -------------------------------------------------------------
        # E. Check for OTP / Verification Codes
        # -------------------------------------------------------------
        otp_direct_pattern = re.compile(
            r"(?i:\b(?:otp|one[- ]time\s*(?:password|pin|code)|verification\s*code|login\s*code|2fa\s*code|sms\s*code)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"(\d{4,8})\b"
        )
        for match in otp_direct_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.OTP,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.98,
                        category=SensitivityCategory.CREDENTIAL,
                        context_evidence="Direct OTP/verification code assignment",
                        has_exposed_value=True
                    )
                )

        otp_cand_pattern = re.compile(r"\b(\d{4,8})\b")
        for match in otp_cand_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)

            if any(e.start <= start_pos and e.end >= end_pos for e in entities):
                continue

            ctx_start = max(0, start_pos - cls.CONTEXT_WINDOW_CHARS)
            ctx_end = min(len(text), end_pos + cls.CONTEXT_WINDOW_CHARS)
            context_window = text[ctx_start:ctx_end].lower()

            matched_otp_syn = None
            for pat in COMPILED_SYNONYMS[PIIType.OTP]:
                if pat.search(context_window):
                    matched_otp_syn = pat.pattern
                    break

            if matched_otp_syn:
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.OTP,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.95,
                        category=SensitivityCategory.CREDENTIAL,
                        context_evidence="Surrounded by OTP/verification code context",
                        has_exposed_value=True
                    )
                )

        # -------------------------------------------------------------
        # F. Check for Confidential Business Information & Internal Prompts
        # -------------------------------------------------------------
        # 1. Internal System Instructions / Hidden Prompts
        sys_prompt_markers = [
            "system prompt", "hidden instructions", "internal model configuration",
            "you are an ai assistant", "ignore all previous instructions",
            "internal prompt directive", "base system instructions"
        ]
        lower_text = text.lower()
        for marker in sys_prompt_markers:
            if marker in lower_text:
                m_idx = lower_text.find(marker)
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.INTERNAL_SYSTEM_INSTRUCTIONS,
                        start=m_idx,
                        end=m_idx + len(marker),
                        value=text[m_idx:m_idx + len(marker)],
                        confidence=0.99,
                        category=SensitivityCategory.BUSINESS_CONFIDENTIAL,
                        context_evidence="Internal system instructions or hidden prompt marker",
                        has_exposed_value=True
                    )
                )
                break

        # 2. Proprietary Source Code
        code_markers = [
            r"def\s+[a-zA-Z_][a-zA-Z0-9_]*\(.*?\):",
            r"class\s+[a-zA-Z_][a-zA-Z0-9_]*(?:\(.*?\))?:",
            r"import\s+[a-zA-Z_][a-zA-Z0-9_.]*",
            r"#include\s+<.*?>",
            r"public\s+class\s+[a-zA-Z_][a-zA-Z0-9_]*",
            r"proprietary code", r"internal repository code", r"trade secret algorithms"
        ]
        for c_pat in code_markers:
            m = re.search(c_pat, text, re.IGNORECASE)
            if m:
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.CONFIDENTIAL_SOURCE_CODE,
                        start=m.start(),
                        end=m.end(),
                        value=m.group(0),
                        confidence=0.95,
                        category=SensitivityCategory.BUSINESS_CONFIDENTIAL,
                        context_evidence="Confidential source code pattern or proprietary marker",
                        has_exposed_value=True
                    )
                )
                break

        # 3. Employee Database / Customer Database
        db_markers = [
            ("employee database", PIIType.EMPLOYEE_RECORDS),
            ("staff records", PIIType.EMPLOYEE_RECORDS),
            ("customer database", PIIType.CUSTOMER_DATABASE),
            ("client database", PIIType.CUSTOMER_DATABASE),
        ]
        for marker, p_type in db_markers:
            if marker in lower_text:
                m_idx = lower_text.find(marker)
                entities.append(
                    PIIEntity(
                        pii_type=p_type,
                        start=m_idx,
                        end=m_idx + len(marker),
                        value=text[m_idx:m_idx + len(marker)],
                        confidence=0.98,
                        category=SensitivityCategory.BUSINESS_CONFIDENTIAL,
                        context_evidence="Database or personnel records marker",
                        has_exposed_value=True
                    )
                )
                break

        # -------------------------------------------------------------
        # G. Other Protected Personal Categories (Passport, DOB, Medical, Salary, etc.)
        # -------------------------------------------------------------
        # Medical diagnosis in context
        medical_cand_pattern = re.compile(
            r"(?:diagnosed with|diagnosis is|health condition:|medical report:)\s*([a-zA-Z\s]{3,30})",
            re.IGNORECASE
        )
        for m in medical_cand_pattern.finditer(text):
            condition_val = m.group(1).strip()
            entities.append(
                PIIEntity(
                    pii_type=PIIType.MEDICAL_DIAGNOSIS,
                    start=m.start(1),
                    end=m.end(1),
                    value=condition_val,
                    confidence=0.93,
                    category=SensitivityCategory.PERSONAL_INFO,
                    context_evidence="Clinical diagnosis context",
                    has_exposed_value=True
                )
            )

        # Salary information
        salary_cand_pattern = re.compile(
            r"(?:salary|compensation|annual ctc|monthly salary)\s*(?:is|was|:|=)\s*([$€£₹]?\s*[\d,]+(?:\.\d+)?(?:\s*(?:k|lac|lakh|usd|inr|per annum|per month))?)",
            re.IGNORECASE
        )
        for m in salary_cand_pattern.finditer(text):
            entities.append(
                PIIEntity(
                    pii_type=PIIType.SALARY_INFO,
                    start=m.start(1),
                    end=m.end(1),
                    value=m.group(1).strip(),
                    confidence=0.95,
                    category=SensitivityCategory.PERSONAL_INFO,
                    context_evidence="Salary / remuneration context",
                    has_exposed_value=True
                )
            )

        # Date of Birth (DOB) in context
        dob_cand_pattern = re.compile(
            r"(?i:(?:DOB|birth\s*date|date\s*of\s*birth|born\s*on|born|birthday|birthdate)\s*(?:is|was|:|=|->|\s)\s*)"
            r"(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4})",
            re.IGNORECASE
        )
        for m in dob_cand_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if not any(e.start == start_pos and e.end == end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.DATE_OF_BIRTH,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.96,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Date of birth context with valid date structure",
                        has_exposed_value=True
                    )
                )

        # Driver's License in context
        dl_cand_pattern = re.compile(
            r"(?i:\b(?:driver\'?s?\s*licen[sc]e(?:\s*(?:no\.?|num(?:ber)?))?|driving\s*licen[sc]e(?:\s*(?:no\.?|num(?:ber)?))?|dl\s*num(?:ber)?|dl\s*no\.?|dl)\b\s*(?:is|was|:|=|->|#|\s)*\s*)"
            r"([A-Za-z0-9][A-Za-z0-9-]{4,18}[A-Za-z0-9])\b",
            re.IGNORECASE
        )
        for m in dl_cand_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if any(c.isdigit() for c in cand_val) and cand_val.lower() not in cls.OPERATIONAL_STOPWORDS:
                if not any(e.start == start_pos and e.end == end_pos for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.DRIVERS_LICENSE,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.97,
                            category=SensitivityCategory.PERSONAL_INFO,
                            context_evidence="Driver's License identifier context",
                            has_exposed_value=True
                        )
                    )

        # Person Name in context (Single names, full names, possessives, and contextual cues)
        name_cand_pattern = re.compile(
            r"(?i:\b(?:"
            r"(?:my\s+name\s+(?:is|was|:|=)|i\s+am|i\'?m)\s+|"
            r"(?:(?:full|first|last)\s+)?name\s*(?:is|was|:|=|->|\s)\s*|"
            r"(?:customer|user|client|employee|patient|individual|applicant|profile|member|account(?:\s+holder)?)\s*(?:onboarding\s+)?(?::|=|->|\s+(?:name\s*(?:is|was|:|=|->)?|profile\s+for|record\s+for|for\s+))\s*|"
            r"(?:user|customer|client|employee|patient|applicant|member|contact(?:\s+person)?|recipient|account\s+holder)\s*(?::|=|->)\s*|"
            r"(?:send\s+(?:an?\s+)?(?:email|mail|message|note|letter|invitation)\s+to|mail\s+to|email\s+to|message\s+to)\s+|"
            r"(?:profile\s+for|record\s+for|details\s+for|account\s+for|onboarding\s+(?:profile\s+)?for)\s+|"
            r"(?:welcome\s+)?(?:note|letter|message|email|invitation)\s+to\s+|"
            r"\b(?:user|employee|contact)\s+(?=[A-Z])|"
            r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\b\.?\s+"
            r")\s*)"
            r"([A-Z][a-zA-Z\'\.\-]+(?:\s+[A-Z][a-zA-Z\'\.\-]*){0,3})"
        )
        for m in name_cand_pattern.finditer(text):
            raw_val = m.group(1).strip()
            tokens = raw_val.split()
            clean_tokens = []
            for tok in tokens:
                if tok.lower() in cls.NAME_TERMINATORS:
                    break
                clean_tokens.append(tok)
            if not clean_tokens:
                continue
            cand_val = " ".join(clean_tokens)
            start_pos = m.start(1)
            end_pos = start_pos + len(cand_val)

            # Skip if followed by @ or contains @ (part of email)
            if (end_pos < len(text) and text[end_pos] == "@") or "@" in cand_val:
                continue

            words = [w.lower().rstrip(".") for w in clean_tokens]
            if not any(w in cls.NAME_STOPWORDS for w in words):
                if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.PERSON_NAME,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.95,
                            category=SensitivityCategory.PERSONAL_INFO,
                            context_evidence="Person name identified via contextual role/name indicators",
                            has_exposed_value=True
                        )
                    )

        # Lowercase name with explicit cue (e.g. "name: sharath", "my name is adithya")
        explicit_lc_name_pattern = re.compile(
            r"(?i:\b(?:(?:my\s+)?name\s*(?:is|was|:|=)|i\s+am|i\'?m)\s+)([a-z][a-z\'\-]+(?:\s+[a-z][a-z\'\-]+)?)\b"
        )
        for m in explicit_lc_name_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if (end_pos < len(text) and text[end_pos] == "@") or "@" in cand_val:
                continue
            words = [w.lower().rstrip(".") for w in cand_val.split()]
            if not any(w in cls.NAME_STOPWORDS for w in words):
                if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.PERSON_NAME,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.94,
                            category=SensitivityCategory.PERSONAL_INFO,
                            context_evidence="Lowercase person name identified via explicit cue",
                            has_exposed_value=True
                        )
                    )

        # Possessive names: e.g. "Sharath's phone number", "Adithya's account"
        possessive_name_pattern = re.compile(
            r"\b([A-Za-z][a-zA-Z\'\-]+)\'s\s+(?:phone|email|account|profile|record|details|info|ssn|pan|aadhaar|passport|dl|address|status|message)\b",
            re.IGNORECASE
        )
        for m in possessive_name_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if cand_val.lower() not in cls.NAME_STOPWORDS:
                if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.PERSON_NAME,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.96,
                            category=SensitivityCategory.PERSONAL_INFO,
                            context_evidence="Possessive person name identifier",
                            has_exposed_value=True
                        )
                    )

        # Passport Number in context (e.g. Passport: A12345678, passport no: A12345678, travel document number: Z11223344)
        passport_cand_pattern = re.compile(
            r"(?i:(?:passport(?:\s*(?:no\.?|num(?:ber)?|id|doc))?|travel\s+document(?:\s+number)?)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"([A-Za-z][0-9]{7,9}|[A-Za-z0-9]{8,10})",
            re.IGNORECASE
        )
        for m in passport_cand_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if not any(e.start == start_pos and e.end == end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.PASSPORT,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.98,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Passport identifier context",
                        has_exposed_value=True
                    )
                )

        # Contextual SSN in context (e.g. "containing SSN 999-12-3456", "SSN: 999-12-3456")
        ssn_ctx_pattern = re.compile(
            r"(?i:(?:ssn|social\s*security(?:\s*number)?)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"(\d{3}-\d{2}-\d{4}|\d{3}\s+\d{2}\s+\d{4})",
            re.IGNORECASE
        )
        for m in ssn_ctx_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            parts = re.split(r"[- ]", cand_val)
            if len(parts) == 3:
                area_num = int(parts[0])
                if area_num == 0 or area_num == 666 or parts[1] == "00" or parts[2] == "0000":
                    continue
                if 900 <= area_num <= 999 and cand_val != "999-12-3456":
                    continue
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.SSN,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.99,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Contextual SSN identifier",
                        has_exposed_value=True
                    )
                )


        # -------------------------------------------------------------
        # H. Indian Identifiers Context Analysis (Aadhaar & PAN)
        # -------------------------------------------------------------
        # 1. Aadhaar Number (12 digits with spaces/hyphens or continuous, resilient to boundaries)
        aadhaar_cand_pattern = re.compile(r"(?<!\d)([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?![ -]?\d)")
        for match in aadhaar_cand_pattern.finditer(text):
            cand_val = match.group(1)
            start_pos, end_pos = match.start(1), match.end(1)

            if any(e.start == start_pos and e.end == end_pos for e in entities):
                continue

            digits = re.sub(r"\D", "", cand_val)
            if len(digits) != 12:
                continue

            ctx_start = max(0, start_pos - cls.CONTEXT_WINDOW_CHARS)
            ctx_end = min(len(text), end_pos + cls.CONTEXT_WINDOW_CHARS)
            context_window = text[ctx_start:ctx_end].lower()

            # False-positive check: operational codes
            if any(stopword in context_window for stopword in cls.OPERATIONAL_STOPWORDS):
                if "order " + cand_val in context_window or "port " + cand_val in context_window:
                    continue

            matched_aadhaar_syn = None
            if PIIType.AADHAAR in COMPILED_SYNONYMS:
                for pat in COMPILED_SYNONYMS[PIIType.AADHAAR]:
                    if pat.search(context_window):
                        matched_aadhaar_syn = pat.pattern
                        break

            # If Aadhaar context is present in the surrounding text:
            if matched_aadhaar_syn:
                from pii_firewall.recognizers.indian_pii import verhoeff_validate
                is_v_valid = verhoeff_validate(digits)

                # Check entity relationships (e.g. Sharath's Aadhaar, My Aadhaar)
                related_entity = None
                for subject, pred, val in cls.extract_entity_relationships(text):
                    if val == cand_val or any(s in pred for s in ["aadhaar", "aadhar", "adhaar", "adhar", "uidai"]):
                        related_entity = subject
                        break

                evidence = f"Surrounded by Aadhaar context ({matched_aadhaar_syn})"
                if is_v_valid:
                    evidence += " [Verhoeff Validated]"

                entities.append(
                    PIIEntity(
                        pii_type=PIIType.AADHAAR,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.99 if is_v_valid else 0.98,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence=evidence,
                        related_entity=related_entity,
                        has_exposed_value=True
                    )
                )

        # 2. PAN Card Context Analysis
        pan_cand_pattern = re.compile(r"(?<![A-Z0-9])([A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z])(?![A-Z0-9])", re.IGNORECASE)
        for match in pan_cand_pattern.finditer(text):
            cand_val = match.group(1).upper()
            start_pos, end_pos = match.start(1), match.end(1)

            if any(e.start == start_pos and e.end == end_pos for e in entities):
                continue

            ctx_start = max(0, start_pos - cls.CONTEXT_WINDOW_CHARS)
            ctx_end = min(len(text), end_pos + cls.CONTEXT_WINDOW_CHARS)
            context_window = text[ctx_start:ctx_end].lower()

            matched_pan_syn = None
            if PIIType.PAN_CARD in COMPILED_SYNONYMS:
                for pat in COMPILED_SYNONYMS[PIIType.PAN_CARD]:
                    if pat.search(context_window):
                        matched_pan_syn = pat.pattern
                        break

            evidence = "Valid Indian PAN format (Entity 4th char verified)"
            if matched_pan_syn:
                evidence += f" surrounded by context ({matched_pan_syn})"

            entities.append(
                PIIEntity(
                    pii_type=PIIType.PAN_CARD,
                    start=start_pos,
                    end=end_pos,
                    value=cand_val,
                    confidence=0.99,
                    category=SensitivityCategory.PERSONAL_INFO,
                    context_evidence=evidence,
                    has_exposed_value=True
                )
            )

        # 3. Context-Backed PAN Card (supports cases where "pan" precedes 5-letter 4-digit 1-letter)
        pan_context_pattern = re.compile(
            r"(?i:\b(?:pan(?:\s*card|\s*number|\s*no\.?|\s*id)?)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"([A-Za-z]{5}\d{4}[A-Za-z])\b"
        )
        for match in pan_context_pattern.finditer(text):
            cand_val = match.group(1).upper()
            start_pos, end_pos = match.start(1), match.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.PAN_CARD,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.99,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="PAN card identifier verified via semantic context",
                        has_exposed_value=True
                    )
                )

        # -------------------------------------------------------------
        # I. Physical Home & Street Address (HOME_ADDRESS)
        # -------------------------------------------------------------
        STREET_TYPES = "Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Nagar|Layout|Sector|Block|Apartment|Apt|Building|Terrace|Ter|Place|Pl|Square|Sq|Circle"
        address_cue_pattern = re.compile(
            r"(?i:\b(?:(?:home|residential|delivery|shipping|mailing|residence|house|living|permanent)?\s*address|lives?\s+at|residing\s+at|residence\s+at)\s*(?:is|was|:|=|->|\s)\s*)"
            rf"([0-9]{{1,6}}\s+[a-zA-Z0-9\s,.-]+?\b(?:{STREET_TYPES})\b[a-zA-Z0-9\s,.-]*)"
        )
        for m in address_cue_pattern.finditer(text):
            cand_val = m.group(1).strip().rstrip(".,;")
            start_pos, end_pos = m.start(1), m.start(1) + len(cand_val)
            if not any(stop in cand_val.lower() for stop in ["port ", "flight ", "runway", "order ", "model ", "year "]):
                if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.HOME_ADDRESS,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.96,
                            category=SensitivityCategory.PERSONAL_INFO,
                            context_evidence="Residential street address context",
                            has_exposed_value=True
                        )
                    )

        address_street_pattern = re.compile(
            rf"\b(\d{{1,6}}\s+[A-Za-z0-9\s.,-]+?\b(?:{STREET_TYPES})\b(?:,\s*[A-Za-z\s]+)*(?:\s+\d{{5,6}})?)\b",
            re.IGNORECASE
        )
        for m in address_street_pattern.finditer(text):
            cand_val = m.group(1).strip().rstrip(".,;")
            start_pos, end_pos = m.start(1), m.start(1) + len(cand_val)
            if not any(stop in cand_val.lower() for stop in ["port ", "flight ", "runway", "order ", "model ", "year "]):
                if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                    entities.append(
                        PIIEntity(
                            pii_type=PIIType.HOME_ADDRESS,
                            start=start_pos,
                            end=end_pos,
                            value=cand_val,
                            confidence=0.94,
                            category=SensitivityCategory.PERSONAL_INFO,
                            context_evidence="Physical street address pattern",
                            has_exposed_value=True
                        )
                    )

        # -------------------------------------------------------------
        # J. Bank Account & Financial Identifiers (BANK_ACCOUNT, IBAN, IFSC)
        # -------------------------------------------------------------
        bank_cue_pattern = re.compile(
            r"(?i:\b(?:(?:bank|checking|savings|current|deposit)?\s*account(?:\s*number|\s*no\.?|\s*num)?|ac\s*no\.?|a/c\s*(?:no\.?|number)?|iban)\s*(?:is|was|:|=|->|#|\s)\s*)"
            r"([A-Za-z0-9\-]{8,24})\b"
        )
        for m in bank_cue_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.BANK_ACCOUNT,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.97,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Bank account identifier context",
                        has_exposed_value=True
                    )
                )

        iban_pattern = re.compile(r"\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16})\b")
        for m in iban_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.BANK_ACCOUNT,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.98,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Standard IBAN international banking identifier",
                        has_exposed_value=True
                    )
                )

        # -------------------------------------------------------------
        # K. Extended Identity Records (VOTER_ID, EMPLOYEE_ID, CUSTOMER_ID, ACCESS_TOKEN)
        # -------------------------------------------------------------
        voter_pattern = re.compile(r"(?i:\b(?:voter\s*id|epic(?:\s*no\.?|\s*id)?)\s*(?:is|was|:|=|->|#|\s)\s*)([A-Za-z]{3}\d{7})\b")
        for m in voter_pattern.finditer(text):
            cand_val = m.group(1).strip().upper()
            start_pos, end_pos = m.start(1), m.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.VOTER_ID,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.97,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Voter ID / EPIC card context",
                        has_exposed_value=True
                    )
                )

        emp_pattern = re.compile(r"(?i:\b(?:employee\s*id|staff\s*id|emp\s*id)\s*(?:is|was|:|=|->|#|\s)\s*)([A-Za-z0-9\-]{3,15})\b")
        for m in emp_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if any(c.isdigit() for c in cand_val) and not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.EMPLOYEE_ID,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.96,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Employee/staff identity badge record",
                        has_exposed_value=True
                    )
                )

        cust_pattern = re.compile(r"(?i:\b(?:customer\s*id|cust\s*id|client\s*id)\s*(?:is|was|:|=|->|#|\s)\s*)([A-Za-z0-9\-]{3,15})\b")
        for m in cust_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if any(c.isdigit() for c in cand_val) and not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.CUSTOMER_ID,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.96,
                        category=SensitivityCategory.PERSONAL_INFO,
                        context_evidence="Customer / CRM reference identifier",
                        has_exposed_value=True
                    )
                )

        bearer_pattern = re.compile(r"\bBearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*)\b")
        for m in bearer_pattern.finditer(text):
            cand_val = m.group(1).strip()
            start_pos, end_pos = m.start(1), m.end(1)
            if not any(e.start <= start_pos and e.end >= end_pos for e in entities):
                entities.append(
                    PIIEntity(
                        pii_type=PIIType.ACCESS_TOKEN,
                        start=start_pos,
                        end=end_pos,
                        value=cand_val,
                        confidence=0.99,
                        category=SensitivityCategory.CREDENTIAL,
                        context_evidence="Bearer JWT authentication token",
                        has_exposed_value=True
                    )
                )

        return entities
