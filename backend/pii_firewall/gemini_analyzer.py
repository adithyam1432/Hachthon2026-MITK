"""
Google Gemini AI PII Analyzer and Recognizer.

Uses Google Gemini Free Tier API (gemini-1.5-flash / gemini-2.0-flash)
to perform semantic analysis, PII extraction, and context classification on user prompts.
Operates with graceful failover to local deterministic & NLP engines.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
import requests

from pii_firewall.models import (
    PIIEntity,
    PIIType,
    SensitivityCategory,
    TYPE_TO_CATEGORY,
)
from pii_firewall.recognizers.base import BasePIIRecognizer

logger = logging.getLogger("pii_firewall.gemini")

# Mapping from common Gemini type strings to PIIType enum
GEMINI_TYPE_MAP: Dict[str, PIIType] = {
    "EMAIL": PIIType.EMAIL,
    "EMAIL_ADDRESS": PIIType.EMAIL,
    "PHONE": PIIType.PHONE,
    "PHONE_NUMBER": PIIType.PHONE,
    "MOBILE": PIIType.PHONE,
    "SSN": PIIType.SSN,
    "SOCIAL_SECURITY_NUMBER": PIIType.SSN,
    "CREDIT_CARD": PIIType.CREDIT_CARD,
    "CARD_NUMBER": PIIType.CREDIT_CARD,
    "DEBIT_CARD": PIIType.CREDIT_CARD,
    "IP_ADDRESS": PIIType.IP_ADDRESS,
    "IP": PIIType.IP_ADDRESS,
    "API_KEY": PIIType.API_KEY,
    "SECRET_KEY": PIIType.API_KEY,
    "ACCESS_TOKEN": PIIType.ACCESS_TOKEN,
    "TOKEN": PIIType.ACCESS_TOKEN,
    "BEARER_TOKEN": PIIType.ACCESS_TOKEN,
    "PRIVATE_KEY": PIIType.PRIVATE_KEY,
    "PAN": PIIType.PAN_CARD,
    "PAN_CARD": PIIType.PAN_CARD,
    "AADHAAR": PIIType.AADHAAR,
    "AADHAAR_NUMBER": PIIType.AADHAAR,
    "AADHAAR_CARD": PIIType.AADHAAR,
    "ADHAAR": PIIType.AADHAAR,
    "ADHAR": PIIType.AADHAAR,
    "UIDAI": PIIType.AADHAAR,
    "PIN": PIIType.PIN,
    "ATM_PIN": PIIType.PIN,
    "PASSWORD": PIIType.PASSWORD,
    "PASSCODE": PIIType.PASSWORD,
    "CVV": PIIType.CVV,
    "OTP": PIIType.OTP,
    "PASSPORT": PIIType.PASSPORT,
    "DATE_OF_BIRTH": PIIType.DATE_OF_BIRTH,
    "DOB": PIIType.DATE_OF_BIRTH,
    "HOME_ADDRESS": PIIType.HOME_ADDRESS,
    "ADDRESS": PIIType.HOME_ADDRESS,
    "BANK_ACCOUNT": PIIType.BANK_ACCOUNT,
    "ACCOUNT_NUMBER": PIIType.BANK_ACCOUNT,
    "MEDICAL_DIAGNOSIS": PIIType.MEDICAL_DIAGNOSIS,
    "SALARY_INFO": PIIType.SALARY_INFO,
    "CONFIDENTIAL_SOURCE_CODE": PIIType.CONFIDENTIAL_SOURCE_CODE,
    "INTERNAL_SYSTEM_INSTRUCTIONS": PIIType.INTERNAL_SYSTEM_INSTRUCTIONS,
    "CUSTOMER_DATABASE": PIIType.CUSTOMER_DATABASE,
    "EMPLOYEE_RECORDS": PIIType.EMPLOYEE_RECORDS,
}


GEMINI_PII_SYSTEM_PROMPT = """You are a high-precision Personally Identifiable Information (PII) and Security Secrets Analyzer for an AI Agent firewall.
Analyze the user prompt and extract ALL sensitive items, credentials, and confidential records.

Categories to detect:
- EMAIL: Email addresses
- AADHAAR: Indian 12-digit Aadhaar/UIDAI numbers (continuous, spaced, dashed, or attached)
- PAN_CARD: Indian Permanent Account Numbers (5 letters, 4 digits, 1 letter)
- PHONE: Telephone/mobile numbers
- CREDIT_CARD: Credit and debit card numbers
- PIN: ATM PINs, debit PINs, card security PINs
- PASSWORD: User and system passwords, passcodes
- CVV: 3-4 digit card security verification codes
- OTP: One-time passwords, verification codes
- API_KEY: Cloud and API tokens (sk-, AKIA, etc.)
- SSN: US Social Security Numbers
- PASSPORT: International passport numbers
- BANK_ACCOUNT: Bank account numbers

CRITICAL FALSE-POSITIVE RULES:
- Operational scheduling parameters like "3pm", "3 pm", "9am", "tomorrow", "31st nov", "1st jan" are NOT PII and must NEVER be flagged.
- Normal business subjects or action phrases are NOT PII.

Return pure JSON conforming exactly to this structure:
{
  "entities": [
    {
      "value": "<exact substring extracted from input>",
      "type": "EMAIL | AADHAAR | PAN_CARD | PHONE | CREDIT_CARD | PIN | PASSWORD | CVV | OTP | API_KEY | SSN | PASSPORT | BANK_ACCOUNT",
      "confidence": 0.98,
      "context": "<brief reason or context explaining why this is sensitive>"
    }
  ]
}
"""


class GeminiPIIAnalyzer:
    """
    Client for Google Gemini Free Tier API to detect PII in prompts.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash",
        timeout: float = 6.0,
    ):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        self.timeout = timeout
        self.last_error: Optional[str] = None

    @property
    def is_available(self) -> bool:
        """Returns True if an API key is configured."""
        return bool(self.api_key and self.api_key.strip())

    def analyze_prompt(self, text: str) -> List[PIIEntity]:
        """
        Sends text to Google Gemini API to extract sensitive entities.
        Returns a list of PIIEntity objects with character positions.
        """
        if not self.is_available or not text or not text.strip():
            return []

        clean_text = text.strip()
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )

        request_body = {
            "system_instruction": {
                "parts": [{"text": GEMINI_PII_SYSTEM_PROMPT}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": clean_text}],
                }
            ],
            "generationConfig": {
                "temperature": 0.0,
                "responseMimeType": "application/json",
            },
        }

        try:
            resp = requests.post(
                url,
                json=request_body,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )

            if resp.status_code != 200:
                self.last_error = f"Gemini API HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning(self.last_error)
                return []

            data = resp.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return []

            first_part = candidates[0].get("content", {}).get("parts", [{}])[0]
            raw_json_str = first_part.get("text", "{}")

            parsed = json.loads(raw_json_str)
            raw_items = parsed.get("entities", [])

            entities: List[PIIEntity] = []
            for item in raw_items:
                raw_val = item.get("value", "").strip()
                if not raw_val:
                    continue

                type_key = str(item.get("type", "EMAIL")).upper().strip()
                pii_type = GEMINI_TYPE_MAP.get(type_key, PIIType.EMAIL)
                conf = float(item.get("confidence", 0.95))
                context_expl = item.get("context", "Identified by Gemini AI")

                # Locate all occurrences in text
                start_search = 0
                while True:
                    idx = text.find(raw_val, start_search)
                    if idx == -1:
                        # Try case-insensitive search if exact case was not found
                        idx = text.lower().find(raw_val.lower(), start_search)
                        if idx == -1:
                            break
                        raw_val = text[idx : idx + len(raw_val)]

                    end_pos = idx + len(raw_val)
                    category = TYPE_TO_CATEGORY.get(
                        pii_type, SensitivityCategory.PERSONAL_INFO
                    )

                    entities.append(
                        PIIEntity(
                            pii_type=pii_type,
                            start=idx,
                            end=end_pos,
                            value=raw_val,
                            confidence=conf,
                            category=category,
                            context_evidence=f"Gemini AI ({self.model}): {context_expl}",
                            has_exposed_value=True,
                        )
                    )
                    start_search = end_pos

            self.last_error = None
            return entities

        except requests.exceptions.Timeout:
            self.last_error = f"Gemini API timed out after {self.timeout}s. Falling back to local NLP engine."
            logger.warning(self.last_error)
            return []
        except Exception as ex:
            self.last_error = f"Gemini API request error ({type(ex).__name__}): {str(ex)}"
            logger.warning(self.last_error)
            return []


class GeminiPIIRecognizer(BasePIIRecognizer):
    """
    PII Recognizer wrapping the GeminiPIIAnalyzer into the firewall recognizer pipeline.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash",
        timeout: float = 6.0,
    ):
        super().__init__(pii_type=PIIType.EMAIL)
        self.analyzer = GeminiPIIAnalyzer(
            api_key=api_key, model=model, timeout=timeout
        )

    def find_entities(self, text: str) -> List[PIIEntity]:
        """Runs Gemini AI semantic extraction."""
        if not self.analyzer.is_available:
            return []
        return self.analyzer.analyze_prompt(text)
