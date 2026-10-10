"""
PII Recognizers registry and exports.
"""

import os
from typing import Dict, List, Optional, Set
from pii_firewall.models import PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer
from pii_firewall.recognizers.email import EmailRecognizer
from pii_firewall.recognizers.phone import PhoneRecognizer
from pii_firewall.recognizers.ssn import SSNRecognizer
from pii_firewall.recognizers.credit_card import CreditCardRecognizer
from pii_firewall.recognizers.ip_address import IPAddressRecognizer
from pii_firewall.recognizers.api_key import APIKeyRecognizer
from pii_firewall.recognizers.indian_pii import PANRecognizer, AadhaarRecognizer
from pii_firewall.recognizers.semantic_nlp_recognizer import SemanticNLPRecognizer
from pii_firewall.gemini_analyzer import GeminiPIIRecognizer, GeminiPIIAnalyzer
from pii_firewall.custom_recognizer import (
    CustomRegexRecognizer,
    CustomFunctionRecognizer,
    create_custom_recognizer,
)


def get_default_recognizers(
    enabled_types: Set[PIIType],
    check_luhn: bool = True,
    check_verhoeff: bool = True,
    enable_semantic_nlp: bool = True,
    gemini_api_key: Optional[str] = None,
    gemini_model: str = "gemini-3.5-flash-lite",
    enable_cloud_ai: bool = False,
) -> List[BasePIIRecognizer]:
    """Factory creating recognizers based on enabled configuration."""
    recognizers: List[BasePIIRecognizer] = []
    if PIIType.EMAIL in enabled_types:
        recognizers.append(EmailRecognizer())
    if PIIType.PHONE in enabled_types:
        recognizers.append(PhoneRecognizer())
    if PIIType.SSN in enabled_types:
        recognizers.append(SSNRecognizer())
    if PIIType.CREDIT_CARD in enabled_types:
        recognizers.append(CreditCardRecognizer(check_luhn=check_luhn))
    if PIIType.IP_ADDRESS in enabled_types:
        recognizers.append(IPAddressRecognizer())
    if PIIType.API_KEY in enabled_types:
        recognizers.append(APIKeyRecognizer())
    if PIIType.PAN_CARD in enabled_types:
        recognizers.append(PANRecognizer())
    if PIIType.AADHAAR in enabled_types:
        recognizers.append(AadhaarRecognizer(check_verhoeff=check_verhoeff))
    if enable_semantic_nlp:
        recognizers.append(SemanticNLPRecognizer())
    active_gemini_key = gemini_api_key if gemini_api_key else (
        os.environ.get("GEMINI_API_KEY", "").strip()
        if (enable_cloud_ai and not os.environ.get("GEMINI_UNIT_TEST_MODE"))
        else ""
    )
    if active_gemini_key:
        recognizers.append(GeminiPIIRecognizer(api_key=active_gemini_key, model=gemini_model))
    return recognizers


__all__ = [
    "BasePIIRecognizer",
    "EmailRecognizer",
    "PhoneRecognizer",
    "SSNRecognizer",
    "CreditCardRecognizer",
    "IPAddressRecognizer",
    "APIKeyRecognizer",
    "PANRecognizer",
    "AadhaarRecognizer",
    "SemanticNLPRecognizer",
    "GeminiPIIRecognizer",
    "GeminiPIIAnalyzer",
    "CustomRegexRecognizer",
    "CustomFunctionRecognizer",
    "create_custom_recognizer",
    "get_default_recognizers",
]
