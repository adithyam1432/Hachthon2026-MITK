"""
PII Recognizers registry and exports.
"""

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
    gemini_model: str = "gemini-1.5-flash",
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
    if gemini_api_key and gemini_api_key.strip():
        recognizers.append(GeminiPIIRecognizer(api_key=gemini_api_key, model=gemini_model))
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
