"""
Adversarial and Evasion Defenses for PII Firewall.
Protects against:
  1. Zero-width character & invisible unicode obfuscation (e.g., a\\u200bl\\u200be\\u200bx@test.com)
  2. Base64-encoded PII payload evasion
  3. Delimiter smuggling / Token forgery attacks
"""

import base64
import re
import unicodedata
from typing import List, Tuple
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


# Set of zero-width and invisible unicode characters used in evasion attacks
INVISIBLE_CHARS_REGEX = re.compile(
    r'[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u180E]'
)

BASE64_CANDIDATE_REGEX = re.compile(
    r'(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])'
)


class AdversarialDefenseNormalizer:
    """Sanitizes text against evasion attacks and detects obfuscated PII."""

    @staticmethod
    def strip_invisible_characters(text: str) -> str:
        """Removes zero-width and invisible characters while normalizing Unicode NFKC."""
        if not text:
            return text
        normalized = unicodedata.normalize("NFKC", text)
        return INVISIBLE_CHARS_REGEX.sub("", normalized)

    @staticmethod
    def inspect_base64_pii(
        text: str,
        recognizers: List[BasePIIRecognizer],
    ) -> List[Tuple[str, PIIEntity]]:
        """
        Inspects strings for embedded Base64-encoded sensitive information.
        Returns list of (base64_string, decoded_entity).
        """
        if not text:
            return []

        evasions: List[Tuple[str, PIIEntity]] = []
        for match in BASE64_CANDIDATE_REGEX.finditer(text):
            b64_candidate = match.group(0)
            try:
                decoded_bytes = base64.b64decode(b64_candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                # Run recognizers on decoded string
                for rec in recognizers:
                    entities = rec.find_entities(decoded_str)
                    for entity in entities:
                        evasions.append((b64_candidate, entity))
            except Exception:
                # Not valid UTF-8 base64 or decode failure
                continue

        return evasions

    @staticmethod
    def sanitize_delimiters(text: str, prefix: str = "⟦", suffix: str = "⟧") -> str:
        """
        Detects unauthenticated token delimiter smuggling in incoming agent inputs
        and escapes them to prevent token injection / mapping hijacking.
        """
        if prefix in text or suffix in text:
            # Replace fake incoming brackets with safe visual alternatives
            escaped = text.replace(prefix, "[PRE_EXISTING_DELIM_L_").replace(suffix, "_DELIM_R]")
            return escaped
        return text
