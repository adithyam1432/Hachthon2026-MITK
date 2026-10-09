"""
Payment Card / Credit Card Recognizer with Luhn Algorithm Checksum.
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


def luhn_checksum_valid(number_str: str) -> bool:
    """Verifies credit card number using Luhn algorithm (mod 10)."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if not (13 <= len(digits) <= 19) or set(digits) == {0}:
        return False

    checksum = 0
    # Process from right to left
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d

    return checksum % 10 == 0


class CreditCardRecognizer(BasePIIRecognizer):
    """
    Detects Visa, MasterCard, American Express, Discover, Diners Club card numbers.
    Validates numbers using the Luhn mod 10 checksum algorithm to prevent false positives.
    """

    CARD_PATTERN = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?'                      # Visa
        r'|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}' # MasterCard
        r'|3[47][0-9]{13}'                                  # Amex
        r'|6(?:011|5[0-9]{2})[0-9]{12}'                     # Discover
        r'|\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}'                 # 16-digit generic spaced/dashed
        r'|\d{4}[- ]\d{6}[- ]\d{5}'                          # 15-digit Amex spaced
        r')\b'
    )

    def __init__(self, check_luhn: bool = True):
        super().__init__(PIIType.CREDIT_CARD)
        self.check_luhn = check_luhn

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        for match in self.CARD_PATTERN.finditer(text):
            start = match.start()
            end = match.end()

            # Reject if part of a longer hyphenated/digit number (e.g. 1111-4111-... or ...-1111-2222)
            if start > 0:
                if text[start - 1].isdigit():
                    continue
                if text[start - 1] == '-' and start > 1 and text[start - 2].isdigit():
                    continue

            if end < len(text):
                if text[end].isdigit():
                    continue
                if text[end] == '-' and end + 1 < len(text) and text[end + 1].isdigit():
                    continue

            raw_val = match.group(0)
            cleaned_digits = re.sub(r'\D', '', raw_val)

            if self.check_luhn and not luhn_checksum_valid(cleaned_digits):
                continue

            entities.append(
                PIIEntity(
                    pii_type=self.pii_type,
                    start=match.start(),
                    end=match.end(),
                    value=raw_val,
                    confidence=0.99,
                )
            )

        return entities
