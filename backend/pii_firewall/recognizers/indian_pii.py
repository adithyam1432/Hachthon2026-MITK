"""
Indian Identifiers Recognizer: PAN Card & Aadhaar Number (with Verhoeff Checksum).
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


# Verhoeff algorithm multiplication table (d)
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

# Verhoeff permutation table (p)
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

def verhoeff_validate(number_str: str) -> bool:
    """Validates 12-digit Aadhaar number using official Verhoeff checksum algorithm."""
    if not number_str:
        return False
    c = 0
    # Process reversed digits
    for i, item in enumerate(reversed(number_str)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(item)]]
    return c == 0


class PANRecognizer(BasePIIRecognizer):
    """
    Detects Indian Permanent Account Number (PAN).
    Structure: 5 uppercase letters + 4 digits + 1 uppercase letter.
    4th character is entity status: [P, C, H, F, A, T, B, L, J, G].
    """

    PAN_PATTERN = re.compile(r'\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b')

    def __init__(self):
        super().__init__(PIIType.PAN_CARD)

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        for match in self.PAN_PATTERN.finditer(text):
            entities.append(
                PIIEntity(
                    pii_type=self.pii_type,
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    confidence=0.99,
                )
            )
        return entities


class AadhaarRecognizer(BasePIIRecognizer):
    """
    Detects 12-digit Indian Aadhaar Numbers.
    Formats: XXXX XXXX XXXX or XXXX-XXXX-XXXX or 12 continuous digits.
    Rules:
      - First digit cannot be 0 or 1.
      - Must pass UIDAI Verhoeff Checksum algorithm.
    """

    AADHAAR_PATTERN = re.compile(r'(?<!\d)([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})(?![ -]?\d)')

    def __init__(self, check_verhoeff: bool = True):
        super().__init__(PIIType.AADHAAR)
        self.check_verhoeff = check_verhoeff

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        for match in self.AADHAAR_PATTERN.finditer(text):
            raw_val = match.group(1)
            digits = re.sub(r'\D', '', raw_val)

            if len(digits) != 12:
                continue

            if self.check_verhoeff and not verhoeff_validate(digits):
                continue

            entities.append(
                PIIEntity(
                    pii_type=self.pii_type,
                    start=match.start(1),
                    end=match.end(1),
                    value=raw_val,
                    confidence=0.98,
                )
            )

        return entities
