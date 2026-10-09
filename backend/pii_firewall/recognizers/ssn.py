"""
Social Security Number (SSN) Recognizer.
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


class SSNRecognizer(BasePIIRecognizer):
    """
    Detects US Social Security Numbers (SSN).
    Enforces SSA structural rules:
      - Format: AAA-GG-SSSS (with hyphens or spaces)
      - Area number (first 3 digits) cannot be 000, 666, or 900-999
      - Group number (middle 2 digits) cannot be 00
      - Serial number (last 4 digits) cannot be 0000
    """

    SSN_PATTERN = re.compile(r'\b(\d{3})[- ](\d{2})[- ](\d{4})\b')

    def __init__(self):
        super().__init__(PIIType.SSN)

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        for match in self.SSN_PATTERN.finditer(text):
            area, group, serial = match.group(1), match.group(2), match.group(3)
            area_num = int(area)

            # SSA validation rules
            if area_num == 0 or area_num == 666 or (900 <= area_num <= 999):
                continue
            if group == "00":
                continue
            if serial == "0000":
                continue

            full_val = match.group(0)
            entities.append(
                PIIEntity(
                    pii_type=self.pii_type,
                    start=match.start(),
                    end=match.end(),
                    value=full_val,
                    confidence=0.99,
                )
            )

        return entities
