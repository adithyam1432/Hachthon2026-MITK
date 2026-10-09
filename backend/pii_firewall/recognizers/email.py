"""
Email Address Recognizer.
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


class EmailRecognizer(BasePIIRecognizer):
    """Detects RFC-compliant email addresses in free text and structured values."""

    EMAIL_PATTERN = re.compile(
        r'(?i)\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b'
    )

    def __init__(self):
        super().__init__(PIIType.EMAIL)

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        for match in self.EMAIL_PATTERN.finditer(text):
            value = match.group(1)
            # Remove any trailing punctuation erroneously caught if edge-case
            while value and value[-1] in ".,;:!?)":
                value = value[:-1]

            if "@" in value and "." in value.split("@")[-1]:
                start = match.start(1)
                end = start + len(value)
                entities.append(
                    PIIEntity(
                        pii_type=self.pii_type,
                        start=start,
                        end=end,
                        value=value,
                        confidence=0.98,
                    )
                )
        return entities
