"""
IP Address Recognizer.
Detects IPv4 addresses in free text and structured payloads.
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


class IPAddressRecognizer(BasePIIRecognizer):
    """
    Detects IPv4 addresses and validates valid octet ranges (0-255).
    Filters out common software versions like 1.2.3.4 if out of range.
    """

    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )

    def __init__(self):
        super().__init__(PIIType.IP_ADDRESS)

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        for match in self.IP_PATTERN.finditer(text):
            val = match.group(0)
            octets = val.split(".")
            if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
                # Ignore 0.0.0.0 if not needed, but keep standard IPs
                entities.append(
                    PIIEntity(
                        pii_type=self.pii_type,
                        start=match.start(),
                        end=match.end(),
                        value=val,
                        confidence=0.97,
                    )
                )

        return entities
