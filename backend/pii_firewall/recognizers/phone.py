"""
Phone Number Recognizer.
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


class PhoneRecognizer(BasePIIRecognizer):
    """
    Detects domestic and international telephone numbers.
    Supports formats like:
      - +1 (555) 123-4567
      - 555-123-4567
      - (555) 123-4567
      - +91 98765 43210
      - +91-9876543210
      - 555.123.4567
    """

    # Comprehensive phone regex capturing 10-15 digit phone patterns with valid delimiters
    PHONE_PATTERNS = [
        # International with + country code: e.g., +1-555-123-4567, +91 9876543210, +44 20 7946 0958
        re.compile(r'(?:^|(?<=[^\w]))\+\d{1,3}[-.\s]?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{4,6}\b'),
        # US/Canada standard: (555) 123-4567 or 555-123-4567 or 555.123.4567 with or without +1
        re.compile(r'(?:^|(?<=[^\w]))(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b'),
        # Indian standard 10 digit starting with 6, 7, 8, or 9 with optional +91 or 0 prefix
        re.compile(r'(?:^|(?<=[^\w]))(?:\+91[-.\s]?|0)?[6-9]\d{4}[-.\s]?\d{5}\b'),
    ]

    def __init__(self):
        super().__init__(PIIType.PHONE)

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        matched_spans = set()
        entities: List[PIIEntity] = []

        for pattern in self.PHONE_PATTERNS:
            for match in pattern.finditer(text):
                raw_val = match.group(0).strip()
                start = match.start()
                end = match.end()

                # Strip sentence punctuation and boundary quotes, but preserve leading '+' or '('
                clean_val = raw_val.strip(" ,;:!?'\"")
                # If trailing unbalanced parenthesis/bracket, trim it
                if clean_val.endswith(")") and "(" not in clean_val:
                    clean_val = clean_val[:-1]
                if clean_val.endswith("]") and "[" not in clean_val:
                    clean_val = clean_val[:-1]

                if not clean_val:
                    continue

                actual_start = text.find(clean_val, start)
                if actual_start == -1:
                    actual_start = start
                actual_end = actual_start + len(clean_val)

                # Count digits
                digits = re.sub(r'\D', '', clean_val)
                # Valid phone numbers usually have between 10 and 15 digits (or 7 with local exchange if strictly formatted)
                if not (10 <= len(digits) <= 15):
                    continue

                # Ignore obvious years or date sequences like 2026-10-09
                if re.match(r'^\d{4}[-/.]\d{2}[-/.]\d{2}$', clean_val):
                    continue

                # Avoid overlapping spans
                span_key = (actual_start, actual_end)
                if any(s[0] <= actual_start and s[1] >= actual_end for s in matched_spans):
                    continue

                matched_spans.add(span_key)
                entities.append(
                    PIIEntity(
                        pii_type=self.pii_type,
                        start=actual_start,
                        end=actual_end,
                        value=clean_val,
                        confidence=0.95,
                    )
                )

        return sorted(entities, key=lambda e: e.start)
