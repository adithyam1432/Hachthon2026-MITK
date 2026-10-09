"""
API Key, Token and Secret Recognizer.
Detects sensitive credentials sent to tools (OpenAI, AWS, GitHub, Stripe, Bearer tokens).
"""

import re
from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


class APIKeyRecognizer(BasePIIRecognizer):
    """
    Detects API keys and secrets:
      - OpenAI (sk-..., sk-proj-...)
      - AWS Access Keys (AKIA...)
      - GitHub Tokens (ghp_..., github_pat_...)
      - Stripe Keys (sk_live_..., sk_test_...)
      - Generic Bearer tokens
    """

    KEY_PATTERNS = [
        # OpenAI API Key
        re.compile(r'\b(?:sk-[A-Za-z0-9]{32,}|sk-proj-[A-Za-z0-9_-]{32,})\b'),
        # AWS Access Key ID
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        # GitHub Personal Access Token
        re.compile(r'\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})\b'),
        # Stripe API Secret / Live / Test Key
        re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b'),
        # Bearer token in headers or auth strings
        re.compile(r'(?i)\bBearer\s+([A-Za-z0-9\-_=]{24,})\b'),
    ]

    def __init__(self):
        super().__init__(PIIType.API_KEY)

    def find_entities(self, text: str) -> List[PIIEntity]:
        if not text:
            return []

        entities: List[PIIEntity] = []
        matched_spans = set()

        for pattern in self.KEY_PATTERNS:
            for match in pattern.finditer(text):
                val = match.group(0)
                start = match.start()
                end = match.end()

                if any(s[0] <= start and s[1] >= end for s in matched_spans):
                    continue

                matched_spans.add((start, end))
                entities.append(
                    PIIEntity(
                        pii_type=self.pii_type,
                        start=start,
                        end=end,
                        value=val,
                        confidence=0.99,
                    )
                )

        return sorted(entities, key=lambda e: e.start)
