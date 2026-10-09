"""
Semantic & Context-Aware NLP Recognizer for PII Firewall.
Wraps ContextAwareNLPEngine into the BasePIIRecognizer architecture.
"""

from typing import List
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer
from pii_firewall.semantic_nlp import ContextAwareNLPEngine


class SemanticNLPRecognizer(BasePIIRecognizer):
    """
    Context-aware NLP Recognizer identifying semantic entities, PINs, Passwords,
    CVVs, OTPs, and Confidential Business information using surrounding language
    and entity relationships.
    """

    def __init__(self):
        super().__init__(pii_type=PIIType.PIN)

    def find_entities(self, text: str) -> List[PIIEntity]:
        """Runs 100% local context-aware NLP semantic scanning."""
        if not text:
            return []
        return ContextAwareNLPEngine.find_semantic_entities(text)
