"""
Base class for PII Recognizers.
"""

from abc import ABC, abstractmethod
from typing import List
from pii_firewall.models import PIIEntity, PIIType


class BasePIIRecognizer(ABC):
    """Abstract base class for all PII pattern recognizers."""

    def __init__(self, pii_type: PIIType):
        self.pii_type = pii_type

    @abstractmethod
    def find_entities(self, text: str) -> List[PIIEntity]:
        """Scan text and return detected PII entities with offsets and confidence."""
        pass
