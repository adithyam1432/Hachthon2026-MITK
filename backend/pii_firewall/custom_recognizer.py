"""
Dynamic Custom Recognizer Registration API for PII Firewall.
Allows developers to easily register custom regex or function-based PII recognizers at runtime.
"""

import re
from typing import Any, Callable, List, Optional, Pattern, Union
from pii_firewall.models import PIIEntity, PIIType
from pii_firewall.recognizers.base import BasePIIRecognizer


class CustomRegexRecognizer(BasePIIRecognizer):
    """
    Regex-based custom PII recognizer.
    Enables pattern matching with optional validator callbacks and context keyword filtering.
    """

    def __init__(
        self,
        pii_type: Union[PIIType, str],
        pattern: Union[str, Pattern],
        flags: int = 0,
        confidence: float = 1.0,
        validator: Optional[Callable[[str], bool]] = None,
        context_words: Optional[List[str]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(pii_type=pii_type)
        if isinstance(pattern, str):
            self.pattern: Pattern = re.compile(pattern, flags)
        else:
            self.pattern = pattern
        self.confidence = float(confidence)
        self.validator = validator
        self.context_words = [w.lower() for w in context_words] if context_words else None
        self.description = description

    def find_entities(self, text: str) -> List[PIIEntity]:
        """Scans text and returns detected PII entities matching regex and validations."""
        if not text:
            return []

        entities: List[PIIEntity] = []
        text_lower = text.lower() if self.context_words else ""

        for match in self.pattern.finditer(text):
            val = match.group(0)
            if not val:
                continue

            # Optional custom validation logic (e.g., checksum, digit check)
            if self.validator is not None:
                try:
                    if not self.validator(val):
                        continue
                except Exception:
                    # Validator failed or raised error
                    continue

            # Optional context words requirement
            if self.context_words:
                has_context = any(w in text_lower for w in self.context_words)
                if not has_context:
                    continue

            entities.append(
                PIIEntity(
                    pii_type=self.pii_type,
                    start=match.start(),
                    end=match.end(),
                    value=val,
                    confidence=self.confidence,
                )
            )

        return entities


class CustomFunctionRecognizer(BasePIIRecognizer):
    """
    Function-based custom PII recognizer allowing programmatic detection logic.
    Supports detectors returning:
      - List[PIIEntity]
      - List[Tuple[int, int]] (start, end)
      - List[Tuple[int, int, str]] (start, end, value)
      - List[Tuple[int, int, str, float]] (start, end, value, confidence)
      - List[Dict[str, Any]] with keys: 'start', 'end', optional 'value', 'confidence'
      - List[str] (exact string matches to find in text)
    """

    def __init__(
        self,
        pii_type: Union[PIIType, str],
        detector: Callable[[str], Any],
        confidence: float = 1.0,
        description: Optional[str] = None,
    ):
        super().__init__(pii_type=pii_type)
        self.detector = detector
        self.confidence = float(confidence)
        self.description = description

    def find_entities(self, text: str) -> List[PIIEntity]:
        """Executes the custom detection function and normalizes results into PIIEntities."""
        if not text:
            return []

        try:
            raw_result = self.detector(text)
        except Exception:
            return []

        if not raw_result:
            return []

        entities: List[PIIEntity] = []

        for item in raw_result:
            if isinstance(item, PIIEntity):
                entities.append(item)
            elif isinstance(item, (tuple, list)):
                if len(item) == 2:
                    start, end = int(item[0]), int(item[1])
                    val = text[start:end]
                    entities.append(
                        PIIEntity(
                            pii_type=self.pii_type,
                            start=start,
                            end=end,
                            value=val,
                            confidence=self.confidence,
                        )
                    )
                elif len(item) == 3:
                    start, end, val = int(item[0]), int(item[1]), str(item[2])
                    entities.append(
                        PIIEntity(
                            pii_type=self.pii_type,
                            start=start,
                            end=end,
                            value=val,
                            confidence=self.confidence,
                        )
                    )
                elif len(item) >= 4:
                    start, end, val, conf = int(item[0]), int(item[1]), str(item[2]), float(item[3])
                    entities.append(
                        PIIEntity(
                            pii_type=self.pii_type,
                            start=start,
                            end=end,
                            value=val,
                            confidence=conf,
                        )
                    )
            elif isinstance(item, dict):
                start = int(item["start"])
                end = int(item["end"])
                val = str(item.get("value", text[start:end]))
                conf = float(item.get("confidence", self.confidence))
                entities.append(
                    PIIEntity(
                        pii_type=self.pii_type,
                        start=start,
                        end=end,
                        value=val,
                        confidence=conf,
                    )
                )
            elif isinstance(item, str):
                # Search occurrences of this detected string in the text
                sub = item
                if not sub:
                    continue
                idx = 0
                while True:
                    found_idx = text.find(sub, idx)
                    if found_idx == -1:
                        break
                    entities.append(
                        PIIEntity(
                            pii_type=self.pii_type,
                            start=found_idx,
                            end=found_idx + len(sub),
                            value=sub,
                            confidence=self.confidence,
                        )
                    )
                    idx = found_idx + len(sub)

        return entities


def create_custom_recognizer(
    pii_type: Union[PIIType, str],
    pattern: Optional[Union[str, Pattern]] = None,
    detector: Optional[Callable[[str], Any]] = None,
    validator: Optional[Callable[[str], bool]] = None,
    confidence: float = 1.0,
    flags: int = 0,
    context_words: Optional[List[str]] = None,
    description: Optional[str] = None,
) -> BasePIIRecognizer:
    """
    Factory helper to instantiate either a CustomRegexRecognizer or CustomFunctionRecognizer.
    """
    if pattern is not None:
        return CustomRegexRecognizer(
            pii_type=pii_type,
            pattern=pattern,
            flags=flags,
            confidence=confidence,
            validator=validator,
            context_words=context_words,
            description=description,
        )
    elif detector is not None:
        return CustomFunctionRecognizer(
            pii_type=pii_type,
            detector=detector,
            confidence=confidence,
            description=description,
        )
    else:
        raise ValueError("Either 'pattern' (regex) or 'detector' (function) must be provided.")
