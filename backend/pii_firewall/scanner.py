"""
Recursive JSON Scanner and Tokenizer with Adversarial Defenses & Granular Policy.
Walks nested JSON payloads, identifies PII in strings & free-text,
and applies policy actions (Tokenize, Redact, Mask, or Block) enforcing fail-closed principles.
"""

from typing import Any, Dict, List, Optional, Tuple
from pii_firewall.adversarial_defense import AdversarialDefenseNormalizer
from pii_firewall.models import PIIEntity, FirewallBlockedError, SensitivityCategory
from pii_firewall.policy import PolicyAction, PolicyEngine, generate_masked_value
from pii_firewall.recognizers.base import BasePIIRecognizer
from pii_firewall.vault import RequestTokenVault


class JSONPIIScanner:
    """Recursively scans and secures JSON payloads with adversarial defense normalization."""

    def __init__(self, recognizers: List[BasePIIRecognizer]):
        self.recognizers = recognizers

    def scan_and_tokenize(
        self,
        payload: Any,
        vault: RequestTokenVault,
        tool_name: str = "*",
        policy_engine: Optional[PolicyEngine] = None,
    ) -> Tuple[Any, Dict[str, int]]:
        """
        Recursively processes arbitrary JSON-like data.
        Returns:
            (sanitized_payload, counts_by_type)
        """
        counts_by_type: Dict[str, int] = {}
        policy = policy_engine or PolicyEngine()

        def _tokenize_text(raw_text: str, current_field: Optional[str] = None) -> str:
            # Step 1: Adversarial defense normalization (strip invisible zero-width chars)
            clean_text = AdversarialDefenseNormalizer.strip_invisible_characters(raw_text)

            # Step 2: Adversarial Base64 PII scan and replacement
            base64_leaks = AdversarialDefenseNormalizer.inspect_base64_pii(clean_text, self.recognizers)
            for b64_cand, decoded_entity in base64_leaks:
                type_name = decoded_entity.pii_type.value if hasattr(decoded_entity.pii_type, "value") else str(decoded_entity.pii_type)
                counts_by_type[type_name] = counts_by_type.get(type_name, 0) + 1
                action = policy.get_action_for_entity(
                    tool_name,
                    decoded_entity.pii_type,
                    current_field,
                    category=getattr(decoded_entity, "category", None)
                )
                if action == PolicyAction.BLOCK_TOOL:
                    raise FirewallBlockedError(
                        f"Firewall policy: Tool '{tool_name}' blocked from receiving base64-encoded {type_name}."
                    )
                # Register in vault & replace b64 candidate with safe token
                b64_token = vault.get_or_create_token(decoded_entity.value, decoded_entity.pii_type)
                clean_text = clean_text.replace(b64_cand, b64_token)

            # Step 3: Collect all detected entities across all recognizers
            raw_entities: List[PIIEntity] = []
            for recognizer in self.recognizers:
                try:
                    found = recognizer.find_entities(clean_text)
                    raw_entities.extend(found)
                except Exception as ex:
                    # Fail closed on scanner failure
                    raise FirewallBlockedError(
                        f"Scanner failure during inspection: {type(ex).__name__}. Failing closed to prevent unauthorized transmission."
                    )

            if not raw_entities:
                return clean_text

            # Step 4: Resolve overlaps
            raw_entities.sort(key=lambda e: (e.end - e.start, e.confidence), reverse=True)
            non_overlapping: List[PIIEntity] = []
            for cand in raw_entities:
                overlap = False
                for chosen in non_overlapping:
                    if not (cand.end <= chosen.start or cand.start >= chosen.end):
                        overlap = True
                        break
                if not overlap:
                    non_overlapping.append(cand)

            # Step 5: Sort entities right-to-left for in-place text slicing
            non_overlapping.sort(key=lambda e: e.start, reverse=True)

            text_chars = list(clean_text)
            for entity in non_overlapping:
                type_name = entity.pii_type.value if hasattr(entity.pii_type, "value") else str(entity.pii_type)
                counts_by_type[type_name] = counts_by_type.get(type_name, 0) + 1

                # Check policy action for this specific tool, field, & category
                action = policy.get_action_for_entity(
                    tool_name=tool_name,
                    pii_type=entity.pii_type,
                    field_name=current_field,
                    category=getattr(entity, "category", None)
                )

                if action == PolicyAction.BLOCK_TOOL:
                    cat_name = entity.category.value if hasattr(entity, "category") and hasattr(entity.category, "value") else "SENSITIVE_DATA"
                    raise FirewallBlockedError(
                        f"Firewall policy violation: Tool '{tool_name}' is strictly prohibited from receiving {cat_name} ({type_name})."
                    )
                elif action == PolicyAction.PASS_THROUGH:
                    # Allow raw value to pass through
                    continue
                elif action == PolicyAction.REDACT:
                    if getattr(entity, "category", None) == SensitivityCategory.CREDENTIAL:
                        replacement = "[REDACTED_CREDENTIAL]"
                    else:
                        replacement = f"[REDACTED_{type_name}]"
                elif action == PolicyAction.MASK:
                    replacement = generate_masked_value(entity.value, entity.pii_type)
                else:  # PolicyAction.TOKENIZE (Default reversible token)
                    replacement = vault.get_or_create_token(entity.value, entity.pii_type)

                # Splice text
                text_chars[entity.start:entity.end] = list(replacement)

            return "".join(text_chars)

        def _walk(item: Any, current_field: Optional[str] = None) -> Any:
            if isinstance(item, str):
                return _tokenize_text(item, current_field=current_field)
            elif isinstance(item, dict):
                return {k: _walk(v, current_field=k) for k, v in item.items()}
            elif isinstance(item, list):
                return [_walk(v, current_field=current_field) for v in item]
            elif isinstance(item, tuple):
                return tuple(_walk(v, current_field=current_field) for v in item)
            else:
                return item

        sanitized_payload = _walk(payload)
        return sanitized_payload, counts_by_type
