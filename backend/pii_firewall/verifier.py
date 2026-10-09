"""
Post-Tokenization Leakage Verifier.
Performs strict audit on the sanitized payload to guarantee that no detected
original PII values are present before outgoing transmission.
"""

import json
from typing import Any, List, Set, Tuple
from pii_firewall.models import PIILeakageDetectedError
from pii_firewall.vault import RequestTokenVault


class LeakageVerifier:
    """Verifies that none of the detected original PII values exist in the sanitized output."""

    @staticmethod
    def verify(
        sanitized_payload: Any,
        vault: RequestTokenVault,
        fail_safe_strict: bool = True,
    ) -> Tuple[bool, List[str]]:
        """
        Scans sanitized payload for any substring match against original detected values.
        Returns:
            (is_safe, list_of_leak_flags_without_values)
        """
        original_values: Set[str] = vault.get_all_original_values()
        if not original_values:
            return True, []

        try:
            # Serialize the sanitized payload to string for rapid global substring checking
            serialized_text = json.dumps(sanitized_payload, default=str)
        except Exception:
            # If serialization fails, treat as a fail-safe block
            if fail_safe_strict:
                raise PIILeakageDetectedError(
                    "Payload cannot be serialized for safety verification. Request blocked by fail-safe policy."
                )
            return False, ["SerializationCheckFailed"]

        leak_indicators: List[str] = []
        for orig in original_values:
            if not orig:
                continue
            # Check if original value is still present anywhere in the outgoing payload
            if orig in serialized_text:
                # IMPORTANT (FR-14 & FR-21): Do NOT include the original raw PII in error messages or telemetry
                leak_indicators.append(f"Detected PII of length {len(orig)} remained in outgoing payload")

        if leak_indicators:
            if fail_safe_strict:
                raise PIILeakageDetectedError(
                    f"Firewall blocked outgoing request: Leakage verification failed ({len(leak_indicators)} residual detected item(s) found)."
                )
            return False, leak_indicators

        return True, []
