"""
Request-Scoped Reversible Token Vault.
Manages bidirectional mapping between original PII and opaque tokens.
Guarantees tokens do not reveal original values and mappings are isolated per request.
"""

import hashlib
import os
import uuid
from typing import Dict, Optional, Set
from pii_firewall.models import PIIType


class RequestTokenVault:
    """
    Isolated in-memory vault for a single request lifecycle.
    Maps:
      - original_pii_value -> opaque_token
      - opaque_token -> original_pii_value
    """

    def __init__(
        self,
        request_id: Optional[str] = None,
        prefix: str = "⟦",
        suffix: str = "⟧",
        client_mac: Optional[str] = None,
    ):
        self.request_id = request_id or str(uuid.uuid4())
        self.prefix = prefix
        self.suffix = suffix
        self.client_mac = client_mac
        # Random salt per request to ensure tokens are opaque and unpredictable across requests
        self._salt = os.urandom(16)
        if client_mac:
            # Cryptographically bind hardware Layer 2 MAC identity into the salt
            self._salt = hashlib.sha256(self._salt + client_mac.encode("utf-8")).digest()[:16]
        # Bidirectional storage
        self._value_to_token: Dict[str, str] = {}
        self._token_to_value: Dict[str, str] = {}
        self._token_types: Dict[str, PIIType] = {}

    def verify_client_identity(self, mac_address: Optional[str]) -> bool:
        """
        Validates that the restoring client matches the Layer 2 MAC address that initiated the vault.
        Returns True if matching or unconstrained; False if MAC mismatch (spoofing attempt).
        """
        if not self.client_mac:
            return True
        return self.client_mac.lower() == (mac_address or "").lower()

    def get_or_create_token(self, value: str, pii_type: PIIType) -> str:
        """
        Returns an existing token for the value if already encountered in this request,
        or creates a new opaque token. Ensures FR-9 (consistent mapping within request).
        """
        # Canonicalize lookup key (preserve original value for restoration)
        type_str = pii_type.value if hasattr(pii_type, "value") else str(pii_type)
        lookup_key = f"{type_str}:{value}"
        if lookup_key in self._value_to_token:
            return self._value_to_token[lookup_key]

        # Generate deterministic opaque hash slice using the request salt
        h = hashlib.sha256(self._salt + lookup_key.encode("utf-8")).hexdigest()[:8]
        token = f"{self.prefix}{type_str}_{h}{self.suffix}"

        # Handle unlikely hash collision
        collision_counter = 1
        while token in self._token_to_value and self._token_to_value[token] != value:
            h_alt = hashlib.sha256(f"{h}_{collision_counter}".encode("utf-8")).hexdigest()[:8]
            token = f"{self.prefix}{type_str}_{h_alt}{self.suffix}"
            collision_counter += 1

        self._value_to_token[lookup_key] = token
        self._token_to_value[token] = value
        try:
            self._token_types[token] = pii_type if isinstance(pii_type, PIIType) else PIIType(type_str)
        except (ValueError, TypeError):
            self._token_types[token] = type_str
        return token

    def get_original(self, token: str) -> Optional[str]:
        """Looks up the original value for a given token."""
        return self._token_to_value.get(token)

    def get_all_original_values(self) -> Set[str]:
        """Returns set of all original PII strings recorded during this request."""
        return set(self._token_to_value.values())

    def get_token_count(self) -> int:
        """Returns number of unique tokens created."""
        return len(self._token_to_value)

    def clear(self) -> None:
        """Purges mapping memory explicitly after request lifecycle finishes."""
        self._value_to_token.clear()
        self._token_to_value.clear()
        self._token_types.clear()
        self._salt = b""
