"""
Response Token Restoration (Re-hydration) Engine.
Restores tokens found in tool responses back to their original values
using strictly the request-scoped vault.
"""

import re
from typing import Any, List, Optional, Tuple
from pii_firewall.vault import RequestTokenVault


class ResponseRestorer:
    """Restores opaque tokens back to their original values in tool responses."""

    def __init__(self, prefix: str = "⟦", suffix: str = "⟧"):
        escaped_prefix = re.escape(prefix)
        escaped_suffix = re.escape(suffix)
        # Token pattern: e.g. ⟦[a-zA-Z0-9_-]+_[a-f0-9]+⟧
        self.token_regex = re.compile(rf"{escaped_prefix}([a-zA-Z0-9_\-]+_[a-zA-Z0-9]+){escaped_suffix}")
        self.prefix = prefix
        self.suffix = suffix

    def restore(
        self,
        response_payload: Any,
        vault: RequestTokenVault,
        allowed_fields: Optional[List[str]] = None,
    ) -> Tuple[Any, int]:
        """
        Recursively restores tokens in response_payload.
        Returns:
            (restored_payload, total_restored_count)
        """
        restored_count = 0

        def _restore_string(text: str) -> str:
            nonlocal restored_count
            if not text:
                return text

            def _replace_token(match: re.Match) -> str:
                nonlocal restored_count
                full_token = match.group(0)
                original = vault.get_original(full_token)
                if original is not None:
                    restored_count += 1
                    return original
                # FR-19: Unknown or malformed tokens are left unchanged
                return full_token

            return self.token_regex.sub(_replace_token, text)

        allowed_set = set(allowed_fields) if allowed_fields is not None else None

        def _walk(
            item: Any,
            current_key: Optional[str] = None,
            parent_allowed: bool = False,
            key_path: str = "",
        ) -> Any:
            # Determine if this node is permitted by allowed_fields
            is_node_allowed = (
                allowed_set is None
                or parent_allowed
                or (current_key in allowed_set if current_key else False)
                or (key_path in allowed_set if key_path else False)
            )

            # If not allowed and this is a leaf (non-container), do not restore tokens
            if allowed_set is not None and not is_node_allowed and not isinstance(item, (dict, list, tuple)):
                return item

            if isinstance(item, str):
                if is_node_allowed:
                    return _restore_string(item)
                return item
            elif isinstance(item, dict):
                return {
                    k: _walk(
                        v,
                        current_key=k,
                        parent_allowed=is_node_allowed,
                        key_path=f"{key_path}.{k}" if key_path else k,
                    )
                    for k, v in item.items()
                }
            elif isinstance(item, list):
                return [
                    _walk(
                        v,
                        current_key=current_key,
                        parent_allowed=is_node_allowed,
                        key_path=key_path,
                    )
                    for v in item
                ]
            elif isinstance(item, tuple):
                return tuple(
                    _walk(
                        v,
                        current_key=current_key,
                        parent_allowed=is_node_allowed,
                        key_path=key_path,
                    )
                    for v in item
                )
            else:
                return item

        restored_payload = _walk(response_payload)
        return restored_payload, restored_count
