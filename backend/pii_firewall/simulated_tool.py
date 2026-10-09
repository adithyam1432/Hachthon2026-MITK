"""
Simulated External Tool for Hackathon Demonstration & Audit.
Records the exact payloads received to conclusively prove leakage prevention (FR-15).
"""

import copy
import json
from typing import Any, Callable, Dict, List, Optional


class SimulatedExternalTool:
    """
    Mock external tool (e.g., Email Service, CRM API, Database, SMS Gateway).
    Captures exact raw payloads received across requests.
    """

    def __init__(self, name: str = "MockExternalService"):
        self.name = name
        self.received_payloads: List[Any] = []
        self.call_history: List[Dict[str, Any]] = []

    def execute(self, payload: Any, custom_response_handler: Optional[Callable[[Any], Any]] = None) -> Any:
        """
        Receives payload, records exact incoming state, and generates a realistic tool response.
        """
        # Store an exact deep copy to audit what the tool received
        recorded_copy = copy.deepcopy(payload)
        self.received_payloads.append(recorded_copy)

        if custom_response_handler:
            response = custom_response_handler(recorded_copy)
        else:
            response = self._default_mock_response(recorded_copy)

        self.call_history.append({
            "received": recorded_copy,
            "response": response,
        })
        return response

    def _default_mock_response(self, payload: Any) -> Dict[str, Any]:
        """Generates standard acknowledgment echoing back parameters or tokens."""
        if isinstance(payload, dict):
            tool_name = payload.get("tool", self.name)
            args = payload.get("arguments", payload)
            return {
                "status": "success",
                "tool": tool_name,
                "message": f"Tool '{tool_name}' successfully executed.",
                "echo_arguments": args,
            }
        return {"status": "success", "echo": payload}

    def contains_any_string(self, target_strings: List[str]) -> bool:
        """Audits all captured payloads to see if any forbidden string arrived."""
        for payload in self.received_payloads:
            serialized = json.dumps(payload, default=str)
            for target in target_strings:
                if target and target in serialized:
                    return True
        return False

    def clear(self) -> None:
        """Resets recorded payloads."""
        self.received_payloads.clear()
        self.call_history.clear()
