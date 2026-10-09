"""
Agent Framework SDK Adapters.
Provides clean wrappers and decorators for Python agent tools,
OpenAI Function Calling, LangChain, and CrewAI frameworks.
"""

import functools
import inspect
import json
from typing import Any, Callable, Dict, Optional, Union
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import FirewallConfig


class AgentToolAdapter:
    """Provides ergonomic developer decorators and interception wrappers for AI agent tools."""

    def __init__(self, firewall: Optional[PIIFirewall] = None):
        self.firewall = firewall or PIIFirewall()

    def protect_tool(
        self,
        func: Optional[Callable] = None,
        *,
        tool_name: Optional[str] = None,
        restore_response: bool = True,
    ):
        """
        Decorator to protect any Python agent tool function from PII leakage.
        Usage:
            @adapter.protect_tool
            def send_email(to: str, message: str) -> dict:
                ...
        """
        def decorator(f: Callable) -> Callable:
            name = tool_name or f.__name__

            @functools.wraps(f)
            def wrapper(*args, **kwargs) -> Any:
                # Bind function arguments to parameter names
                sig = inspect.signature(f)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                raw_arguments = dict(bound.arguments)

                # Form payload for firewall
                payload = {
                    "tool": name,
                    "arguments": raw_arguments,
                }

                # Inner execution callback
                def _run_tool(sanitized_payload: Dict[str, Any]) -> Any:
                    sanitized_args = sanitized_payload.get("arguments", {})
                    # Re-map arguments to function call
                    return f(**sanitized_args)

                # Execute through firewall
                envelope = self.firewall.process_tool_call(
                    request_payload=payload,
                    tool_callable=_run_tool,
                )

                if restore_response:
                    return envelope["response"]
                else:
                    return envelope["tool_response_raw"]

            wrapper.__firewall_protected__ = True
            wrapper.__tool_name__ = name
            return wrapper

        if func is None:
            return decorator
        return decorator(func)

    def intercept_openai_tool_call(
        self,
        tool_call_dict: Dict[str, Any],
        tool_runner: Callable[[str, Dict[str, Any]], Any],
    ) -> Dict[str, Any]:
        """
        Intercepts OpenAI standard tool_call format:
        {
            "id": "call_123",
            "type": "function",
            "function": {
                "name": "send_email",
                "arguments": "{\"to\": \"alex@demo.test\", ...}"
            }
        }
        """
        function_info = tool_call_dict.get("function", {})
        func_name = function_info.get("name", "unknown_tool")
        raw_args_str = function_info.get("arguments", "{}")

        try:
            parsed_args = json.loads(raw_args_str) if isinstance(raw_args_str, str) else raw_args_str
        except Exception:
            parsed_args = {"raw_arguments": raw_args_str}

        payload = {
            "tool": func_name,
            "arguments": parsed_args
        }

        def _execute(sanitized_payload: Dict[str, Any]) -> Any:
            sanitized_args = sanitized_payload.get("arguments", {})
            return tool_runner(func_name, sanitized_args)

        result = self.firewall.process_tool_call(
            request_payload=payload,
            tool_callable=_execute,
        )

        return {
            "tool_call_id": tool_call_dict.get("id"),
            "tool_name": func_name,
            "sanitized_arguments_sent": result["sanitized_payload_sent"].get("arguments"),
            "restored_output": result["response"],
            "metrics": result["metrics"],
        }
