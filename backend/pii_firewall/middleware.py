"""
PII Firewall Middleware for AI Agents.
Intercepts outgoing agent tool calls, sanitizes sensitive data with opaque tokens,
verifies zero leakage, forwards to external tool, and restores responses.
"""

import copy
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Pattern, Sequence, Tuple, Union
from pii_firewall.audit_logger import AuditLogger
from pii_firewall.models import (
    FirewallConfig,
    FirewallMetrics,
    FirewallResult,
    PIIEntity,
    PIIType,
    PIILeakageDetectedError,
    FirewallBlockedError,
)
from pii_firewall.policy import PolicyEngine
from pii_firewall.recognizers import get_default_recognizers
from pii_firewall.recognizers.base import BasePIIRecognizer
from pii_firewall.restoration import ResponseRestorer
from pii_firewall.scanner import JSONPIIScanner
from pii_firewall.vault import RequestTokenVault
from pii_firewall.verifier import LeakageVerifier


class PIIFirewall:
    """
    Middleware that intercepts outgoing AI-agent tool requests.
    Prevents PII leakage, maintains per-request reversible token vaults,
    and supports authorized response re-hydration.
    """

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.config = config or FirewallConfig()
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit_logger = audit_logger or AuditLogger()
        self.recognizers = get_default_recognizers(
            enabled_types=self.config.enabled_types,
            check_luhn=self.config.enable_luhn_validation,
            check_verhoeff=self.config.enable_verhoeff_validation,
            enable_semantic_nlp=self.config.enable_semantic_nlp,
            gemini_api_key=getattr(self.config, "gemini_api_key", None),
            gemini_model=getattr(self.config, "gemini_model", "gemini-3.5-flash-lite"),
            enable_cloud_ai=getattr(self.config, "enable_cloud_ai", False),
        )
        self.scanner = JSONPIIScanner(self.recognizers)
        self.verifier = LeakageVerifier()
        self.restorer = ResponseRestorer(
            prefix=self.config.token_format_prefix,
            suffix=self.config.token_format_suffix,
        )
        # Active vaults keyed by request_id
        self._active_vaults: Dict[str, RequestTokenVault] = {}
        self._lock = threading.Lock()

    def intercept_request(
        self,
        payload: Any,
        request_id: Optional[str] = None,
    ) -> Tuple[FirewallResult, RequestTokenVault]:
        """
        Intercepts an outgoing tool request.
        1. Scans and tokenizes PII in strings and free text.
        2. Verifies zero leakage.
        3. Returns FirewallResult and keeps vault for response restoration.
        """
        req_id = request_id or str(uuid.uuid4())
        start_time = time.perf_counter()

        vault = RequestTokenVault(
            request_id=req_id,
            prefix=self.config.token_format_prefix,
            suffix=self.config.token_format_suffix,
        )
        with self._lock:
            self._active_vaults[req_id] = vault

        metrics = FirewallMetrics(request_id=req_id)

        tool_name = payload.get("tool", "*") if isinstance(payload, dict) else "*"

        try:
            # 1. Recursive scan & tokenization with policy engine
            sanitized_payload, counts_by_type = self.scanner.scan_and_tokenize(
                payload=payload,
                vault=vault,
                tool_name=tool_name,
                policy_engine=self.policy_engine,
            )
            metrics.counts_by_type = counts_by_type
            metrics.total_detected = sum(counts_by_type.values())

            # 2. Strict post-tokenization leakage check (FR-12, FR-13)
            is_safe, leak_flags = self.verifier.verify(
                sanitized_payload=sanitized_payload,
                vault=vault,
                fail_safe_strict=self.config.fail_safe_strict,
            )
            metrics.verification_passed = is_safe

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            metrics.processing_time_ms = duration_ms

            # Safe compliance audit logging
            self.audit_logger.record_event(
                request_id=req_id,
                tool_name=tool_name,
                action="SANITIZED_AND_FORWARDED",
                counts_by_type=counts_by_type,
                duration_ms=duration_ms,
                verification_passed=is_safe,
                blocked=False,
                sanitized_payload=sanitized_payload,
            )

            result = FirewallResult(
                request_id=req_id,
                sanitized_payload=sanitized_payload,
                metrics=metrics,
                blocked=False,
                detected_entities=list(getattr(self.scanner, "last_detected_entities", [])),
            )
            return result, vault

        except PIILeakageDetectedError as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            metrics.processing_time_ms = duration_ms
            metrics.verification_passed = False

            self.audit_logger.record_event(
                request_id=req_id,
                tool_name=tool_name,
                action="BLOCKED_LEAKAGE_DETECTED",
                counts_by_type=metrics.counts_by_type,
                duration_ms=duration_ms,
                verification_passed=False,
                blocked=True,
                error_type="PIILeakageDetectedError",
            )
            raise e

        except FirewallBlockedError as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            metrics.processing_time_ms = duration_ms
            metrics.verification_passed = False

            self.audit_logger.record_event(
                request_id=req_id,
                tool_name=tool_name,
                action="BLOCKED_POLICY_VIOLATION",
                counts_by_type=metrics.counts_by_type,
                duration_ms=duration_ms,
                verification_passed=False,
                blocked=True,
                error_type="FirewallBlockedError",
            )
            raise e

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            metrics.processing_time_ms = duration_ms
            metrics.verification_passed = False

            self.audit_logger.record_event(
                request_id=req_id,
                tool_name=tool_name,
                action="BLOCKED_INTERNAL_ERROR",
                counts_by_type=metrics.counts_by_type,
                duration_ms=duration_ms,
                verification_passed=False,
                blocked=True,
                error_type=type(e).__name__,
            )

            if self.config.fail_safe_strict:
                raise FirewallBlockedError(f"Fail-safe block: unexpected firewall inspection error: {type(e).__name__}")
            result = FirewallResult(
                request_id=req_id,
                sanitized_payload=None,
                metrics=metrics,
                blocked=True,
                block_reason=str(e),
            )
            return result, vault

    def intercept_response(
        self,
        response_payload: Any,
        request_id: str,
        purge_vault: bool = True,
    ) -> Tuple[Any, FirewallMetrics]:
        """
        Intercepts incoming tool response and restores tokens if enabled.
        """
        start_time = time.perf_counter()
        with self._lock:
            vault = self._active_vaults.get(request_id)
        metrics = FirewallMetrics(request_id=request_id)

        if not vault:
            # Vault already purged or not found
            return response_payload, metrics

        if not self.config.allow_restoration:
            if purge_vault:
                vault.clear()
                with self._lock:
                    self._active_vaults.pop(request_id, None)
            return response_payload, metrics

        restored_payload, restored_count = self.restorer.restore(
            response_payload=response_payload,
            vault=vault,
            allowed_fields=self.config.allowed_restoration_fields,
        )

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        metrics.restored_count = restored_count
        metrics.restoration_time_ms = duration_ms

        if purge_vault:
            vault.clear()
            with self._lock:
                self._active_vaults.pop(request_id, None)

        return restored_payload, metrics

    def process_tool_call(
        self,
        request_payload: Any,
        tool_callable: Callable[[Any], Any],
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        End-to-end wrapper:
        1. Intercepts and sanitizes request.
        2. Executes tool callable with sanitized payload.
        3. Intercepts and restores response.
        4. Returns structured envelope with safe metrics.
        """
        fw_result, vault = self.intercept_request(request_payload, request_id=request_id)

        # Execute tool with sanitized payload
        tool_raw_response = tool_callable(fw_result.sanitized_payload)

        # Restore response
        restored_response, resp_metrics = self.intercept_response(
            response_payload=tool_raw_response,
            request_id=fw_result.request_id,
            purge_vault=True,
        )

        return {
            "request_id": fw_result.request_id,
            "sanitized_payload_sent": fw_result.sanitized_payload,
            "tool_response_raw": tool_raw_response,
            "response": restored_response,
            "metrics": {
                **fw_result.metrics.to_dict(),
                "restored_count": resp_metrics.restored_count,
                "restoration_time_ms": resp_metrics.restoration_time_ms,
                "total_overhead_ms": round(fw_result.metrics.processing_time_ms + resp_metrics.restoration_time_ms, 3),
            },
        }

    def register_custom_recognizer(
        self,
        recognizer: Optional[Union[BasePIIRecognizer, PIIType, str]] = None,
        *,
        pii_type: Optional[Union[PIIType, str]] = None,
        pattern: Optional[Union[str, Pattern]] = None,
        detector: Optional[Callable[[str], Any]] = None,
        validator: Optional[Callable[[str], bool]] = None,
        confidence: float = 1.0,
        flags: int = 0,
        context_words: Optional[List[str]] = None,
        priority: bool = False,
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> BasePIIRecognizer:
        """
        Dynamically registers a custom PII recognizer at runtime.
        Accepts:
          - A BasePIIRecognizer instance (e.g. CustomRegexRecognizer or CustomFunctionRecognizer)
          - Or pii_type + regex pattern
          - Or pii_type + custom detector function
        """
        from pii_firewall.custom_recognizer import (
            CustomRegexRecognizer,
            CustomFunctionRecognizer,
        )

        target_rec: BasePIIRecognizer
        if isinstance(recognizer, BasePIIRecognizer):
            target_rec = recognizer
        else:
            resolved_type = pii_type or recognizer or "CUSTOM_PII"
            if pattern is not None:
                target_rec = CustomRegexRecognizer(
                    pii_type=resolved_type,
                    pattern=pattern,
                    flags=flags,
                    confidence=confidence,
                    validator=validator,
                    context_words=context_words,
                    description=description,
                )
            elif detector is not None:
                target_rec = CustomFunctionRecognizer(
                    pii_type=resolved_type,
                    detector=detector,
                    confidence=confidence,
                    description=description,
                )
            else:
                raise ValueError(
                    "register_custom_recognizer requires either a BasePIIRecognizer instance, "
                    "a regex 'pattern', or a detection 'detector' callable."
                )

        with self._lock:
            if priority:
                self.recognizers.insert(0, target_rec)
            else:
                self.recognizers.append(target_rec)
            self.scanner.recognizers = self.recognizers
            if isinstance(target_rec.pii_type, PIIType):
                self.config.enabled_types.add(target_rec.pii_type)

        return target_rec

    def process_batch(
        self,
        requests: Sequence[Any],
        tool_callable: Optional[Callable[[Any], Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """
        Processes a batch of requests concurrently with optimal throughput.
        """
        from pii_firewall.batch import BatchPIIFirewall
        batch_fw = BatchPIIFirewall(firewall=self)
        return batch_fw.process_batch(requests, tool_callable=tool_callable, **kwargs)
