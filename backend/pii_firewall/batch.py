"""
High-Performance Batch Processor for PII Firewall.
Allows AI agents to sanitize and restore batches of requests concurrently
with optimal throughput, low latency, and zero PII leakage guarantees.
"""

import concurrent.futures
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallConfig,
    FirewallMetrics,
    FirewallResult,
    FirewallBlockedError,
    PIILeakageDetectedError,
)
from pii_firewall.vault import RequestTokenVault


@dataclass
class BatchItemResult:
    """Result container for a single item within a batch execution."""
    index: int
    request_id: str
    sanitized_payload: Any = None
    tool_response_raw: Any = None
    response: Any = None
    metrics: Optional[FirewallMetrics] = None
    success: bool = True
    error: Optional[str] = None
    error_type: Optional[str] = None

    @property
    def sanitized_payload_sent(self) -> Any:
        return self.sanitized_payload

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "index": self.index,
            "request_id": self.request_id,
            "sanitized_payload": self.sanitized_payload,
            "sanitized_payload_sent": self.sanitized_payload,
            "tool_response_raw": self.tool_response_raw,
            "response": self.response,
            "success": self.success,
            "error": self.error,
            "error_type": self.error_type,
        }
        if self.metrics:
            d["metrics"] = self.metrics.to_dict()
        return d


@dataclass
class BatchProcessResult:
    """Aggregated result for a concurrent batch processing operation."""
    results: List[BatchItemResult]
    total_items: int
    successful_items: int
    failed_items: int
    total_duration_ms: float
    throughput_items_per_sec: float
    total_detected_pii: int = 0
    total_restored_pii: int = 0

    @property
    def sanitized_payloads(self) -> List[Any]:
        return [r.sanitized_payload for r in self.results]

    @property
    def responses(self) -> List[Any]:
        return [r.response for r in self.results]

    @property
    def has_errors(self) -> bool:
        return self.failed_items > 0

    @property
    def errors(self) -> List[Optional[str]]:
        return [r.error for r in self.results if not r.success]

    def __len__(self) -> int:
        return len(self.results)

    def __getitem__(self, index: Union[int, slice]) -> Any:
        if isinstance(index, slice):
            return self.results[index]
        return self.results[index]

    def __iter__(self) -> Iterator[BatchItemResult]:
        return iter(self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_items": self.total_items,
            "successful_items": self.successful_items,
            "failed_items": self.failed_items,
            "total_duration_ms": round(self.total_duration_ms, 3),
            "throughput_items_per_sec": round(self.throughput_items_per_sec, 2),
            "total_detected_pii": self.total_detected_pii,
            "total_restored_pii": self.total_restored_pii,
            "results": [r.to_dict() for r in self.results],
        }


class BatchPIIFirewall:
    """
    Concurrent batch processor for PII Firewall.
    Enables high-throughput concurrent sanitization and restoration
    across multiple agent tool calls or request payloads.
    """

    def __init__(
        self,
        firewall: Optional[PIIFirewall] = None,
        config: Optional[FirewallConfig] = None,
        max_workers: Optional[int] = None,
        **firewall_kwargs: Any,
    ):
        self.firewall = firewall or PIIFirewall(config=config, **firewall_kwargs)
        cpu_count = os.cpu_count() or 1
        self.max_workers = max_workers or min(32, cpu_count * 4)

    def register_custom_recognizer(self, *args: Any, **kwargs: Any) -> Any:
        """Delegates custom recognizer registration directly to the underlying firewall."""
        return self.firewall.register_custom_recognizer(*args, **kwargs)

    def _process_single(
        self,
        item: Any,
        idx: int,
        tool_callable: Optional[Callable[[Any], Any]],
        request_id: str,
        stop_on_error: bool,
    ) -> BatchItemResult:
        """Processes a single batch item (sanitize, optional tool execute, optional restore)."""
        try:
            # Check if item itself defines a dedicated callable
            effective_callable = tool_callable
            payload = item
            if isinstance(item, dict):
                if callable(item.get("tool_callable")):
                    effective_callable = item["tool_callable"]
                if "payload" in item and "tool" not in item:
                    payload = item["payload"]

            if effective_callable is not None:
                # Full end-to-end processing (sanitize -> execute tool -> restore)
                call_res = self.firewall.process_tool_call(
                    request_payload=payload,
                    tool_callable=effective_callable,
                    request_id=request_id,
                )
                # Reconstruct FirewallMetrics from call_res dictionary
                fw_metrics = FirewallMetrics(request_id=request_id)
                metrics_dict = call_res.get("metrics", {})
                fw_metrics.counts_by_type = metrics_dict.get("counts_by_type", {})
                fw_metrics.total_detected = metrics_dict.get("total_detected", 0)
                fw_metrics.verification_passed = metrics_dict.get("verification_passed", True)
                fw_metrics.processing_time_ms = metrics_dict.get("processing_time_ms", 0.0)
                fw_metrics.restored_count = metrics_dict.get("restored_count", 0)
                fw_metrics.restoration_time_ms = metrics_dict.get("restoration_time_ms", 0.0)

                return BatchItemResult(
                    index=idx,
                    request_id=request_id,
                    sanitized_payload=call_res["sanitized_payload_sent"],
                    tool_response_raw=call_res["tool_response_raw"],
                    response=call_res["response"],
                    metrics=fw_metrics,
                    success=True,
                )
            else:
                # Sanitization only mode
                fw_result, vault = self.firewall.intercept_request(
                    payload=payload,
                    request_id=request_id,
                )
                return BatchItemResult(
                    index=idx,
                    request_id=request_id,
                    sanitized_payload=fw_result.sanitized_payload,
                    tool_response_raw=None,
                    response=None,
                    metrics=fw_result.metrics,
                    success=True,
                )

        except Exception as e:
            if stop_on_error:
                raise e
            return BatchItemResult(
                index=idx,
                request_id=request_id,
                sanitized_payload=None,
                tool_response_raw=None,
                response=None,
                metrics=FirewallMetrics(request_id=request_id),
                success=False,
                error=str(e),
                error_type=type(e).__name__,
            )

    def process_batch(
        self,
        requests: Sequence[Any],
        tool_callable: Optional[Callable[[Any], Any]] = None,
        request_ids: Optional[Sequence[str]] = None,
        stop_on_error: bool = False,
        max_workers: Optional[int] = None,
    ) -> BatchProcessResult:
        """
        Processes a batch of requests concurrently.
        Supports both end-to-end tool execution (when tool_callable is provided)
        and concurrent sanitization.
        Maintains strict input order in the returned results.
        """
        n_items = len(requests)
        if n_items == 0:
            return BatchProcessResult(
                results=[],
                total_items=0,
                successful_items=0,
                failed_items=0,
                total_duration_ms=0.0,
                throughput_items_per_sec=0.0,
                total_detected_pii=0,
                total_restored_pii=0,
            )

        start_time = time.perf_counter()
        req_ids = [
            request_ids[i] if request_ids and i < len(request_ids) else str(uuid.uuid4())
            for i in range(n_items)
        ]

        workers = max_workers or self.max_workers
        workers = min(workers, n_items)

        results: List[Optional[BatchItemResult]] = [None] * n_items

        if workers <= 1 or n_items == 1:
            # Sequential execution for single item or single worker
            for idx, item in enumerate(requests):
                res = self._process_single(
                    item=item,
                    idx=idx,
                    tool_callable=tool_callable,
                    request_id=req_ids[idx],
                    stop_on_error=stop_on_error,
                )
                results[idx] = res
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_idx = {
                    executor.submit(
                        self._process_single,
                        item=item,
                        idx=idx,
                        tool_callable=tool_callable,
                        request_id=req_ids[idx],
                        stop_on_error=stop_on_error,
                    ): idx
                    for idx, item in enumerate(requests)
                }

                for future in concurrent.futures.as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        res = future.result()
                        results[idx] = res
                    except Exception as e:
                        if stop_on_error:
                            executor.shutdown(wait=False, cancel_futures=True)
                            raise e
                        results[idx] = BatchItemResult(
                            index=idx,
                            request_id=req_ids[idx],
                            success=False,
                            error=str(e),
                            error_type=type(e).__name__,
                        )

        total_duration_ms = (time.perf_counter() - start_time) * 1000.0
        elapsed_sec = max(total_duration_ms / 1000.0, 1e-6)
        throughput = n_items / elapsed_sec

        final_results = [r for r in results if r is not None]
        successful = sum(1 for r in final_results if r.success)
        failed = n_items - successful
        total_detected = sum(r.metrics.total_detected for r in final_results if r.metrics)
        total_restored = sum(r.metrics.restored_count for r in final_results if r.metrics)

        return BatchProcessResult(
            results=final_results,
            total_items=n_items,
            successful_items=successful,
            failed_items=failed,
            total_duration_ms=total_duration_ms,
            throughput_items_per_sec=throughput,
            total_detected_pii=total_detected,
            total_restored_pii=total_restored,
        )

    def sanitize_batch(
        self,
        requests: Sequence[Any],
        request_ids: Optional[Sequence[str]] = None,
        stop_on_error: bool = False,
        max_workers: Optional[int] = None,
    ) -> BatchProcessResult:
        """Concurrently sanitizes a batch of request payloads."""
        return self.process_batch(
            requests=requests,
            tool_callable=None,
            request_ids=request_ids,
            stop_on_error=stop_on_error,
            max_workers=max_workers,
        )

    def restore_batch(
        self,
        response_items: Sequence[Tuple[Any, str]],
        purge_vault: bool = True,
        stop_on_error: bool = False,
        max_workers: Optional[int] = None,
    ) -> List[Tuple[Any, FirewallMetrics]]:
        """
        Concurrently restores tokens across multiple responses.
        Each item is a tuple: (response_payload, request_id).
        Returns list of (restored_payload, metrics) matching input order.
        """
        n_items = len(response_items)
        if n_items == 0:
            return []

        def _restore_worker(item: Tuple[Any, str]) -> Tuple[Any, FirewallMetrics]:
            resp_payload, req_id = item
            return self.firewall.intercept_response(
                response_payload=resp_payload,
                request_id=req_id,
                purge_vault=purge_vault,
            )

        workers = max_workers or self.max_workers
        workers = min(workers, n_items)

        if workers <= 1 or n_items == 1:
            return [_restore_worker(item) for item in response_items]

        results: List[Optional[Tuple[Any, FirewallMetrics]]] = [None] * n_items
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_idx = {
                executor.submit(_restore_worker, item): idx
                for idx, item in enumerate(response_items)
            }
            for future in concurrent.futures.as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    if stop_on_error:
                        executor.shutdown(wait=False, cancel_futures=True)
                        raise e
                    results[idx] = (None, FirewallMetrics(request_id=""))

        return [r for r in results if r is not None]
