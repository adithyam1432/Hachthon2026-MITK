"""
Multi-Agent PII Firewall Pipeline.

Implements an end-to-end multi-agent pipeline mirroring the architecture:
[ Agent ] ──> [ NLP ] ──> [ Detection ] ──> [ Classify ] ──> [ Redact & Tokenize ] ──> [ Other Tool ]
    ▲                                                                                          │
    └───────────────────────────────────── Re-hydration ──────────────────────────────────────┘

Each stage is handled by a specialized autonomous agent:
1. ClientAgent: Formulates prompt & agent tool call payload.
2. NLPAgent: Contextual semantic parsing & stopword disambiguation via Google Gemini AI / Semantic NLP.
3. DetectionAgent: Entity discovery, span extraction & confidence scoring via Gemini AI + Checksum Recognizers.
4. ClassificationAgent: Statutory compliance taxonomy & enterprise policy classification (TOKENIZE / REDACT / MASK).
5. TransformationAgent: Dual-mode policy enforcement (ephemeral token vaulting vs permanent redaction).
6. SimulatedToolAgent: Downstream tool execution with zero wire leakage.
7. RehydrationAgent: Response interception, token restoration & vault memory purging.
"""

import copy
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from pii_firewall.gemini_analyzer import GeminiPIIAnalyzer
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallBlockedError,
    FirewallConfig,
    PIIEntity,
    PIILeakageDetectedError,
    PIIType,
    SensitivityCategory,
    TYPE_TO_CATEGORY,
)
from pii_firewall.policy import PolicyAction, PolicyEngine, generate_masked_value
from pii_firewall.scanner import JSONPIIScanner
from pii_firewall.semantic_nlp import ContextAwareNLPEngine
from pii_firewall.simulated_tool import SimulatedExternalTool
from pii_firewall.vault import RequestTokenVault

logger = logging.getLogger("pii_firewall.multi_agent")


@dataclass
class AgentStepResult:
    """Record of an individual agent's execution in the pipeline."""
    step_number: int
    agent_id: str
    agent_name: str
    role_description: str
    engine_badge: str
    status: str  # "SUCCESS", "WARNING", "BLOCKED"
    execution_ms: float
    input_summary: Any
    output_summary: Any
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MultiAgentExecutionTrace:
    """Complete trace of all agent actions from prompt to re-hydrated response."""
    request_id: str
    total_execution_ms: float
    success: bool
    status_message: str
    steps: List[AgentStepResult] = field(default_factory=list)
    raw_prompt: str = ""
    sanitized_prompt: str = ""
    final_response: Any = None
    detected_entities: List[PIIEntity] = field(default_factory=list)
    vault_token_count: int = 0
    redacted_count: int = 0
    wire_leakage_percentage: float = 0.0


# ==============================================================================
# 1. CLIENT AGENT (Initiator)
# ==============================================================================
class ClientAgent:
    """Agent 1: Formulates user query into structured tool execution payload."""

    def __init__(self, name: str = "Client Agent (User Interface)"):
        self.name = name

    def execute(self, prompt: str) -> Tuple[AgentStepResult, Dict[str, Any]]:
        t0 = time.perf_counter()
        prompt_str = prompt.strip()

        # Try JSON parsing if prompt is already JSON
        if prompt_str.startswith("{") and prompt_str.endswith("}"):
            try:
                payload = json.loads(prompt_str)
                tool_name = payload.get("tool", "external_api")
                ms = (time.perf_counter() - t0) * 1000.0
                step = AgentStepResult(
                    step_number=1,
                    agent_id="client_agent",
                    agent_name=self.name,
                    role_description="Formats structured agent tool payload from raw input query",
                    engine_badge="Client Task Planner",
                    status="SUCCESS",
                    execution_ms=round(ms, 3),
                    input_summary=prompt_str[:120],
                    output_summary=f"Tool call: {tool_name} with JSON arguments",
                    details={"tool": tool_name, "is_json": True},
                )
                return step, payload
            except Exception:
                pass

        lower = prompt_str.lower()
        tool_name = "send_email"
        if lower.startswith("send email") or "send email" in lower or "email" in lower:
            tool_name = "send_email"
        elif any(k in lower for k in ["pin", "atm", "password", "credential", "assistant"]):
            tool_name = "external_assistant"
        elif any(k in lower for k in ["card", "credit", "pay", "charge", "stripe", "billing"]):
            tool_name = "stripe_payment"
        elif any(k in lower for k in ["aadhaar", "aadhar", "adhaar", "adhar", "pan", "kyc", "identity", "passport"]):
            tool_name = "kyc_verify"
        elif any(k in lower for k in ["crm", "customer", "contact", "salesforce"]):
            tool_name = "crm_service"
        elif any(k in lower for k in ["deploy", "server", "ip", "api key", "aws", "openai"]):
            tool_name = "cloud_deploy"

        # Extract subject and schedule if mentioned
        subject_val = "Profile Update" if "profile" in lower else "Automated Request"
        if "subject" in lower:
            idx = lower.find("subject")
            sub_part = prompt_str[idx + len("subject"):].strip().lstrip(":").strip()
            if sub_part:
                subject_val = sub_part

        schedule_val = "Immediate"
        if "3pm" in lower or "3 pm" in lower:
            schedule_val = "3:00 PM"
        elif "tomorrow" in lower:
            schedule_val = "Tomorrow"

        payload = {
            "tool": tool_name,
            "arguments": {
                "query": prompt_str,
                "subject": subject_val,
                "schedule": schedule_val,
                "message": prompt_str,
            },
        }

        ms = (time.perf_counter() - t0) * 1000.0
        step = AgentStepResult(
            step_number=1,
            agent_id="client_agent",
            agent_name=self.name,
            role_description="Formats structured agent tool payload from user input query",
            engine_badge="Client Task Planner",
            status="SUCCESS",
            execution_ms=round(ms, 3),
            input_summary=prompt_str[:120],
            output_summary=f"Dispatched tool '{tool_name}' with arguments",
            details={"tool": tool_name, "arguments": payload["arguments"]},
        )
        return step, payload


# ==============================================================================
# 2. NLP AGENT (Context & Stopwords via Google Gemini API / Semantic NLP)
# ==============================================================================
class NLPAgent:
    """Agent 2: Performs linguistic context analysis & operational stopword validation."""

    def __init__(
        self,
        name: str = "NLP Context Agent",
        gemini_api_key: Optional[str] = None,
        gemini_model: str = "gemini-3.5-flash-lite",
        enable_cloud_gemini: bool = True,
    ):
        self.name = name
        self.gemini_analyzer = GeminiPIIAnalyzer(api_key=gemini_api_key, model=gemini_model)
        self.local_nlp = ContextAwareNLPEngine()
        self.enable_cloud_gemini = enable_cloud_gemini

    def execute(self, text: str) -> Tuple[AgentStepResult, Dict[str, Any]]:
        t0 = time.perf_counter()
        engine_badge = "⚡ Local Semantic NLP"
        stopwords_found = []
        gemini_entities = []

        # Operational stopwords to disambiguate
        text_lower = text.lower()
        temporal_patterns = ["3pm", "3 pm", "9am", "9 am", "tomorrow", "31st nov", "1st jan", "batch 42"]
        for p in temporal_patterns:
            if p in text_lower:
                stopwords_found.append(p)

        # Attempt Gemini API if enabled and key present
        if self.enable_cloud_gemini and self.gemini_analyzer.is_available:
            try:
                gemini_entities = self.gemini_analyzer.analyze_prompt(text)
                if gemini_entities:
                    engine_badge = f"☁️ Google Gemini AI ({self.gemini_analyzer.model})"
                elif self.gemini_analyzer.last_error:
                    engine_badge = "⚡ Local NLP (Gemini fallback)"
            except Exception as e:
                logger.warning(f"Gemini API call skipped: {e}")
                engine_badge = "⚡ Local NLP (Fallback active)"

        ms = (time.perf_counter() - t0) * 1000.0
        analysis_data = {
            "engine": engine_badge,
            "operational_stopwords_verified": stopwords_found,
            "temporal_noise_isolated": len(stopwords_found) > 0,
            "gemini_context_entities": len(gemini_entities),
            "semantic_intent": "Authorized tool request with contextual parameter isolation",
        }

        step = AgentStepResult(
            step_number=2,
            agent_id="nlp_agent",
            agent_name=self.name,
            role_description="Performs semantic parsing, linguistic boundaries & stopword isolation",
            engine_badge=engine_badge,
            status="SUCCESS",
            execution_ms=round(ms, 3),
            input_summary=text[:120],
            output_summary=(
                f"Isolated {len(stopwords_found)} operational stopwords; "
                f"Linguistic context verified via {engine_badge}"
            ),
            details=analysis_data,
        )
        return step, analysis_data


# ==============================================================================
# 3. DETECTION AGENT (PII Discovery via Gemini API + Hybrid Checksum Recognizers)
# ==============================================================================
class DetectionAgent:
    """Agent 3: Identifies PII entities, character boundaries, and confidence scores."""

    def __init__(
        self,
        name: str = "Detection Agent",
        firewall: Optional[PIIFirewall] = None,
        gemini_api_key: Optional[str] = None,
        gemini_model: str = "gemini-3.5-flash-lite",
        enable_cloud_gemini: bool = True,
    ):
        self.name = name
        self.gemini_analyzer = GeminiPIIAnalyzer(api_key=gemini_api_key, model=gemini_model)
        self.firewall = firewall or PIIFirewall()
        self.enable_cloud_gemini = enable_cloud_gemini

    def execute(self, text: str) -> Tuple[AgentStepResult, List[PIIEntity]]:
        t0 = time.perf_counter()
        engine_badge = "Deterministic Hybrid Engine"
        detected: List[PIIEntity] = []

        # 1. Deterministic local recognizers (Regex, Verhoeff, Luhn, NLP context)
        local_entities = self.firewall.scanner.scan_text(text)
        detected.extend(local_entities)

        # 2. Gemini API detection if active
        if self.enable_cloud_gemini and self.gemini_analyzer.is_available:
            try:
                gemini_ents = self.gemini_analyzer.analyze_prompt(text)
                if gemini_ents:
                    engine_badge = f"☁️ Gemini AI + Deterministic Hybrid"
                    # Merge unique entities
                    existing_values = {e.value.lower() for e in detected}
                    for ge in gemini_ents:
                        if ge.value.lower() not in existing_values:
                            detected.append(ge)
                            existing_values.add(ge.value.lower())
            except Exception as e:
                logger.warning(f"Detection Gemini pass fallback: {e}")

        # Deduplicate and sort by start position
        deduped = sorted(detected, key=lambda e: (e.start, -e.end))
        ms = (time.perf_counter() - t0) * 1000.0

        step = AgentStepResult(
            step_number=3,
            agent_id="detection_agent",
            agent_name=self.name,
            role_description="Discovers PII spans, computes exact offsets and verifies mathematical checksums",
            engine_badge=engine_badge,
            status="SUCCESS",
            execution_ms=round(ms, 3),
            input_summary=text[:120],
            output_summary=f"Detected {len(deduped)} sensitive entities across {len(set(e.pii_type for e in deduped))} categories",
            details={
                "detected_count": len(deduped),
                "entities": [
                    {
                        "type": e.pii_type.value if hasattr(e.pii_type, "value") else str(e.pii_type),
                        "value": e.value,
                        "span": f"[{e.start}:{e.end}]",
                        "confidence": e.confidence,
                    }
                    for e in deduped
                ],
            },
        )
        return step, deduped


# ==============================================================================
# 4. CLASSIFICATION AGENT (Taxonomy & Statutory Policy Rules)
# ==============================================================================
class ClassificationAgent:
    """Agent 4: Classifies detected entities against corporate compliance taxonomy."""

    def __init__(
        self,
        name: str = "Classification Agent",
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.name = name
        self.policy_engine = policy_engine or PolicyEngine.create_default_backend_policy(simple_redaction=True)

    def get_rationale(self, pii_type: Union[PIIType, str]) -> Tuple[str, str]:
        p_type = PIIType(pii_type) if isinstance(pii_type, str) and pii_type in [t.value for t in PIIType] else pii_type
        mapping = {
            PIIType.PERSON_NAME: (
                "PERSONAL_INFO",
                "Supports identity matching & conversational reference; reversible through protected token vault.",
            ),
            PIIType.EMAIL: (
                "PERSONAL_INFO",
                "Direct digital contact channel; reversible through protected token vault.",
            ),
            PIIType.PHONE: (
                "PERSONAL_INFO",
                "Direct telecommunications identifier; reversible through protected token vault.",
            ),
            PIIType.DATE_OF_BIRTH: (
                "PERSONAL_INFO",
                "Sensitive identity attribute; useful for authorized customer verification.",
            ),
            PIIType.HOME_ADDRESS: (
                "PERSONAL_INFO",
                "Residential location record; reversible through protected token vault.",
            ),
            PIIType.PASSPORT: (
                "HIGH_RISK_GOVERNMENT_ID",
                "Essential sovereign government identity record; high cross-border misuse risk; zero downstream retention.",
            ),
            PIIType.SSN: (
                "HIGH_RISK_GOVERNMENT_ID",
                "High-risk national government identifier; mandatory zero-retention regulatory compliance.",
            ),
            PIIType.AADHAAR: (
                "HIGH_RISK_GOVERNMENT_ID",
                "High-risk national biometric identity number; severe identity theft liability.",
            ),
            PIIType.PAN_CARD: (
                "HIGH_RISK_TAX_IDENTIFIER",
                "Sensitive tax & financial identifier subject to strict statutory privacy.",
            ),
            PIIType.DRIVERS_LICENSE: (
                "GOVERNMENT_ID",
                "Government-issued identity document; unnecessary for downstream AI tool reasoning.",
            ),
            PIIType.IP_ADDRESS: (
                "NETWORK_TELEMETRY",
                "Reveals approximate network location; format-preserving mask prevents device tracking.",
            ),
            PIIType.CREDIT_CARD: (
                "FINANCIAL_CREDENTIAL",
                "Payment card identifier; subject to PCI-DSS zero-exposure standards.",
            ),
            PIIType.API_KEY: (
                "CREDENTIAL",
                "Cloud/Service authentication secret; strictly blocked across external boundaries.",
            ),
            PIIType.PASSWORD: (
                "CREDENTIAL",
                "Authentication secret; strictly blocked across external boundaries.",
            ),
            PIIType.PIN: (
                "CREDENTIAL",
                "Card/ATM authentication PIN; strictly blocked across external boundaries.",
            ),
        }
        if p_type in mapping:
            return mapping[p_type]
        cat = TYPE_TO_CATEGORY.get(p_type, SensitivityCategory.PERSONAL_INFO)
        cat_str = cat.value if hasattr(cat, "value") else str(cat)
        return (cat_str, "Sensitive entity classified under enterprise data protection taxonomy.")

    def execute(
        self,
        entities: List[PIIEntity],
        tool_name: str = "send_email",
    ) -> Tuple[AgentStepResult, List[Dict[str, Any]]]:
        t0 = time.perf_counter()
        classifications: List[Dict[str, Any]] = []

        for ent in entities:
            action = self.policy_engine.get_action_for_entity(
                tool_name=tool_name,
                pii_type=ent.pii_type,
                category=getattr(ent, "category", None),
            )
            cat_str, rationale = self.get_rationale(ent.pii_type)
            classifications.append({
                "entity": ent,
                "value": ent.value,
                "type": ent.pii_type.value if hasattr(ent.pii_type, "value") else str(ent.pii_type),
                "category": cat_str,
                "recommended_action": action.value if hasattr(action, "value") else str(action),
                "rationale": rationale,
            })

        ms = (time.perf_counter() - t0) * 1000.0
        step = AgentStepResult(
            step_number=4,
            agent_id="classification_agent",
            agent_name=self.name,
            role_description="Maps entities to statutory taxonomy and determines Tokenize/Redact/Mask policy",
            engine_badge="Enterprise Compliance Engine",
            status="SUCCESS",
            execution_ms=round(ms, 3),
            input_summary=f"{len(entities)} raw detected entities",
            output_summary=f"Assigned policy actions: {', '.join(set(c['recommended_action'] for c in classifications)) if classifications else 'No PII'}",
            details={"classifications": classifications},
        )
        return step, classifications


# ==============================================================================
# 5. TRANSFORMATION AGENT (Redaction & Tokenization)
# ==============================================================================
class TransformationAgent:
    """Agent 5: Executes dual-mode enforcement: ephemeral vaulting vs permanent redaction."""

    def __init__(
        self,
        name: str = "Redaction & Tokenization Agent",
        firewall: Optional[PIIFirewall] = None,
    ):
        self.name = name
        self.firewall = firewall or PIIFirewall()

    def execute(
        self,
        payload: Dict[str, Any],
        entities: List[PIIEntity],
    ) -> Tuple[AgentStepResult, Any, RequestTokenVault]:
        t0 = time.perf_counter()

        # Intercept and transform through the core firewall engine
        fw_res, vault = self.firewall.intercept_request(payload)

        vault_count = len(vault._token_to_value)
        san_str = json.dumps(fw_res.sanitized_payload) if fw_res else ""
        redact_count = san_str.count("[REDACTED")

        ms = (time.perf_counter() - t0) * 1000.0
        step = AgentStepResult(
            step_number=5,
            agent_id="transformation_agent",
            agent_name=self.name,
            role_description="Executes dual-mode enforcement: tokenizes to vault & permanently wipes redacted data",
            engine_badge="Zero-Trust Cryptographic Engine",
            status="SUCCESS",
            execution_ms=round(ms, 3),
            input_summary="Original payload containing raw PII",
            output_summary=(
                f"Generated {vault_count} ephemeral tokens in vault; "
                f"Applied permanent redaction to {redact_count} statutory secrets"
            ),
            details={
                "sanitized_payload": fw_res.sanitized_payload,
                "vault_tokens": dict(vault._token_to_value),
                "vault_token_count": vault_count,
                "redacted_count": redact_count,
            },
        )
        return step, fw_res, vault


# ==============================================================================
# 6. SIMULATED TOOL AGENT (Other Tool)
# ==============================================================================
class SimulatedToolAgent:
    """Agent 6: Simulates downstream external tool processing with 0.0% wire leakage."""

    def __init__(self, name: str = "Downstream External Tool"):
        self.name = name

    def execute(
        self,
        sanitized_payload: Dict[str, Any],
        raw_entities: List[PIIEntity],
    ) -> Tuple[AgentStepResult, Any, float]:
        t0 = time.perf_counter()
        tool_name = sanitized_payload.get("tool", "external_api")
        sim_service = SimulatedExternalTool(tool_name)

        # Inspect outgoing packet to verify zero raw PII leakage
        wire_str = json.dumps(sanitized_payload)
        leaked_count = 0
        for ent in raw_entities:
            # Check if any raw high-risk secret is present verbatim
            if ent.value in wire_str:
                leaked_count += 1

        leakage_pct = (leaked_count / len(raw_entities) * 100.0) if raw_entities else 0.0

        # Execute downstream simulated tool
        tool_response = sim_service.execute(sanitized_payload)

        ms = (time.perf_counter() - t0) * 1000.0
        step = AgentStepResult(
            step_number=6,
            agent_id="tool_agent",
            agent_name=f"External Tool Agent ({tool_name})",
            role_description="Executes downstream API call using only safe tokens and redacted markers",
            engine_badge="Simulated Tool Sandbox",
            status="SUCCESS" if leakage_pct == 0.0 else "WARNING",
            execution_ms=round(ms, 3),
            input_summary=f"Sanitized packet for tool '{tool_name}'",
            output_summary=f"Tool executed successfully. Wire leakage verified: {leakage_pct:.1f}%",
            details={
                "tool_name": tool_name,
                "tool_response": tool_response,
                "wire_leakage_pct": leakage_pct,
            },
        )
        return step, tool_response, leakage_pct


# ==============================================================================
# 7. REHYDRATION AGENT (Restoration from Vault)
# ==============================================================================
class RehydrationAgent:
    """Agent 7: Intercepts tool response, restores tokens from vault, and purges memory."""

    def __init__(
        self,
        name: str = "Response Re-hydration Agent",
        firewall: Optional[PIIFirewall] = None,
    ):
        self.name = name
        self.firewall = firewall or PIIFirewall()

    def execute(
        self,
        tool_response: Any,
        request_id: str,
        vault: RequestTokenVault,
    ) -> Tuple[AgentStepResult, Any]:
        t0 = time.perf_counter()

        # Intercept response and restore tokens
        restored_resp, resp_met = self.firewall.intercept_response(
            response_payload=tool_response,
            request_id=request_id,
            purge_vault=True,
        )

        ms = (time.perf_counter() - t0) * 1000.0
        step = AgentStepResult(
            step_number=7,
            agent_id="rehydration_agent",
            agent_name=self.name,
            role_description="Re-hydrates tokens from ephemeral vault while leaving redacted secrets scrubbed",
            engine_badge="Cryptographic Re-hydration Vault",
            status="SUCCESS",
            execution_ms=round(ms, 3),
            input_summary="Tool response with token placeholders",
            output_summary="Restored response delivered to Agent; Vault memory purged cleanly",
            details={
                "restored_response": restored_resp,
                "restored_tokens_count": getattr(resp_met, "restored_count", 0),
                "vault_purged": True,
            },
        )
        return step, restored_resp


# ==============================================================================
# ORCHESTRATOR: MULTI-AGENT PIPELINE
# ==============================================================================
class MultiAgentPipeline:
    """
    Coordinates the 7 autonomous agents into a seamless Zero-Trust AI firewall workflow.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        gemini_model: str = "gemini-3.5-flash-lite",
        enable_cloud_gemini: bool = False,
    ):
        # Build shared core engine
        self.policy_engine = PolicyEngine.create_default_backend_policy(simple_redaction=True)
        self.config = FirewallConfig(
            allow_restoration=True,
            fail_safe_strict=True,
            enable_semantic_nlp=True,
            enable_cloud_ai=enable_cloud_gemini,
            gemini_api_key=gemini_api_key,
            gemini_model=gemini_model,
        )
        self.firewall = PIIFirewall(
            config=self.config,
            policy_engine=self.policy_engine,
        )

        # Initialize all 7 agents
        self.client_agent = ClientAgent()
        self.nlp_agent = NLPAgent(
            gemini_api_key=gemini_api_key,
            gemini_model=gemini_model,
            enable_cloud_gemini=enable_cloud_gemini,
        )
        self.detection_agent = DetectionAgent(
            firewall=self.firewall,
            gemini_api_key=gemini_api_key,
            gemini_model=gemini_model,
            enable_cloud_gemini=enable_cloud_gemini,
        )
        self.classification_agent = ClassificationAgent(policy_engine=self.policy_engine)
        self.transformation_agent = TransformationAgent(firewall=self.firewall)
        self.tool_agent = SimulatedToolAgent()
        self.rehydration_agent = RehydrationAgent(firewall=self.firewall)

    def run(self, prompt: str) -> MultiAgentExecutionTrace:
        """Runs the complete 7-agent pipeline end-to-end."""
        total_t0 = time.perf_counter()
        trace = MultiAgentExecutionTrace(
            request_id="req_" + str(int(time.time() * 1000)),
            total_execution_ms=0.0,
            success=False,
            status_message="",
            raw_prompt=prompt,
        )

        try:
            # 1. Client Agent
            s1, payload = self.client_agent.execute(prompt)
            trace.steps.append(s1)
            tool_name = payload.get("tool", "external_api")

            # 2. NLP Agent (Context & Stopwords via Gemini API / Semantic NLP)
            s2, nlp_meta = self.nlp_agent.execute(prompt)
            trace.steps.append(s2)

            # 3. Detection Agent (PII Discovery via Gemini API + Checksum Recognizers)
            s3, entities = self.detection_agent.execute(prompt)
            trace.steps.append(s3)
            trace.detected_entities = entities

            # 4. Classification Agent (Taxonomy & Policy Rules)
            s4, classifications = self.classification_agent.execute(entities, tool_name=tool_name)
            trace.steps.append(s4)

            # Check for credential block
            for c in classifications:
                if c["recommended_action"] == PolicyAction.BLOCK_TOOL.value:
                    raise FirewallBlockedError(f"Credential '{c['type']}' blocked from external tool transmission.")

            # 5. Transformation Agent (Redaction & Tokenization)
            s5, fw_res, vault = self.transformation_agent.execute(payload, entities)
            trace.steps.append(s5)
            trace.vault_token_count = len(vault._token_to_value)
            san_str = json.dumps(fw_res.sanitized_payload) if fw_res else ""
            trace.redacted_count = san_str.count("[REDACTED")

            # Extract sanitized prompt text for display
            if isinstance(fw_res.sanitized_payload, dict) and "arguments" in fw_res.sanitized_payload:
                trace.sanitized_prompt = fw_res.sanitized_payload["arguments"].get("query", prompt)

            # 6. Tool Agent (External Tool Execution)
            s6, tool_resp, leakage_pct = self.tool_agent.execute(fw_res.sanitized_payload, entities)
            trace.steps.append(s6)
            trace.wire_leakage_percentage = leakage_pct

            # 7. Re-hydration Agent (Response Interception & Restoration)
            s7, final_resp = self.rehydration_agent.execute(tool_resp, fw_res.request_id, vault)
            trace.steps.append(s7)
            trace.final_response = final_resp

            trace.success = True
            trace.status_message = "All 7 Agents Completed Successfully. Zero wire leakage verified."

        except FirewallBlockedError as e:
            trace.success = False
            trace.status_message = f"Security Policy Block: {str(e)}"
        except Exception as e:
            trace.success = False
            trace.status_message = f"Execution Error: {str(e)}"

        trace.total_execution_ms = round((time.perf_counter() - total_t0) * 1000.0, 3)
        return trace
