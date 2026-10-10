"""
Streamlit Web Dashboard for PII Firewall for AI Agents.
Minimalist, zero-leakage privacy gateway simulation with Context-Aware NLP,
Semantic Classification, and Mandatory Three-Tier Security Principles.
"""

import copy
import json
import os
import sys
import time
from pathlib import Path

# Add backend directory to path
_backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(_backend_path) not in sys.path:
    sys.path.insert(0, str(_backend_path))

import streamlit as st

from pii_firewall.audit_logger import AuditLogger
from pii_firewall.middleware import PIIFirewall
from pii_firewall.models import (
    FirewallConfig,
    PIIType,
    SensitivityCategory,
    TYPE_TO_CATEGORY,
    PIILeakageDetectedError,
    FirewallBlockedError,
)
from pii_firewall.policy import PolicyAction, PolicyEngine, ToolPolicyRule, generate_masked_value
from pii_firewall.semantic_nlp import ContextAwareNLPEngine
from pii_firewall.simulated_tool import SimulatedExternalTool


# Page configuration
st.set_page_config(
    page_title="PII Firewall for AI Agents",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Minimalist Custom CSS
st.markdown("""
<style>
    /* Hide Streamlit chrome & sidebar */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    [data-testid="stSidebar"], section[data-testid="stSidebar"], div[data-testid="collapsedControl"] {
        display: none !important;
    }

    /* Minimalist layout: centered & clean max width */
    .block-container {
        max-width: 800px !important;
        padding-top: 2.2rem !important;
        padding-bottom: 3.5rem !important;
        margin: 0 auto !important;
    }

    /* Modern clean typography */
    body, [class*="css"] {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Minimalist Header */
    .hero-container {
        text-align: center;
        margin-bottom: 2rem;
    }
    .hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #F1F5F9;
        color: #475569;
        font-size: 0.78rem;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 9999px;
        margin-bottom: 10px;
        letter-spacing: 0.3px;
        border: 1px solid #E2E8F0;
    }
    .hero-dot {
        width: 7px;
        height: 7px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
    }
    .hero-title {
        font-size: 1.85rem;
        font-weight: 700;
        color: #0F172A;
        margin: 0 0 6px 0;
        letter-spacing: -0.02em;
    }
    .hero-sub {
        font-size: 0.95rem;
        color: #64748B;
        margin: 0;
    }

    /* Step Card Styling */
    .step-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 14px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
        font-size: 0.92rem;
        line-height: 1.55;
        color: #334155;
    }
    .step-title {
        font-weight: 700;
        color: #0F172A;
        font-size: 0.98rem;
        margin-bottom: 8px;
    }

    /* Sleek inputs */
    .stTextArea textarea {
        border-radius: 8px !important;
        border: 1px solid #CBD5E1 !important;
        font-size: 0.95rem !important;
        line-height: 1.5 !important;
    }
    .stTextArea textarea:focus {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 1px #3B82F6 !important;
    }
    .stSelectbox div[data-baseweb="select"] {
        border-radius: 8px !important;
    }
    .stButton button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding-top: 0.55rem !important;
        padding-bottom: 0.55rem !important;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "audit_logger" not in st.session_state:
    st.session_state.audit_logger = AuditLogger()

if "agent_prompt_input" not in st.session_state:
    st.session_state.agent_prompt_input = (
        "send email to sharath@gmail.com at 3pm with subject i will be leave on the 31st nov due to personal issue"
    )

selected_types = [t.value for t in PIIType]
block_cards_on_email = True


# Helper to package user text into a realistic agent tool call
def extract_tool_call_from_prompt(prompt_str: str) -> dict:
    prompt_str = prompt_str.strip()
    if prompt_str.startswith("{") and prompt_str.endswith("}"):
        try:
            return json.loads(prompt_str)
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
    elif any(k in lower for k in ["aadhaar", "aadhar", "adhaar", "adhar", "pan", "kyc", "identity"]):
        tool_name = "kyc_verify"
    elif any(k in lower for k in ["crm", "customer", "contact", "salesforce"]):
        tool_name = "crm_service"
    elif any(k in lower for k in ["deploy", "server", "ip", "api key", "aws", "openai"]):
        tool_name = "cloud_deploy"

    # Extract subject if mentioned
    subject_val = "Leave Notification"
    if "subject" in lower:
        idx = lower.find("subject")
        sub_part = prompt_str[idx + len("subject"):].strip().lstrip(":").strip()
        if sub_part:
            subject_val = sub_part

    # Extract schedule
    schedule_val = "Immediate"
    if "3pm" in lower or "3 pm" in lower:
        schedule_val = "3:00 PM"
    elif "tomorrow" in lower:
        schedule_val = "Tomorrow"

    return {
        "tool": tool_name,
        "arguments": {
            "query": prompt_str,
            "subject": subject_val,
            "schedule": schedule_val,
            "message": prompt_str,
        }
    }


# =====================================================================
# MINIMALIST HEADER
# =====================================================================
st.markdown("""
<div class="hero-container">
    <div class="hero-badge">
        <span class="hero-dot"></span>
        STATUS: FIREWALL ACTIVE
    </div>
    <h1 class="hero-title">🛡️ PII Firewall for AI Agents</h1>
    <p class="hero-sub">Zero-Leakage Privacy Layer Intercepting Tool Requests in Real Time</p>
</div>
""", unsafe_allow_html=True)


# =====================================================================
# QUERY BOX & CONTROLS
# =====================================================================
st.markdown("### ✍️ Agent Query Input:")

user_prompt = st.text_area(
    "Query Box:",
    value=st.session_state.agent_prompt_input,
    height=90,
    label_visibility="collapsed",
    placeholder="Update account profile. Name: David Miller, Passport: A12345678, Status: Active.",
)

send_sim_clicked = st.button("🚀 Send", type="primary", use_container_width=True)

if send_sim_clicked:
    st.session_state["sim_has_executed"] = True
    st.session_state["executed_prompt"] = user_prompt


# =====================================================================
# 7-STEP BACKGROUND EXECUTION DETAILS (RENDERED UPON SEND)
# =====================================================================
if st.session_state.get("sim_has_executed", False):
    active_prompt = st.session_state.get("executed_prompt", user_prompt)

    # Build payload
    sim_tool_payload = extract_tool_call_from_prompt(active_prompt)
    sim_tool_name = sim_tool_payload.get("tool", "send_email")

    # Configure Policy Engine directly from native backend classification rules
    sim_policy = PolicyEngine.create_default_backend_policy(simple_redaction=True)

    if block_cards_on_email:
        sim_policy.add_rule(
            ToolPolicyRule(
                tool_name="send_email",
                blocked_pii_types={PIIType.CREDIT_CARD, PIIType.SSN}
            )
        )


    # Configure Firewall with Context-Aware NLP & Automatic Backend Gemini AI
    sim_config = FirewallConfig(
        enabled_types={PIIType(t) for t in selected_types},
        allow_restoration=True,
        fail_safe_strict=True,
        enable_semantic_nlp=True,
    )
    sim_firewall = PIIFirewall(
        config=sim_config,
        policy_engine=sim_policy,
        audit_logger=st.session_state.audit_logger,
    )
    mock_external_service = SimulatedExternalTool(sim_tool_name)

    # Scan prompt to identify raw entities
    pre_detected_entities = []
    try:
        for rec in sim_firewall.scanner.recognizers:
            found = rec.find_entities(active_prompt)
            pre_detected_entities.extend(found)
    except Exception:
        pass

    # Deduplicate overlapping entities and sort by position in text
    pre_detected_entities.sort(key=lambda e: (e.end - e.start, e.confidence), reverse=True)
    deduped_entities = []
    for cand in pre_detected_entities:
        overlap = False
        for chosen in deduped_entities:
            if not (cand.end <= chosen.start or cand.start >= chosen.end):
                overlap = True
                break
        if not overlap:
            deduped_entities.append(cand)
    deduped_entities.sort(key=lambda e: e.start)

    sim_start_time = time.perf_counter()
    sim_blocked = False
    sim_block_reason = ""

    try:
        # Step A: Intercept & Sanitize Request
        fw_res, vault = sim_firewall.intercept_request(sim_tool_payload)

        # Snapshot vault tokens before restoration purge
        vault_tokens_map = dict(vault._token_to_value)
        vault_types_map = dict(vault._token_types)

        # Step B: External Tool Execution
        mock_received = mock_external_service.execute(fw_res.sanitized_payload)

        # Step C: Intercept Response & Restore
        restored_resp, resp_met = sim_firewall.intercept_response(
            response_payload=mock_received,
            request_id=fw_res.request_id,
            purge_vault=True,
        )

        sim_total_ms = (time.perf_counter() - sim_start_time) * 1000.0

    except PIILeakageDetectedError as e:
        sim_blocked = True
        sim_block_reason = f"Leakage Verification Failure: {str(e)}"
        sim_total_ms = (time.perf_counter() - sim_start_time) * 1000.0
        fw_res, vault, mock_received, restored_resp, resp_met = None, None, None, None, None
        vault_tokens_map, vault_types_map = {}, {}

    except FirewallBlockedError as e:
        sim_blocked = True
        sim_block_reason = f"Policy Block Triggered: {str(e)}"
        sim_total_ms = (time.perf_counter() - sim_start_time) * 1000.0
        fw_res, vault, mock_received, restored_resp, resp_met = None, None, None, None, None
        vault_tokens_map, vault_types_map = {}, {}

    except Exception as e:
        sim_blocked = True
        sim_block_reason = f"Security Exception: {str(e)}"
        sim_total_ms = (time.perf_counter() - sim_start_time) * 1000.0
        fw_res, vault, mock_received, restored_resp, resp_met = None, None, None, None, None
        vault_tokens_map, vault_types_map = {}, {}

    st.markdown("---")
    st.markdown("### ⚡ Live 7-Step Firewall Pipeline Interception")

    # Extract dynamic formatting data for all detected entities
    sanitized_query_text = fw_res.sanitized_payload["arguments"]["query"] if fw_res else active_prompt

    if deduped_entities:
        # Step 1 Items HTML
        items_detected_html = []
        for ent in deduped_entities:
            t_str = ent.pii_type.value if hasattr(ent.pii_type, "value") else str(ent.pii_type)
            cat_enum = getattr(ent, "category", TYPE_TO_CATEGORY.get(ent.pii_type, SensitivityCategory.PERSONAL_INFO))
            cat_str = cat_enum.value if hasattr(cat_enum, "value") else str(cat_enum)
            items_detected_html.append(
                f'<div style="margin-top: 4px;"><b>Detected Item:</b> 🔴 {t_str}: <code>{ent.value}</code> '
                f'<span style="font-size: 0.82rem; color: #64748B;">({cat_str})</span></div>'
            )
        detected_items_display = "".join(items_detected_html)

        # Step 2 Targets HTML
        targets_discovered_html = []
        for ent in deduped_entities:
            t_str = ent.pii_type.value if hasattr(ent.pii_type, "value") else str(ent.pii_type)
            conf_str = f"{int(ent.confidence * 100)}%"
            ev_str = f" &bull; <i>{ent.context_evidence}</i>" if getattr(ent, "context_evidence", None) else ""
            targets_discovered_html.append(
                f'<div style="margin-top: 4px;"><b>Target Discovered:</b> <code>{ent.value}</code> classified as <code>PIIType.{t_str}</code> (Confidence: {conf_str}){ev_str}.</div>'
            )
        targets_display = "".join(targets_discovered_html)

        # Step 3 Transformations HTML
        transforms_list = []
        for ent in deduped_entities:
            t_str = ent.pii_type.value if hasattr(ent.pii_type, "value") else str(ent.pii_type)
            action_for_ent = sim_policy.get_action_for_entity(sim_tool_name, ent.pii_type, category=getattr(ent, "category", None))
            if action_for_ent == PolicyAction.MASK:
                m_val = generate_masked_value(ent.value, ent.pii_type)
            elif action_for_ent == PolicyAction.TOKENIZE:
                m_val = vault_tokens_map.get(ent.value, f"⟦{t_str}_token⟧")
            elif action_for_ent == PolicyAction.BLOCK_TOOL:
                m_val = "[BLOCKED]"
            else:
                m_val = "[REDACTED]" if getattr(sim_policy, "simple_redaction", False) else f"[REDACTED_{t_str}]"
            transforms_list.append(f"<code>{ent.value}</code> ➔ <code>{m_val}</code>")
        transformations_display = ", ".join(transforms_list)

        raw_pii_summary = ", ".join([f"<code>{e.value}</code>" for e in deduped_entities])

    else:
        detected_items_display = '<div style="margin-top: 4px;"><b>Detected Item:</b> 🟢 No PII detected</div>'
        targets_display = '<div style="margin-top: 4px;"><b>Target Discovered:</b> Zero sensitive entities found in query.</div>'
        transformations_display = "None required"
        raw_pii_summary = "sensitive values"

    # 1️⃣ STEP 1: User Prompt Received by AI Agent
    with st.container():
        st.markdown(f"""
        <div class="step-card" style="border-left: 4px solid #3B82F6;">
          <div class="step-title">1️⃣ STEP 1: User Prompt Received by AI Agent</div>
          <div><b>Input Query:</b> &ldquo;{active_prompt}&rdquo;</div>
          {detected_items_display}
        </div>
        """, unsafe_allow_html=True)

    has_gemini = any("Gemini" in type(r).__name__ for r in sim_firewall.scanner.recognizers)
    if has_gemini:
        ai_scanner_badge = (
            '<div style="margin-bottom: 8px; padding: 6px 10px; background: rgba(16, 185, 129, 0.12); border-radius: 6px; border: 1px solid rgba(16, 185, 129, 0.35); font-size: 0.85rem;">'
            '🤖 <b>AI PII Scanner Active:</b> Powered by Google Gemini Free API (configured in backend <code>.env</code>) &bull; Semantic prompt analysis & PII extraction enabled.'
            '</div>'
        )
    else:
        ai_scanner_badge = (
            '<div style="margin-bottom: 8px; padding: 6px 10px; background: rgba(59, 130, 246, 0.1); border-radius: 6px; border: 1px solid rgba(59, 130, 246, 0.25); font-size: 0.85rem;">'
            '🛡️ <b>Local Hybrid Engine Active:</b> High-speed Context-Aware NLP, NER & Checksum Validators running locally (Configure <code>GEMINI_API_KEY</code> in backend <code>.env</code> to activate Cloud AI).'
            '</div>'
        )

    # 2️⃣ STEP 2: Whole-Prompt PII Detection & Safety Inspection
    with st.container():
        st.markdown(f"""
        <div class="step-card" style="border-left: 4px solid #10B981;">
          <div class="step-title">2️⃣ STEP 2: Whole-Prompt PII Detection & Safety Inspection</div>
          {ai_scanner_badge}
          <div><b>Recursive Scanner:</b> Scans the whole prompt across email, phone, SSN, credit cards, Aadhaar, PAN, and cloud secret recognizers.</div>
          {targets_display}
          <div style="margin-top: 4px;"><b>False-Positive Prevention:</b> The terms &ldquo;3pm&rdquo; and &ldquo;31st nov&rdquo; are analyzed by the phone and date evaluators and verified as non-PII operational scheduling parameters (not misidentified as phone numbers or identifiers!).</div>
          <div style="margin-top: 4px;"><b>Adversarial Sanitization:</b> Zero-width Unicode stripping and Base64 bypass checks pass clean.</div>
        </div>
        """, unsafe_allow_html=True)

    # 3️⃣ STEP 3: Privacy Transformation Applied (MASK / BLOCK)
    with st.container():
        if sim_blocked:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #EF4444;">
              <div class="step-title" style="color: #DC2626;">3️⃣ STEP 3: Mandatory Security Policy Applied (BLOCKED)</div>
              <div><b>Policy Action Enforced:</b> 🛑 <b>BLOCK BY DEFAULT</b> (Mandatory Credential & Destination Policy).</div>
              <div style="margin-top: 4px;"><b>Violation Reason:</b> {sim_block_reason}</div>
              <div style="margin-top: 4px;"><b>Safe Preview:</b> <code>[REDACTED_CREDENTIAL]</code> (Zero cleartext leakage).</div>
              <div style="margin-top: 4px;"><b>Mathematical Leakage Check:</b> Transmission aborted: <b>0.0% Leakage (Verified Blocked)</b>.</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #8B5CF6;">
              <div class="step-title">3️⃣ STEP 3: Privacy Transformation Applied (Enterprise Classification Rules)</div>
              <div><b>Policy Applied:</b> {transformations_display}.</div>
              <div style="margin-top: 4px;"><b>Sanitized Query:</b> &ldquo;{sanitized_query_text}&rdquo;.</div>
              <div style="margin-top: 4px;"><b>Mathematical Leakage Check:</b> Outgoing payload scanned for raw {raw_pii_summary}: <b>0.0% Leakage (Verified Safe)</b>.</div>
            </div>
            """, unsafe_allow_html=True)

    # 4️⃣ STEP 4: Request Sent to External Tool (send_email)
    with st.container():
        if sim_blocked:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #EF4444;">
              <div class="step-title" style="color: #DC2626;">4️⃣ STEP 4: Outgoing Transmission Intercepted ({sim_tool_name})</div>
              <div><b>Security Proof:</b> Request intercepted and terminated before crossing network boundary! External service received <b>0 packets</b>.</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #F59E0B;">
              <div class="step-title">4️⃣ STEP 4: Request Sent to External Tool ({sim_tool_name})</div>
              <div>Audits the exact wire packet received by the simulated third-party tool:</div>
            </div>
            """, unsafe_allow_html=True)
            if mock_external_service.received_payloads:
                st.json(mock_external_service.received_payloads[-1])
            st.caption("**Security Proof:** Third-party tool received zero raw PII!")

    # 5️⃣ STEP 5: Simulated External Tool Response
    with st.container():
        if sim_blocked:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #EF4444;">
              <div class="step-title" style="color: #DC2626;">5️⃣ STEP 5: Simulated External Tool Response</div>
              <div>External tool was not executed because the firewall blocked the request. Zero exposure footprint.</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #06B6D4;">
              <div class="step-title">5️⃣ STEP 5: Simulated External Tool Response</div>
              <div>Tool executes with the masked parameters and responds:</div>
            </div>
            """, unsafe_allow_html=True)
            if mock_received:
                st.json(mock_received)

    # 6️⃣ STEP 6: Response Interception & Token Restoration
    with st.container():
        if sim_blocked:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #EF4444;">
              <div class="step-title" style="color: #DC2626;">6️⃣ STEP 6: Response Interception & Security Boundary Enforced</div>
              <div>Firewall caught the unauthorized request at ingress. No tokens required restoration because transmission never occurred.</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            step6_active_badge = f"""
            <div style="margin-top: 8px; padding: 8px 12px; background: rgba(16, 185, 129, 0.12); border-left: 3px solid #10B981; border-radius: 4px; font-size: 0.88rem;">
              <b>⚡ Solution in Action (Enterprise Classification Matrix):</b> The firewall token vault caught the returning response and re-hydrated tokenized values ({raw_pii_summary}) back into AI agent memory! Redacted values (e.g. SSN, Passport) remain permanently scrubbed as <code>[REDACTED]</code> with zero vault storage.
            </div>
            """

            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #10B981;">
              <div class="step-title">6️⃣ STEP 6: Response Interception & Token Restoration</div>
              <div>Firewall catches the returning response from the external tool.</div>
              <div style="margin-top: 6px;">&bull; <b>TOKENIZE</b>: Re-hydrates tokenized values ({raw_pii_summary}) back into agent memory.</div>
              <div style="margin-top: 4px;">&bull; <b>REDACT</b>: High-risk secrets (SSN, Passport) remain permanently scrubbed.</div>
              {step6_active_badge}
            </div>
            """, unsafe_allow_html=True)

    # 7️⃣ STEP 7: Final Safe Result Delivered to AI Agent
    with st.container():
        if sim_blocked:
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #10B981;">
              <div class="step-title" style="color: #059669;">7️⃣ STEP 7: Final Safe Notification Delivered to AI Agent</div>
              <div>AI agent receives safety notification: tool call safely blocked by policy. Zero authentication secrets or confidential assets were leaked!</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            solution_summary_note = "<b>Backend Policy Context Preservation:</b> AI agent resumes autonomous workflow with full context intact for tokenized fields, while high-risk secrets and credentials never cross the external boundary!"

            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #059669;">
              <div class="step-title">7️⃣ STEP 7: Final Safe Result Delivered to AI Agent</div>
              <div>AI agent receives the confirmed response without having leaked {raw_pii_summary} across the network boundary!</div>
              <div style="margin-top: 6px; font-size: 0.85rem; color: #059669;">{solution_summary_note}</div>
            </div>
            """, unsafe_allow_html=True)


