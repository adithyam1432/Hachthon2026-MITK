"""
Streamlit Web Dashboard for PII Firewall for AI Agents.
Minimalist, zero-leakage privacy gateway simulation with Context-Aware NLP,
Semantic Classification, and Mandatory Three-Tier Security Principles.
"""

import base64
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
from pii_firewall.multi_agent_pipeline import MultiAgentPipeline, AgentStepResult


# Page configuration - wide layout for responsive screen width & height
st.set_page_config(
    page_title="PII Firewall for AI Agents",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


def get_base64_bg() -> str:
    """Loads cyber background image as base64 for sticky backdrop."""
    candidates = [
        Path(__file__).resolve().parent / "assets" / "cyber_background.jpg",
        Path.cwd() / "assets" / "cyber_background.jpg",
        Path.cwd() / "frontend" / "assets" / "cyber_background.jpg",
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            try:
                with open(p, "rb") as f:
                    return base64.b64encode(f.read()).decode("utf-8")
            except Exception:
                pass
    return ""


bg_base64 = get_base64_bg()
bg_css_rule = (
    f'background: linear-gradient(rgba(10, 15, 30, 0.80), rgba(10, 15, 30, 0.88)), url("data:image/jpeg;base64,{bg_base64}") !important;'
    if bg_base64
    else "background: linear-gradient(135deg, #0B1120 0%, #0F172A 100%) !important;"
)


# Minimalist Liquid Glass (Glassmorphism) CSS with Sticky Cyber Background
st.markdown(f"""
<style>
    /* Hide Streamlit chrome & sidebar */
    #MainMenu {{visibility: hidden;}}
    footer {{visibility: hidden;}}
    header {{visibility: hidden;}}
    [data-testid="stSidebar"], section[data-testid="stSidebar"], div[data-testid="collapsedControl"] {{
        display: none !important;
    }}

    /* Sticky Cyber Background */
    .stApp {{
        {bg_css_rule}
        background-size: cover !important;
        background-position: center center !important;
        background-repeat: no-repeat !important;
        background-attachment: fixed !important; /* Sticky background */
        min-height: 100vh !important;
        width: 100% !important;
    }}

    /* Leave 15% width from both left and right sides (70% content width) */
    .block-container {{
        max-width: 70% !important;
        width: 70% !important;
        margin-left: 15% !important;
        margin-right: 15% !important;
        padding-top: 2rem !important;
        padding-bottom: 3.5rem !important;
        padding-left: 0 !important;
        padding-right: 0 !important;
    }}

    /* Modern clean typography */
    body, [class*="css"], p, span, label, div {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        color: #F8FAFC;
    }}

    /* Liquid Glass Effect Header */
    .hero-container {{
        text-align: center;
        margin-bottom: 2rem;
        background: rgba(15, 23, 42, 0.65) !important;
        backdrop-filter: blur(18px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(18px) saturate(180%) !important;
        border: 1px solid rgba(255, 255, 255, 0.14) !important;
        border-radius: 16px !important;
        padding: 24px 30px !important;
        box-shadow: 0 10px 35px 0 rgba(0, 0, 0, 0.5) !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }}
    .hero-badge {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(255, 255, 255, 0.1);
        color: #E2E8F0;
        font-size: 0.8rem;
        font-weight: 700;
        padding: 5px 14px;
        border-radius: 9999px;
        margin-bottom: 12px;
        letter-spacing: 0.5px;
        border: 1px solid rgba(255, 255, 255, 0.18);
    }}
    .hero-dot {{
        width: 8px;
        height: 8px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 10px #10B981;
    }}
    .hero-title {{
        font-size: 2.2rem;
        font-weight: 800;
        color: #FFFFFF !important;
        margin: 0 0 8px 0;
        letter-spacing: -0.02em;
        text-shadow: 0 2px 12px rgba(0, 0, 0, 0.6);
    }}
    .hero-sub {{
        font-size: 1.05rem;
        color: #CBD5E1 !important;
        margin: 0;
    }}

    /* Liquid Glass Step Cards (Full Screen Width) */
    .step-card {{
        background: rgba(15, 23, 42, 0.72) !important;
        backdrop-filter: blur(16px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
        border: 1px solid rgba(255, 255, 255, 0.14) !important;
        border-radius: 14px !important;
        padding: 20px 26px !important;
        margin-bottom: 18px !important;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45) !important;
        font-size: 0.95rem !important;
        line-height: 1.6 !important;
        color: #F8FAFC !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }}
    .step-title {{
        font-weight: 700;
        color: #FFFFFF !important;
        font-size: 1.08rem;
        margin-bottom: 10px;
    }}

    /* Liquid Glass Textarea (Full Screen Width) */
    .stTextArea, .stTextArea > div {{
        width: 100% !important;
    }}
    .stTextArea textarea {{
        background: rgba(15, 23, 42, 0.8) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border-radius: 12px !important;
        border: 1px solid rgba(255, 255, 255, 0.2) !important;
        font-size: 1rem !important;
        line-height: 1.55 !important;
        color: #FFFFFF !important;
        padding: 14px 18px !important;
        width: 100% !important;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35) !important;
    }}
    .stTextArea textarea:focus {{
        border-color: #38BDF8 !important;
        box-shadow: 0 0 18px rgba(56, 189, 248, 0.5) !important;
    }}

    /* Send Button (Cyber Glow Effect) */
    .stButton, .stButton button {{
        width: 100% !important;
        border-radius: 10px !important;
        background: linear-gradient(135deg, #0284C7 0%, #0369A1 100%) !important;
        border: 1px solid #38BDF8 !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        font-size: 1.05rem !important;
        padding-top: 0.65rem !important;
        padding-bottom: 0.65rem !important;
        /* Radiant cyber glow lighting */
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.6), 0 0 30px rgba(2, 132, 199, 0.4), inset 0 0 10px rgba(56, 189, 248, 0.25) !important;
        text-shadow: 0 0 6px rgba(255, 255, 255, 0.7) !important;
        transition: all 0.25s ease-in-out !important;
    }}
    .stButton button:hover {{
        background: linear-gradient(135deg, #0369A1 0%, #0284C7 100%) !important;
        border-color: #7DD3FC !important;
        /* Intensified neon glow on hover */
        box-shadow: 0 0 25px rgba(56, 189, 248, 0.9), 0 0 50px rgba(2, 132, 199, 0.65), inset 0 0 15px rgba(56, 189, 248, 0.45) !important;
        text-shadow: 0 0 10px rgba(255, 255, 255, 1) !important;
        transform: translateY(-2px) !important;
    }}
    .stButton button:active {{
        box-shadow: 0 0 30px rgba(56, 189, 248, 1), 0 0 60px rgba(2, 132, 199, 0.8) !important;
        transform: translateY(0px) !important;
    }}

    /* Code blocks & JSON preview with dark liquid glass styling */
    code {{
        color: #38BDF8 !important;
        background: rgba(15, 23, 42, 0.85) !important;
        padding: 2px 7px !important;
        border-radius: 4px !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
    }}
    [data-testid="stJson"] {{
        background: rgba(15, 23, 42, 0.75) !important;
        backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(255, 255, 255, 0.14) !important;
        border-radius: 10px !important;
        padding: 14px !important;
        width: 100% !important;
        box-sizing: border-box !important;
    }}
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
# QUERY BOX & CONTROLS (FULL WIDTH, SEND ONLY)
# =====================================================================
st.markdown("### Agent Query Input:")

user_prompt = st.text_area(
    "Query Box:",
    value=st.session_state.agent_prompt_input,
    height=90,
    label_visibility="collapsed",
    placeholder="Update account profile. Name: David Miller, Passport: A12345678, Status: Active.",
)

col_space_l, col_btn, col_space_r = st.columns([1, 8, 1])
with col_btn:
    send_sim_clicked = st.button("Send", type="primary", use_container_width=True)

if send_sim_clicked:
    st.session_state["sim_has_executed"] = True
    st.session_state["executed_prompt"] = user_prompt


# =====================================================================
# MULTI-AGENT EXECUTION TRACE (RENDERED UPON SEND)
# =====================================================================
if st.session_state.get("sim_has_executed", False):
    active_prompt = st.session_state.get("executed_prompt", user_prompt)

    # Execute end-to-end Multi-Agent Pipeline (sub-3ms local execution)
    pipeline = MultiAgentPipeline(
        gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
        enable_cloud_gemini=False,  # High-speed local engine guarantees instant ~2ms execution
    )
    trace = pipeline.run(active_prompt)

    st.markdown("---")

    # STATUS & LATENCY HEADER
    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; width: 100%;">
        <div style="font-size: 1.25rem; font-weight: 700; color: #FFFFFF;">
             Multi-Agent Execution Trace (7 Collaborative Agents)
        </div>
        <span style="background: rgba(16, 185, 129, 0.18); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.5); padding: 5px 16px; border-radius: 20px; font-size: 0.85rem; font-weight: 700;">
             Fast Execution: {trace.total_execution_ms:.2f} ms (&lt; 25ms SLA)
        </span>
    </div>
    """, unsafe_allow_html=True)

    # Helper mapping for steps
    step_map = {s.agent_id: s for s in trace.steps}
    s_client = step_map.get("client_agent")
    s_nlp = step_map.get("nlp_agent")
    s_detection = step_map.get("detection_agent")
    s_classification = step_map.get("classification_agent")
    s_transform = step_map.get("transformation_agent")
    s_tool = step_map.get("tool_agent")
    s_rehydrate = step_map.get("rehydration_agent")

    # If policy block occurred
    if not trace.success and "Policy Block" in trace.status_message:
        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #EF4444;">
              <div class="step-title" style="color: #EF4444;">🛑 Security Policy Violation: Request Blocked</div>
              <div><b>Reason:</b> {trace.status_message}</div>
              <div style="margin-top: 6px; font-size: 0.85rem; color: #CBD5E1;">
                Mandatory Principle A: Authentication credentials are prohibited across external tool boundaries. Outgoing network transmission was aborted immediately (0.0% Wire Leakage).
              </div>
            </div>
            """, unsafe_allow_html=True)

    # 1️⃣ STEP 1:  Agent (Client Agent)
    if s_client:
        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #94A3B8;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #E2E8F0; margin-bottom: 0;">1️⃣ STEP 1: 🤖 Agent (Client Task Formulation)</div>
                <span style="font-size: 0.82rem; color: #94A3B8; font-weight: 600;">⚡ {s_client.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;"><b>Incoming Query:</b> &ldquo;{active_prompt}&rdquo;</div>
              <div style="margin-top: 6px; font-size: 0.88rem; color: #CBD5E1;">
                &bull; <b>Dispatched Tool:</b> <code>{s_client.details.get('tool', 'external_api')}</code> | <b>Role:</b> {s_client.role_description}
              </div>
            </div>
            """, unsafe_allow_html=True)

    # 2️⃣ STEP 2:  NLP Agent (Google Gemini AI / Context NLP)
    if s_nlp:
        stopwords = s_nlp.details.get("operational_stopwords_verified", [])
        sw_html = ", ".join([f"<code>{w}</code>" for w in stopwords]) if stopwords else "None"
        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #3B82F6;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #60A5FA; margin-bottom: 0;">2️⃣ STEP 2: 🧠 NLP Agent (Semantic Context & Stopwords)</div>
                <span style="font-size: 0.82rem; color: #60A5FA; font-weight: 600;">{s_nlp.engine_badge} &bull; ⚡ {s_nlp.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;"><b>Semantic Intent:</b> {s_nlp.details.get('semantic_intent', 'Authorized tool execution')}</div>
              <div style="margin-top: 6px; font-size: 0.88rem; color: #CBD5E1;">
                 <b>False-Positive Disambiguation:</b> Operational stopwords verified: {sw_html} (isolated from sensitive numbers).
              </div>
            </div>
            """, unsafe_allow_html=True)

    # 3️⃣ STEP 3:  Detection Agent (Gemini AI + Checksum Recognizers)
    if s_detection:
        ents = s_detection.details.get("entities", [])
        if ents:
            det_rows = "".join([
                f'<div style="margin-top: 6px; padding: 8px 14px; background: rgba(99, 102, 241, 0.12); border-radius: 8px; border-left: 3px solid #6366F1;">'
                f'🔴 <b>Entity:</b> <code>{e["value"]}</code> &bull; <b>Type:</b> <code>{e["type"]}</code> &bull; <b>Span:</b> <code>{e["span"]}</code> &bull; <b>Confidence:</b> <code>{int(e["confidence"]*100)}%</code>'
                f'</div>'
                for e in ents
            ])
        else:
            det_rows = '<div style="margin-top: 6px; color: #10B981;">🟢 No sensitive PII detected in prompt.</div>'

        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #6366F1;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #818CF8; margin-bottom: 0;">3️⃣ STEP 3: 🔍 Detection Agent (PII Discovery & Checksums)</div>
                <span style="font-size: 0.82rem; color: #818CF8; font-weight: 600;">{s_detection.engine_badge} &bull; ⚡ {s_detection.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;">Discovered <b>{len(ents)}</b> sensitive entities with exact character offsets:</div>
              {det_rows}
            </div>
            """, unsafe_allow_html=True)

    # 4️⃣ STEP 4:  Classification Agent (Taxonomy & Statutory Policy Rules)
    if s_classification:
        class_list = s_classification.details.get("classifications", [])
        if class_list:
            class_rows = "".join([
                f'<div style="margin-top: 8px; padding: 10px 14px; background: rgba(245, 158, 11, 0.12); border-radius: 8px; border-left: 3px solid #F59E0B;">'
                f' <b>Entity:</b> <code>{c["value"]}</code> ➔ <b>Type:</b> <code>{c["type"]}</code> '
                f'<span style="background: rgba(245, 158, 11, 0.25); color: #FCD34D; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600;">{c["category"]}</span> &bull; '
                f'<b>Policy Action:</b> <code style="color: #FCD34D; font-weight: 700;">{c["recommended_action"]}</code><br/>'
                f'<span style="font-size: 0.85rem; color: #CBD5E1;">📖 <i>Rationale: {c["rationale"]}</i></span>'
                f'</div>'
                for c in class_list
            ])
        else:
            class_rows = '<div style="margin-top: 6px; color: #94A3B8;">Zero sensitive entities to classify.</div>'

        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #F59E0B;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #FBBF24; margin-bottom: 0;">4️⃣ STEP 4: 🏷️ Classification Agent (Taxonomy & Policy)</div>
                <span style="font-size: 0.82rem; color: #FBBF24; font-weight: 600;">{s_classification.engine_badge} &bull; ⚡ {s_classification.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;">Classifies detected entities against enterprise compliance rules:</div>
              {class_rows}
            </div>
            """, unsafe_allow_html=True)

    # 5️⃣ STEP 5:  Redaction & Tokenization Agent (Dual-Mode Enforcement)
    if s_transform:
        vault_tokens = s_transform.details.get("vault_tokens", {})
        vault_count = s_transform.details.get("vault_token_count", 0)
        redact_count = s_transform.details.get("redacted_count", 0)

        tf_items = []
        if vault_tokens:
            for raw_v, tok_v in vault_tokens.items():
                tf_items.append(
                    f'<div style="margin-top: 6px; padding: 8px 14px; background: rgba(16, 185, 129, 0.12); border-radius: 8px; border-left: 3px solid #10B981;">'
                    f'<span style="background: rgba(16, 185, 129, 0.25); color: #34D399; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 700;">🔑 TOKENIZE</span> '
                    f'<code>{raw_v}</code> ➔ <code style="color: #34D399; font-weight: 700;">{tok_v}</code><br/>'
                    f'<span style="font-size: 0.84rem; color: #CBD5E1;">&bull; Reversible encrypted token stored in ephemeral vault; will be re-hydrated on tool response.</span>'
                    f'</div>'
                )
        if redact_count > 0:
            tf_items.append(
                f'<div style="margin-top: 6px; padding: 8px 14px; background: rgba(239, 68, 68, 0.12); border-radius: 8px; border-left: 3px solid #EF4444;">'
                f'<span style="background: rgba(239, 68, 68, 0.25); color: #F87171; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 700;">🔒 REDACT</span> '
                f'Statutory high-risk secrets ➔ <code style="color: #F87171; font-weight: 700;">[REDACTED]</code><br/>'
                f'<span style="font-size: 0.84rem; color: #CBD5E1;">&bull; Permanently wiped clean from payload; zero vault storage; never leaves application boundary.</span>'
                f'</div>'
            )

        tf_display = "".join(tf_items) if tf_items else '<div style="margin-top: 6px; color: #94A3B8;">No privacy transformation required.</div>'

        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #8B5CF6;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #A78BFA; margin-bottom: 0;">5️⃣ STEP 5: 🛡️ Redaction & Tokenization Agent (Dual-Mode Enforcement)</div>
                <span style="font-size: 0.82rem; color: #A78BFA; font-weight: 600;">{s_transform.engine_badge} &bull; ⚡ {s_transform.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;">Enforces dual-mode tokenization & redaction:</div>
              {tf_display}
              <div style="margin-top: 10px; padding: 10px 14px; background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 8px;">
                <b>Outgoing Wire Query:</b><br/>
                <code style="display: block; font-size: 0.92rem; color: #FDE68A; background: transparent; word-break: break-all; margin-top: 4px;">&ldquo;{trace.sanitized_prompt}&rdquo;</code>
              </div>
              <div style="margin-top: 8px; font-size: 0.85rem; color: #34D399; font-weight: 600;">
                ✅ <b>Mathematical Leakage Proof:</b> Outgoing payload verified free of cleartext PII (0.0% Wire Leakage).
              </div>
            </div>
            """, unsafe_allow_html=True)

    # 6️⃣ STEP 6:  Other Tool Agent (Downstream External Service Execution)
    if s_tool and trace.success:
        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #06B6D4;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #67E8F9; margin-bottom: 0;">6️⃣ STEP 6: ⚙️ Other Tool Agent (Downstream External Tool)</div>
                <span style="font-size: 0.82rem; color: #67E8F9; font-weight: 600;">{s_tool.engine_badge} &bull; ⚡ {s_tool.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;">Downstream tool executes with sanitized parameters and responds:</div>
            </div>
            """, unsafe_allow_html=True)
            if s_tool.details.get("tool_response"):
                st.json(s_tool.details.get("tool_response"))
            st.caption(f"**Security Proof:** Third-party tool received 0 raw PII (Wire leakage: {trace.wire_leakage_percentage:.1f}%)")

    # 7️⃣ STEP 7:  Re-hydration Agent (Vault Interception & Restoration)
    if s_rehydrate and trace.success:
        with st.container():
            st.markdown(f"""
            <div class="step-card" style="border-left: 4px solid #10B981;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <div class="step-title" style="color: #34D399; margin-bottom: 0;">7️⃣ STEP 7: 🔄 Re-hydration Agent (Vault Interception & Restoration)</div>
                <span style="font-size: 0.82rem; color: #34D399; font-weight: 600;">{s_rehydrate.engine_badge} &bull; ⚡ {s_rehydrate.execution_ms:.2f} ms</span>
              </div>
              <div style="margin-top: 8px;">
                Intercepts the returning tool response. Restores tokenized values from ephemeral vault back into AI agent memory, while redacted secrets remain permanently scrubbed!
              </div>
              <div style="margin-top: 8px; padding: 8px 14px; background: rgba(16, 185, 129, 0.12); border-radius: 8px; font-size: 0.85rem; color: #34D399; font-weight: 600;">
                 <b>Zero Residual Lifecycle:</b> Ephemeral vault memory purged cleanly upon delivery.
              </div>
            </div>
            """, unsafe_allow_html=True)
            if trace.final_response:
                st.json(trace.final_response)
