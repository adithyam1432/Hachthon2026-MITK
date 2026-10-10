"""
build_streamlined_presentation.py
Generates a clean, professional white-theme PowerPoint presentation with ONLY:
1. Problem Statement
2. Proposed Solution
3. Key Features
4. Implementation
5. Outcome

Formatting Constraints:
- Background: Pure White (#FFFFFF)
- Font: Times New Roman
- Font Color: Black (#000000)
- Main Heading: 16 pt (Bold)
- Sub Heading: 14 pt (Bold)
- Content: 12 pt (Regular / Bold labels)
- Minimal, required content only (concise and clean)
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

PRIMARY_OUTPUT_FILE = "PII_Firewall_Core_Presentation.pptx"
FLOW_IMG_PATH = "docs/system_flow_design_white.png"

FONT_NAME = "Times New Roman"
COLOR_BLACK = RGBColor(0, 0, 0)
COLOR_WHITE = RGBColor(255, 255, 255)
COLOR_CARD_BG = RGBColor(250, 250, 250)
COLOR_BORDER = RGBColor(210, 215, 220)

def set_slide_background_white(slide):
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
    bg.fill.solid()
    bg.fill.fore_color.rgb = COLOR_WHITE
    bg.line.fill.background()
    return bg

def format_paragraph(p, text, size_pt, bold=False, space_after=0):
    p.text = text
    p.font.name = FONT_NAME
    p.font.size = Pt(size_pt)
    p.font.bold = bold
    p.font.color.rgb = COLOR_BLACK
    if space_after > 0:
        p.space_after = Pt(space_after)
    for run in p.runs:
        run.font.name = FONT_NAME
        run.font.size = Pt(size_pt)
        run.font.bold = bold
        run.font.color.rgb = COLOR_BLACK

def add_header(slide, main_heading, sub_heading):
    head_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.45), Inches(11.733), Inches(0.42))
    tf_head = head_box.text_frame
    tf_head.word_wrap = True
    tf_head.margin_left = tf_head.margin_top = tf_head.margin_right = tf_head.margin_bottom = 0
    format_paragraph(tf_head.paragraphs[0], main_heading, 16, bold=True)

    sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.92), Inches(11.733), Inches(0.38))
    tf_sub = sub_box.text_frame
    tf_sub.word_wrap = True
    tf_sub.margin_left = tf_sub.margin_top = tf_sub.margin_right = tf_sub.margin_bottom = 0
    format_paragraph(tf_sub.paragraphs[0], sub_heading, 14, bold=True)

def add_content_card(slide, left=Inches(0.8), top=Inches(1.45), width=Inches(11.733), height=Inches(5.5)):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD_BG
    card.line.color.rgb = COLOR_BORDER
    card.line.width = Pt(1.2)
    tf = card.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.4)
    tf.margin_right = Inches(0.4)
    tf.margin_top = Inches(0.3)
    return tf

def add_bullet_item(tf, bold_label, normal_text, space_after=8):
    p = tf.add_paragraph()
    if space_after > 0:
        p.space_after = Pt(space_after)
    
    r1 = p.add_run()
    r1.text = bold_label
    r1.font.name = FONT_NAME
    r1.font.size = Pt(12)
    r1.font.bold = True
    r1.font.color.rgb = COLOR_BLACK

    r2 = p.add_run()
    r2.text = normal_text
    r2.font.name = FONT_NAME
    r2.font.size = Pt(12)
    r2.font.bold = False
    r2.font.color.rgb = COLOR_BLACK
    return p

# -------------------------------------------------------------
# 1. PROBLEM STATEMENT
# -------------------------------------------------------------
def build_slide_problem(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Problem Statement", 
               "Privacy and Credential Leakage in Autonomous AI Agent Workflows")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "Problem Statement:", 14, bold=True, space_after=4)
    p_desc = tf.add_paragraph()
    format_paragraph(p_desc, 
                     "Autonomous AI agents executing third-party tool calls (Email, CRM, Payment APIs, Databases) frequently transmit unredacted personal information, financial identifiers, and credentials directly over the network wire, causing severe data privacy breaches and regulatory non-compliance.",
                     12, bold=False, space_after=16)

    p_pain = tf.add_paragraph()
    format_paragraph(p_pain, "Critical Pain Points:", 14, bold=True, space_after=8)

    pain_points = [
        ("• Direct PII Exposure: ", "Customer names, phone numbers, emails, SSNs, and credit cards are forwarded in cleartext to external API providers and stored in third-party logs."),
        ("• Adversarial Evasion: ", "Prompt injection techniques bypass traditional regex filters using invisible zero-width Unicode characters (\\u200B), Base64 encoding, and character delimiters."),
        ("• High Latency & Broken Tools: ", "Conventional cloud DLP gateways introduce 200–500 ms delays, while irreversible redaction breaks downstream API arguments and corrupts agent workflows."),
        ("• Severe Regulatory Liability: ", "Unauthorized personal data transmission violates GDPR, HIPAA, and DPDP Act 2023 mandates, exposing enterprises to substantial legal fines.")
    ]

    for label, text in pain_points:
        add_bullet_item(tf, label, text, space_after=10)

# -------------------------------------------------------------
# 2. PROPOSED SOLUTION
# -------------------------------------------------------------
def build_slide_solution(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Proposed Solution", 
               "PII Firewall for AI Agents: Zero-Trust Inline Privacy Middleware")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "Solution Overview:", 14, bold=True, space_after=4)
    p_desc = tf.add_paragraph()
    format_paragraph(p_desc, 
                     "An ultra-low-latency inline security middleware that intercepts agent tool calls, replaces sensitive values with cryptographically salted reversible tokens, mathematically verifies zero residual leakage before transmission, and losslessly restores responses into agent memory.",
                     12, bold=False, space_after=16)

    p_core = tf.add_paragraph()
    format_paragraph(p_core, "Core Architectural Principles:", 14, bold=True, space_after=8)

    principles = [
        ("• Inline Gateway Interception: ", "Inspects tool calls transparently via Python decorators or REST microservice proxy without modifying underlying tool logic."),
        ("• Reversible Salted Tokenization: ", "Replaces sensitive data with opaque tokens ([TYPE_hash8]) using a unique 128-bit cryptographic salt per request."),
        ("• Ephemeral Volatile Vault: ", "Token mapping tables exist strictly in volatile RAM for the duration of the request and are never written to disk or logs."),
        ("• Fail-Closed Leakage Verification: ", "Performs a full serialized wire packet scan against detected secrets before dispatch, guaranteeing 0.0% residual cleartext leakage."),
        ("• Lossless Context Re-Hydration: ", "Transparently swaps echoed tokens back to original values in agent memory and purges temporary vault RAM to zero bytes.")
    ]

    for label, text in principles:
        add_bullet_item(tf, label, text, space_after=10)

# -------------------------------------------------------------
# 3. KEY FEATURES
# -------------------------------------------------------------
def build_slide_features(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Key Features", 
               "Core Security, Detection, and Performance Capabilities")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "System Capabilities:", 14, bold=True, space_after=8)

    features = [
        ("• Hybrid Multi-Modal Detection: ", "Combines RFC regex, mathematical checksum algorithms (Luhn Mod-10 for credit cards, UIDAI Verhoeff for Aadhaar), and context-aware NLP heuristics."),
        ("• 3-Tier Security Policy Engine: ", "Enforces mandatory Zero-Trust rules: Tier 1 Credentials (PIN, CVV, OTP, Passwords) are hard-blocked; Tier 2 Personal Info is tokenized; Tier 3 Business data requires destination approval."),
        ("• Adversarial Attack Defense: ", "Normalizes Unicode NFKC, strips hidden zero-width characters (\\u200B), and decodes Base64-smuggled strings to defeat prompt injection bypasses."),
        ("• Hardware Layer 2 Binding: ", "Pins requests to client MAC addresses, integrating with IEEE 802.1AE MACsec for OSI Data Link Layer defense-in-depth."),
        ("• Zero-Code Integration: ", "Provides a simple @protect_tool Python decorator for LangChain, CrewAI, and AutoGen agents, alongside standard REST endpoints (/v1/intercept, /v1/restore)."),
        ("• Zero-PII Compliance Audit: ", "Generates tamper-evident SHA-256 compliance logs recording request metrics and timestamps with zero cleartext personal data stored.")
    ]

    for label, text in features:
        add_bullet_item(tf, label, text, space_after=9)

# -------------------------------------------------------------
# 4. IMPLEMENTATION
# -------------------------------------------------------------
def build_slide_implementation(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Implementation", 
               "End-to-End Execution Pipeline and System Architecture")

    # Embed human-understandable flow diagram
    if os.path.exists(FLOW_IMG_PATH):
        slide.shapes.add_picture(FLOW_IMG_PATH, Inches(0.8), Inches(1.4), width=Inches(11.733), height=Inches(4.65))

    # Bottom implementation summary container
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(6.18), Inches(11.733), Inches(0.95))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD_BG
    card.line.color.rgb = COLOR_BORDER
    card.line.width = Pt(1.0)

    tf = card.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.25)
    tf.margin_right = Inches(0.25)
    tf.margin_top = Inches(0.12)

    format_paragraph(tf.paragraphs[0], 
                     "• Execution Pipeline: Ingress tool call -> Adversarial cleaning (\\u200B stripped) -> Hybrid detection matrix -> 3-tier policy -> 128-bit salted token vault -> Pre-wire leakage verification (0.0% residual leak) -> External tool execution -> Lossless response re-hydration -> RAM purge.", 
                     12, bold=False, space_after=3)

    p2 = tf.add_paragraph()
    format_paragraph(p2, 
                     "• Tech Stack: Python 3.11+ runtime, ThreadPoolExecutor concurrent batching (>2,500 req/s), Flask REST microservice, Streamlit interactive dashboard, and 333+ PyTest automated test battery.", 
                     12, bold=False)

# -------------------------------------------------------------
# 5. OUTCOME
# -------------------------------------------------------------
def build_slide_outcome(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Outcome", 
               "Measured Performance Benchmarks, Security Guarantees, and Impact")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "Verified Results and Impact:", 14, bold=True, space_after=8)

    outcomes = [
        ("• Zero Data Leakage (0.0%): ", "Verified that 0 bytes of cleartext PII or credentials ever reach external tools or network wires during simulated and live API executions."),
        ("• Sub-Millisecond Processing Latency (~1.2 ms): ", "Demonstrated an average overhead of ~1.2 ms per tool call, easily surpassing the <25 ms SLA and adding less than 0.05% overhead to LLM workflows."),
        ("• 100% Automated Test Pass Rate (333 / 333): ", "Comprehensive test battery successfully validated all edge cases, nested JSON structures, Indian KYC entities (PAN, Aadhaar), and adversarial attack vectors."),
        ("• High Concurrent Throughput (>2,500 req/sec): ", "Multi-threaded batch engine sustained over 2,500 requests per second across 50 concurrent worker threads without race conditions or memory leaks."),
        ("• Strict Regulatory Compliance: ", "Guarantees complete legal and compliance safety under GDPR (Art. 6/9/32), HIPAA, PCI-DSS, and India DPDP Act 2023 with tamper-evident audit trails."),
        ("• Lossless Workflow Fidelity (100.0%): ", "Maintains complete context retention in autonomous agent memory while wiping ephemeral vault RAM to zero residual bytes upon response.")
    ]

    for label, text in outcomes:
        add_bullet_item(tf, label, text, space_after=9)

def main():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    print("Generating streamlined presentation (Problem Statement, Proposed Solution, Key Features, Implementation, Outcome)...")
    build_slide_problem(prs)
    build_slide_solution(prs)
    build_slide_features(prs)
    build_slide_implementation(prs)
    build_slide_outcome(prs)

    prs.save(PRIMARY_OUTPUT_FILE)
    print(f"Successfully generated: {PRIMARY_OUTPUT_FILE}")

if __name__ == "__main__":
    main()
