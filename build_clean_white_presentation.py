"""
build_clean_white_presentation.py
Generates a professional, clean, white-theme PowerPoint presentation with:
- Background: Pure White (RGB 255, 255, 255)
- Font Style: Times New Roman
- Font Color: Black (RGB 0, 0, 0)
- Main Heading: 16 pt
- Sub Heading: 14 pt
- Content: 12 pt
- Minimal, required content only (no clutter)
- 6 Pages:
  1. Problem statement and pain points
  2. Solution given to that problem through our product
  3. System flow design (with human-understandable image)
  4. System architecture design (with human-understandable image)
  5. Users
  6. Tech stacks used
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

PRIMARY_OUTPUT_FILE = "PII_Firewall_Professional_Presentation.pptx"
FALLBACK_OUTPUT_FILE = "PII_Firewall_Presentation.pptx"
FLOW_IMG_PATH = "docs/system_flow_design_white.png"
ARCH_IMG_PATH = "docs/system_architecture_design_white.png"

FONT_NAME = "Times New Roman"
COLOR_BLACK = RGBColor(0, 0, 0)
COLOR_WHITE = RGBColor(255, 255, 255)
COLOR_CARD_BG = RGBColor(250, 250, 250) # Subtle clean light card background
COLOR_BORDER = RGBColor(210, 215, 220)   # Clean professional border

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
    # Main Heading (16 pt, Times New Roman, Bold, Black)
    head_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.45), Inches(11.733), Inches(0.42))
    tf_head = head_box.text_frame
    tf_head.word_wrap = True
    tf_head.margin_left = tf_head.margin_top = tf_head.margin_right = tf_head.margin_bottom = 0
    format_paragraph(tf_head.paragraphs[0], main_heading, 16, bold=True)

    # Sub Heading (14 pt, Times New Roman, Bold, Black)
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
    tf.margin_left = Inches(0.35)
    tf.margin_right = Inches(0.35)
    tf.margin_top = Inches(0.3)
    return tf

def add_item_with_label(tf, bold_label, normal_text, space_after=8):
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
# SLIDE 1: Problem Statement and Pain Points
# -------------------------------------------------------------
def build_slide_1(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Problem Statement and Pain Points", 
               "Privacy and Credential Leakage in Autonomous AI Agent Workflows")

    tf = add_content_card(slide)

    # Problem Statement Section
    format_paragraph(tf.paragraphs[0], "Problem Statement:", 14, bold=True, space_after=4)
    p_prob = tf.add_paragraph()
    format_paragraph(p_prob, 
                     "Autonomous AI agents executing third-party tool calls (Email, CRM, Payment APIs, Databases) frequently pass unredacted personal information, financial identifiers, and credentials directly over the network wire, causing severe data privacy and regulatory breaches.",
                     12, bold=False, space_after=16)

    # Pain Points Section
    p_pain = tf.add_paragraph()
    format_paragraph(p_pain, "Key Pain Points:", 14, bold=True, space_after=8)

    points = [
        ("1. Direct PII & Credential Exposure: ", "Customer names, phone numbers, emails, SSNs, and credit cards are routinely forwarded in cleartext to external API providers and third-party logs."),
        ("2. Adversarial Evasion & Smuggling: ", "Prompt injection techniques bypass traditional regex using invisible zero-width Unicode characters (\\u200B), Base64 encoding, and character delimiters."),
        ("3. High Latency & Broken Tool Execution: ", "Conventional cloud DLP gateways introduce 200–500 ms delays, while irreversible redaction breaks downstream API arguments and corrupts agent execution."),
        ("4. Severe Regulatory Penalties: ", "Unauthorized personal data transmission violates GDPR, HIPAA, and DPDP Act 2023 mandates, exposing enterprises to substantial legal fines.")
    ]

    for label, desc in points:
        add_item_with_label(tf, label, desc, space_after=10)

# -------------------------------------------------------------
# SLIDE 2: Solution Given to That Problem Through Our Product
# -------------------------------------------------------------
def build_slide_2(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Solution Given to That Problem Through Our Product", 
               "PII Firewall for AI Agents: Zero-Trust, Sub-Millisecond Privacy Middleware")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "Product Solution Overview:", 14, bold=True, space_after=4)
    p_sol = tf.add_paragraph()
    format_paragraph(p_sol, 
                     "An ultra-low-latency inline security middleware that intercepts agent tool calls, replaces sensitive values with cryptographically salted reversible tokens, mathematically verifies zero residual leakage before transmission, and losslessly restores responses into agent memory.",
                     12, bold=False, space_after=14)

    p_feat = tf.add_paragraph()
    format_paragraph(p_feat, "Core Solution Capabilities:", 14, bold=True, space_after=6)

    capabilities = [
        ("• Hybrid Multi-Modal Detection: ", "Combines RFC regex, mathematical checksums (Luhn Mod-10 for cards, UIDAI Verhoeff for Aadhaar), context-aware NLP heuristics, and Google Gemini fallback."),
        ("• 3-Tier Security Policy Engine: ", "Enforces strict Zero-Trust rules: Tier 1 Credentials (PIN, CVV, OTP, Passwords) are hard-blocked; Tier 2 Personal Info is tokenized; Tier 3 Business data requires destination approval."),
        ("• Cryptographically Salted Ephemeral Vault: ", "Maps sensitive values to opaque tokens ([TYPE_hash8]) using a 128-bit random salt and Layer 2 MAC address binding in non-persistent volatile memory."),
        ("• Fail-Closed Leakage Verification: ", "Audits serialized wire packets against detected secrets, guaranteeing 0.0% residual cleartext before packets leave the local gateway."),
        ("• Lossless Response Re-Hydration: ", "Transparently restores echoed tokens in tool responses back to original cleartext for the agent, then purges temporary vault RAM to zero bytes."),
        ("• Verified Performance Metrics: ", "Sub-millisecond latency overhead (~1.2 ms), concurrent throughput exceeding 2,500 requests/sec, and 100% test pass rate across 333+ tests.")
    ]

    for label, desc in capabilities:
        add_item_with_label(tf, label, desc, space_after=6)

# -------------------------------------------------------------
# SLIDE 3: System Flow Design
# -------------------------------------------------------------
def build_slide_3(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "System Flow Design", 
               "End-to-End Interception, Tokenization, and Restoration Lifecycle")

    # Embed clean white diagram
    if os.path.exists(FLOW_IMG_PATH):
        slide.shapes.add_picture(FLOW_IMG_PATH, Inches(0.8), Inches(1.4), width=Inches(11.733), height=Inches(4.65))

    # Bottom content container
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
                     "• Request Flow (Ingress): AI agent tool call -> Adversarial normalization (\\u200B stripped) -> Hybrid detection matrix -> 3-tier policy evaluation -> Salted token vault -> Wire leakage audit (0.0% residual leak).", 
                     12, bold=False, space_after=3)

    p2 = tf.add_paragraph()
    format_paragraph(p2, 
                     "• Response Flow (Egress): Downstream tool executes safely with opaque tokens -> Tool response intercepted -> Re-hydrator restores cleartext into agent memory -> Ephemeral vault memory purged to 0 bytes.", 
                     12, bold=False)

# -------------------------------------------------------------
# SLIDE 4: System Architecture Design
# -------------------------------------------------------------
def build_slide_4(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "System Architecture Design", 
               "Multi-Tier Defense-in-Depth Modular System Architecture")

    # Embed clean white diagram
    if os.path.exists(ARCH_IMG_PATH):
        slide.shapes.add_picture(ARCH_IMG_PATH, Inches(0.8), Inches(1.4), width=Inches(11.733), height=Inches(4.65))

    # Bottom content container
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
                     "• Multi-Tier Modularity: Layer 1 Agent Ingress (@protect_tool / REST Gateway) -> Layer 2 Evasion Defense & Detection Matrix -> Layer 3 Policy Engine & Ephemeral Vault -> Layer 4 Leakage Verifier & Re-Hydrator.", 
                     12, bold=False, space_after=3)

    p2 = tf.add_paragraph()
    format_paragraph(p2, 
                     "• Enterprise Security Controls: Hardware Layer 2 MAC address pinning, request-isolated volatile RAM vaults, fail-closed transmission block on leakage, and Zero-PII SHA-256 compliance audit ledger.", 
                     12, bold=False)

# -------------------------------------------------------------
# SLIDE 5: Users
# -------------------------------------------------------------
def build_slide_5(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Users", 
               "Target Users, Personas, and Enterprise Stakeholders")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "Target User Groups and Beneficiaries:", 14, bold=True, space_after=12)

    users = [
        ("1. AI Agent Developers & Engineers: ", "Teams building autonomous tool-calling systems using LangChain, CrewAI, AutoGen, or custom LLM frameworks. They benefit from drop-in Python decorators (@protect_tool) and REST proxies requiring zero modification to existing tool logic, with virtually no latency penalty (~1.2 ms)."),
        ("2. Enterprise CISOs & SecOps Teams: ", "Security leaders seeking to enforce strict Zero-Trust security perimeters around corporate AI deployments. The system prevents prompt-injected data exfiltration, Unicode evasions, and API credential leakage through Layer 2 MAC address binding and fail-closed controls."),
        ("3. Compliance, Legal & Risk Officers: ", "Corporate governance officers responsible for ensuring strict adherence to GDPR (Art. 6, 9, 32), HIPAA, PCI-DSS, and the India DPDP Act 2023. They gain mathematical proof of 0.0% data leakage along with tamper-evident SHA-256 audit ledgers containing zero cleartext PII."),
        ("4. FinTech, Healthcare & Public Sector SaaS: ", "Enterprises automating loan approvals, insurance claim triage, customer onboarding, and telehealth consultations. The product ensures sensitive financial credentials (PIN, CVV), Indian KYC records (PAN, Aadhaar), and medical data are never leaked to third-party APIs.")
    ]

    for label, desc in users:
        add_item_with_label(tf, label, desc, space_after=12)

# -------------------------------------------------------------
# SLIDE 6: Tech Stacks Used
# -------------------------------------------------------------
def build_slide_6(prs):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_background_white(slide)
    add_header(slide, 
               "Tech Stacks Used", 
               "Core Technologies, Algorithms, and Architectural Frameworks")

    tf = add_content_card(slide)

    format_paragraph(tf.paragraphs[0], "Architectural Technology Stack Breakdown:", 14, bold=True, space_after=10)

    tech_stacks = [
        ("• Core Runtime & Concurrency: ", "Python 3.11+, ThreadPoolExecutor for concurrent batch execution (>2,500 requests/sec), recursive JSON data tree parser preserving primitive types."),
        ("• Algorithmic Checksums & Validation: ", "Luhn Mod-10 checksum algorithm (Credit Card validation), UIDAI Verhoeff checksum algorithm (12-digit Indian Aadhaar validation), RFC-compliant regex pattern matchers."),
        ("• AI & Semantic NLP: ", "Context-aware semantic heuristics (disambiguating PIN vs calendar year, suppressing scheduling stopwords like 'at 3pm'), Google Gemini Free-Tier API for semantic intent fallback."),
        ("• Cryptography & Network Security: ", "128-bit cryptographic random salting (os.urandom), HMAC/SHA-256 token hashing, Hardware Layer 2 MAC address pinning, IEEE 802.1AE MACsec compatibility."),
        ("• Interfaces & Observability: ", "Flask REST Microservice API (/v1/intercept, /v1/restore), Streamlit interactive web dashboard, @protect_tool Python SDK decorator, Zero-PII SHA-256 audit ledger."),
        ("• Testing & Verification Battery: ", "PyTest automated test suite with 333+ unit, synthetic, and integration tests covering adversarial evasions, concurrent load, and edge cases (100% pass rate).")
    ]

    for label, desc in tech_stacks:
        add_item_with_label(tf, label, desc, space_after=8)

def main():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    print("Generating clean white presentation with Times New Roman (16/14/12 pt)...")
    build_slide_1(prs)
    build_slide_2(prs)
    build_slide_3(prs)
    build_slide_4(prs)
    build_slide_5(prs)
    build_slide_6(prs)

    prs.save(PRIMARY_OUTPUT_FILE)
    print(f"Successfully generated: {PRIMARY_OUTPUT_FILE}")

    try:
        prs.save(FALLBACK_OUTPUT_FILE)
        print(f"Also saved to: {FALLBACK_OUTPUT_FILE}")
    except PermissionError:
        print(f"Note: {FALLBACK_OUTPUT_FILE} is open in PowerPoint; saved to {PRIMARY_OUTPUT_FILE} instead.")

if __name__ == "__main__":
    main()
