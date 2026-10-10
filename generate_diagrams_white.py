"""
generate_diagrams_white.py
Generates clean, professional white-background diagrams using Times New Roman:
1. docs/system_flow_design_white.png
2. docs/system_architecture_design_white.png
"""

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import os

os.makedirs("docs", exist_ok=True)
os.makedirs("assets", exist_ok=True)

FONT_FAMILY = 'Times New Roman'

# -------------------------------------------------------------
# 1. WHITE THEME SYSTEM FLOW DESIGN
# -------------------------------------------------------------
def generate_system_flow_white():
    fig, ax = plt.subplots(figsize=(22, 11), dpi=300)
    fig.patch.set_facecolor('#FFFFFF')
    ax.set_facecolor('#FFFFFF')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Main Diagram Title
    ax.text(50, 96, "PII Firewall for AI Agents — End-to-End System Flow", 
            fontsize=20, fontweight='bold', color='#000000', ha='center', va='center', family=FONT_FAMILY)
    ax.text(50, 92.5, "8-Step Data Pipeline: Request Interception, Tokenization, Wire Verification, and Response Re-Hydration", 
            fontsize=13, color='#333333', ha='center', va='center', family=FONT_FAMILY)

    cards = [
        # (x, y, w, h, step, badge_col, title, bullets, eg_title, eg_text)
        (4, 52, 20.5, 36, "Step 1: Agent Ingress", "#0284C7", "AI Agent Tool Call",
         ["• Agent issues tool request", "• Intercepted via gateway", "• Analyzes JSON arguments"],
         "Input Data:", '{"to": "alex@corp.com",\n "ssn": "123-45-6789"}'),

        (28, 52, 20.5, 36, "Step 2: Normalization", "#7C3AED", "Adversarial Defense",
         ["• Strips zero-width chars (\\u200B)", "• Decodes Base64 payloads", "• Neutralizes bypass attempts"],
         "Normalized:", '"alex\\u200B@corp.com"\n  -> "alex@corp.com"'),

        (52, 52, 20.5, 36, "Step 3: Detection Matrix", "#059669", "Hybrid PII Detection",
         ["• Regex: RFC Email, Phone", "• Checksums: Luhn, Verhoeff", "• Context NLP: PIN vs Year"],
         "Detected Entities:", "• alex@corp.com (Email)\n• 123-45-6789 (SSN)"),

        (76, 52, 20.5, 36, "Step 4: Policy Engine", "#D97706", "3-Tier Policy Action",
         ["• Tier 1: Credentials -> Block", "• Tier 2: Personal -> Tokenize", "• Tier 3: Business -> Allow"],
         "Policy Action:", "Decision: TOKENIZE\nCredentials: None"),

        # Row 2 (Steps 5 to 8, right to left)
        (76, 10, 20.5, 36, "Step 5: Ephemeral Vault", "#DB2777", "Salted Token Vault",
         ["• 128-bit cryptographic salt", "• Layer 2 MAC address binding", "• Non-persistent memory"],
         "Generated Tokens:", '"alex@corp.com"\n  -> [EMAIL_a7b8c9d0]'),

        (52, 10, 20.5, 36, "Step 6: Leakage Verifier", "#DC2626", "Wire Leakage Audit",
         ["• Scans serialized wire bytes", "• Compares with original PII", "• 0.0% residual guaranteed"],
         "Audit Status:", "Residual Leakage: 0.0%\nTransmission: SAFE"),

        (28, 10, 20.5, 36, "Step 7: External Tool", "#16A34A", "Downstream Tool Wire",
         ["• Tool receives opaque tokens", "• Executes task safely", "• Zero real PII disclosed"],
         "Tool Receives:", '{"to": "[EMAIL_a7b8c9d0]",\n "status": "sent"}'),

        (4, 10, 20.5, 36, "Step 8: Re-Hydration", "#4F46E5", "Response Restoration",
         ["• Resolves echoed tokens", "• Injects cleartext to agent", "• Vault memory purged to 0B"],
         "Agent Receives:", '{"to": "alex@corp.com",\n "status": "sent"}')
    ]

    for (x, y, w, h, step, badge_col, title, bullets, eg_title, eg_text) in cards:
        # Card
        card = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.2,rounding_size=0.8",
                              facecolor='#F8FAFC', edgecolor='#94A3B8', linewidth=1.5, zorder=2)
        ax.add_patch(card)

        # Header bar
        hbar = FancyBboxPatch((x, y + h - 4.5), w, 4.5, boxstyle="round,pad=0.1,rounding_size=0.6",
                              facecolor='#E2E8F0', edgecolor='none', zorder=3)
        ax.add_patch(hbar)

        # Step header
        ax.text(x + 1.2, y + h - 2.3, step, fontsize=11, fontweight='bold', color=badge_col, 
                va='center', family=FONT_FAMILY, zorder=4)

        # Title
        ax.text(x + 1.2, y + h - 6.5, title, fontsize=12, fontweight='bold', color='#000000', 
                va='center', family=FONT_FAMILY, zorder=4)

        # Bullets
        by = y + h - 10.0
        for b in bullets:
            ax.text(x + 1.2, by, b, fontsize=10, color='#1E293B', va='top', family=FONT_FAMILY, zorder=4)
            by -= 2.8

        # Example box
        ebox = FancyBboxPatch((x + 1.0, y + 1.2), w - 2.0, 11, boxstyle="round,pad=0.2,rounding_size=0.6",
                              facecolor='#FFFFFF', edgecolor='#CBD5E1', linewidth=1.2, zorder=3)
        ax.add_patch(ebox)
        ax.text(x + 1.6, y + 10.5, eg_title, fontsize=9.5, fontweight='bold', color='#334155', 
                va='center', family=FONT_FAMILY, zorder=4)
        ax.text(x + 1.6, y + 6.0, eg_text, fontsize=9, color='#0F172A', 
                va='center', family='Courier New', zorder=4)

    # Connecting Arrows
    ax.annotate('', xy=(28, 70), xytext=(24.5, 70),
                arrowprops=dict(arrowstyle="-|>", color='#0284C7', lw=2.5, mutation_scale=16), zorder=10)
    ax.annotate('', xy=(52, 70), xytext=(48.5, 70),
                arrowprops=dict(arrowstyle="-|>", color='#7C3AED', lw=2.5, mutation_scale=16), zorder=10)
    ax.annotate('', xy=(76, 70), xytext=(72.5, 70),
                arrowprops=dict(arrowstyle="-|>", color='#059669', lw=2.5, mutation_scale=16), zorder=10)
    
    # Step 4 -> 5
    ax.annotate('', xy=(86.25, 46), xytext=(86.25, 52),
                arrowprops=dict(arrowstyle="-|>", color='#D97706', lw=2.5, mutation_scale=16), zorder=10)

    # Step 5 -> 6 -> 7 -> 8 (Leftwards)
    ax.annotate('', xy=(72.5, 28), xytext=(76, 28),
                arrowprops=dict(arrowstyle="-|>", color='#DB2777', lw=2.5, mutation_scale=16), zorder=10)
    ax.annotate('', xy=(48.5, 28), xytext=(52, 28),
                arrowprops=dict(arrowstyle="-|>", color='#DC2626', lw=2.5, mutation_scale=16), zorder=10)
    ax.annotate('', xy=(24.5, 28), xytext=(28, 28),
                arrowprops=dict(arrowstyle="-|>", color='#16A34A', lw=2.5, mutation_scale=16), zorder=10)

    # Step 8 -> 1 (Loop back)
    ax.annotate('', xy=(14.25, 52), xytext=(14.25, 46),
                arrowprops=dict(arrowstyle="-|>", color='#4F46E5', lw=2.5, mutation_scale=16), zorder=10)
    ax.text(15.5, 49, "Context Restored to Agent", fontsize=10, fontweight='bold', color='#4F46E5', 
            va='center', family=FONT_FAMILY, zorder=11)

    # Bottom Benchmarks
    bbar = FancyBboxPatch((4, 2.0), 92.5, 4.5, boxstyle="round,pad=0.2,rounding_size=0.6",
                          facecolor='#F1F5F9', edgecolor='#94A3B8', linewidth=1.2, zorder=2)
    ax.add_patch(bbar)
    ax.text(50, 4.25, 
            "Verified Benchmarks: Latency: 1.2 ms  |  Wire Leakage: 0.0%  |  Throughput: >2,500 req/s  |  Test Suite: 333/333 Passed",
            fontsize=11, fontweight='bold', color='#0F172A', ha='center', va='center', family=FONT_FAMILY, zorder=4)

    plt.tight_layout()
    out_path = "docs/system_flow_design_white.png"
    plt.savefig(out_path, facecolor='#FFFFFF', edgecolor='none', bbox_inches='tight')
    plt.savefig("assets/system_flow_design_white.png", facecolor='#FFFFFF', edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f"Generated {out_path}")

# -------------------------------------------------------------
# 2. WHITE THEME SYSTEM ARCHITECTURE DESIGN
# -------------------------------------------------------------
def generate_system_architecture_white():
    fig, ax = plt.subplots(figsize=(22, 11), dpi=300)
    fig.patch.set_facecolor('#FFFFFF')
    ax.set_facecolor('#FFFFFF')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Main Header
    ax.text(50, 96, "PII Firewall for AI Agents — System Architecture", 
            fontsize=20, fontweight='bold', color='#000000', ha='center', va='center', family=FONT_FAMILY)
    ax.text(50, 92.5, "Defense-in-Depth Layered Architecture for Autonomous AI Tool Interception", 
            fontsize=13, color='#333333', ha='center', va='center', family=FONT_FAMILY)

    # 4 Layers (Horizontal Tiers)
    layers = [
        # (title, col, y, h, cards)
        ("Layer 1: Agent & Ingress Gateway", "#0369A1", 72, 17, [
            (6, "Autonomous AI Agents", "LangChain, CrewAI, AutoGen", ["• Issues tool requests with dynamic parameters"]),
            (37, "Python SDK Adapter", "@protect_tool Decorator", ["• Intercepts tool calls in-memory with zero overhead"]),
            (68, "REST Microservice Gateway", "Flask / FastAPI Endpoints", ["• Standard HTTP endpoints for multi-language agents"])
        ]),
        ("Layer 2: Adversarial Defense & Detection Matrix", "#6D28D9", 49, 19, [
            (6, "Adversarial Pre-Filter", "Evasion Defense", ["• Strips zero-width chars (\\u200B)", "• Decodes Base64 payloads"]),
            (29, "Deterministic Regex", "RFC Compliant", ["• Email, Phone, SSN", "• IP addresses & API keys"]),
            (52, "Algorithmic Checksums", "Zero False-Positives", ["• Luhn Mod-10 (Cards)", "• UIDAI Verhoeff (Aadhaar)"]),
            (75, "Context NLP & AI", "Semantic Disambiguation", ["• PIN vs Year heuristic", "• Google Gemini fallback"])
        ]),
        ("Layer 3: Policy Engine & Ephemeral Token Vault", "#047857", 26, 19, [
            (6, "3-Tier Policy Engine", "Mandatory Security Rules", ["• Tier 1: Hard-blocks credentials", "• Tier 2: Tokenizes personal PII", "• Tier 3: Business allowlists"]),
            (37, "Ephemeral Token Vault", "Salted Hash Registry", ["• 128-bit random cryptographic salt", "• Opaque tokens: [TYPE_hash8]", "• Ephemeral RAM storage"]),
            (68, "Layer 2 Hardware Binding", "OSI Data Link Security", ["• Client MAC address pinning", "• Prevents spoofing / MITM", "• VLAN microsegmentation"])
        ]),
        ("Layer 4: Verification, Wire Egress & Re-Hydration", "#B91C1C", 3, 19, [
            (6, "Leakage Verifier", "Fail-Closed Proof", ["• Pre-transmission scan", "• 0.0% residual leakage proof"]),
            (29, "External Tool Wire", "Safe Downstream Tool", ["• Receives opaque tokens only", "• Echoes token responses"]),
            (52, "Response Re-Hydrator", "Lossless Restoration", ["• Restores tokens in agent memory", "• Purges vault RAM to 0 bytes"]),
            (75, "Compliance Audit", "Zero-PII Ledger", ["• SHA-256 tamper-proof log", "• GDPR & HIPAA verifiable"])
        ])
    ]

    for ltitle, lcol, ly, lh, lcards in layers:
        # Layer container
        l_box = FancyBboxPatch((3, ly), 94, lh, boxstyle="round,pad=0.2,rounding_size=0.6",
                               facecolor='#F8FAFC', edgecolor='#CBD5E1', linewidth=1.5, zorder=2)
        ax.add_patch(l_box)
        ax.text(5, ly + lh - 2.5, ltitle, fontsize=11.5, fontweight='bold', color=lcol, 
                va='center', family=FONT_FAMILY, zorder=4)

        # Inner cards
        cw = 88 / len(lcards) - 2.0
        for idx, item in enumerate(lcards):
            cx = 5 + idx * (cw + 2.5)
            c_box = FancyBboxPatch((cx, ly + 1.2), cw, lh - 4.5, boxstyle="round,pad=0.2,rounding_size=0.5",
                                   facecolor='#FFFFFF', edgecolor='#E2E8F0', linewidth=1.2, zorder=3)
            ax.add_patch(c_box)
            ax.text(cx + 1.0, ly + lh - 5.2, item[1], fontsize=10.5, fontweight='bold', color='#000000', 
                    va='center', family=FONT_FAMILY, zorder=4)
            ax.text(cx + 1.0, ly + lh - 7.2, item[2], fontsize=9, color='#475569', 
                    va='center', family=FONT_FAMILY, zorder=4)
            
            by = ly + lh - 9.5
            for bullet in item[3]:
                ax.text(cx + 1.0, by, bullet, fontsize=8.5, color='#1E293B', 
                        va='top', family=FONT_FAMILY, zorder=4)
                by -= 2.2

    # Vertical Connecting Arrows
    ax.annotate('', xy=(50, 68), xytext=(50, 72),
                arrowprops=dict(arrowstyle="-|>", color='#0369A1', lw=2.0, mutation_scale=14), zorder=10)
    ax.annotate('', xy=(50, 45), xytext=(50, 49),
                arrowprops=dict(arrowstyle="-|>", color='#6D28D9', lw=2.0, mutation_scale=14), zorder=10)
    ax.annotate('', xy=(50, 22), xytext=(50, 26),
                arrowprops=dict(arrowstyle="-|>", color='#047857', lw=2.0, mutation_scale=14), zorder=10)

    plt.tight_layout()
    out_path = "docs/system_architecture_design_white.png"
    plt.savefig(out_path, facecolor='#FFFFFF', edgecolor='none', bbox_inches='tight')
    plt.savefig("assets/system_architecture_design_white.png", facecolor='#FFFFFF', edgecolor='none', bbox_inches='tight')
    plt.close()
    print(f"Generated {out_path}")

if __name__ == "__main__":
    generate_system_flow_white()
    generate_system_architecture_white()
