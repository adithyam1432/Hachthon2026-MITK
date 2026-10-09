"""
PII Firewall for AI Agents - Core Package
"""

from pii_firewall.middleware import PIIFirewall
from pii_firewall.batch import (
    BatchPIIFirewall,
    BatchItemResult,
    BatchProcessResult,
)
from pii_firewall.custom_recognizer import (
    CustomRegexRecognizer,
    CustomFunctionRecognizer,
    create_custom_recognizer,
)
from pii_firewall.models import (
    PIIType,
    PIIEntity,
    SensitivityCategory,
    TYPE_TO_CATEGORY,
    FirewallConfig,
    FirewallResult,
    FirewallMetrics,
    PIILeakageDetectedError,
    FirewallBlockedError,
)
from pii_firewall.semantic_nlp import ContextAwareNLPEngine
from pii_firewall.simulated_tool import SimulatedExternalTool
from pii_firewall.agent_adapter import AgentToolAdapter
from pii_firewall.policy import PolicyEngine, PolicyAction, ToolPolicyRule
from pii_firewall.adversarial_defense import AdversarialDefenseNormalizer
from pii_firewall.audit_logger import AuditLogger

__all__ = [
    "PIIFirewall",
    "BatchPIIFirewall",
    "BatchItemResult",
    "BatchProcessResult",
    "CustomRegexRecognizer",
    "CustomFunctionRecognizer",
    "create_custom_recognizer",
    "PIIType",
    "PIIEntity",
    "SensitivityCategory",
    "TYPE_TO_CATEGORY",
    "ContextAwareNLPEngine",
    "FirewallConfig",
    "FirewallResult",
    "FirewallMetrics",
    "PIILeakageDetectedError",
    "FirewallBlockedError",
    "SimulatedExternalTool",
    "AgentToolAdapter",
    "PolicyEngine",
    "PolicyAction",
    "ToolPolicyRule",
    "AdversarialDefenseNormalizer",
    "AuditLogger",
]
