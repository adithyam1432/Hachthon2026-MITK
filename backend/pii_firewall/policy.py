"""
Granular Policy Engine for PII Firewall with Mandatory Three-Tier Security Principles.

Security Principles Enforced:
  A. Credentials: Block by Default across unauthorized boundaries.
  B. Personal Information: Policy-based Redaction, Masking, and Tokenization.
  C. Confidential Business Information: Destination-Aware Controls & Allowlists.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Union
from pii_firewall.models import PIIType, SensitivityCategory, TYPE_TO_CATEGORY


class PolicyAction(str, Enum):
    TOKENIZE = "TOKENIZE"         # Reversible encrypted token
    REDACT = "REDACT"             # Non-reversible [REDACTED_TYPE]
    MASK = "MASK"                 # Partial masking: ****-1234
    BLOCK_TOOL = "BLOCK_TOOL"     # Abort tool call immediately
    PASS_THROUGH = "PASS_THROUGH" # Explicitly allow untouched


STRICT_BLOCKED_CREDENTIALS = {
    PIIType.PIN,
    PIIType.CVV,
    PIIType.OTP,
    PIIType.PASSWORD,
    PIIType.PRIVATE_KEY,
    PIIType.DATABASE_CREDENTIAL,
}


@dataclass
class ToolPolicyRule:
    """Policy rule defined for a specific tool or globally."""
    tool_name: str  # "*" matches all tools
    pii_actions: Dict[Union[PIIType, str], PolicyAction] = field(default_factory=dict)
    blocked_pii_types: Set[Union[PIIType, str]] = field(default_factory=set)
    whitelisted_fields: Set[str] = field(default_factory=set)
    approved_categories: Set[SensitivityCategory] = field(
        default_factory=lambda: {SensitivityCategory.PERSONAL_INFO}
    )
    allowed_credential_exceptions: Set[Union[PIIType, str]] = field(default_factory=set)
    is_external_destination: bool = True


def generate_masked_value(value: str, pii_type: Union[PIIType, str]) -> str:
    """
    Generates a privacy-preserving partially masked representation.
    Credentials are NEVER partially leaked—they are always redacted safely!
    """
    category = TYPE_TO_CATEGORY.get(pii_type, SensitivityCategory.PERSONAL_INFO)

    # Mandatory Principle A: Never reveal raw characters/digits of credentials in previews or logs!
    if category == SensitivityCategory.CREDENTIAL:
        return "[REDACTED_CREDENTIAL]"

    # Business Confidential
    if category == SensitivityCategory.BUSINESS_CONFIDENTIAL:
        if pii_type == PIIType.CONFIDENTIAL_SOURCE_CODE:
            return "[SOURCE_CODE_REDACTED]"
        elif pii_type == PIIType.INTERNAL_SYSTEM_INSTRUCTIONS:
            return "[SYSTEM_INSTRUCTION_REDACTED]"
        elif pii_type == PIIType.CUSTOMER_DATABASE:
            return "[DATABASE_DUMP_BLOCKED]"
        elif pii_type == PIIType.EMPLOYEE_RECORDS:
            return "[EMPLOYEE_RECORDS_REDACTED]"
        return "[BUSINESS_CONFIDENTIAL_REDACTED]"

    # Personal Information
    if pii_type == PIIType.EMAIL:
        if "@" in value:
            user, domain = value.split("@", 1)
            masked_user = (user[0] + "***" + user[-1]) if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        return "***@***.***"

    elif pii_type == PIIType.PHONE:
        digits = [c for c in value if c.isdigit()]
        if len(digits) >= 4:
            return f"***-***-{value[-4:]}"
        return "***-***-****"

    elif pii_type == PIIType.CREDIT_CARD:
        return f"****-****-****-{value[-4:]}"

    elif pii_type == PIIType.SSN:
        return f"***-**-{value[-4:]}"

    elif pii_type == PIIType.AADHAAR:
        return f"XXXX-XXXX-{value[-4:]}"

    elif pii_type == PIIType.PAN_CARD:
        return f"{value[:2]}***{value[-2:]}"

    elif pii_type == PIIType.PASSPORT:
        return f"{value[:2]}*****{value[-2:]}" if len(value) >= 4 else "[REDACTED_PASSPORT]"

    elif pii_type == PIIType.BANK_ACCOUNT:
        return f"******{value[-4:]}" if len(value) >= 4 else "[REDACTED_ACCOUNT]"

    elif pii_type == PIIType.DATE_OF_BIRTH:
        if len(value) >= 8 and ("-" in value or "/" in value or "." in value):
            parts = re.split(r"[-/.]", value)
            if len(parts) == 3:
                if len(parts[0]) == 4:
                    return f"****-**-{parts[2]}"
                elif len(parts[2]) == 4:
                    return f"{parts[0]}-**-****"
        return "[DOB_REDACTED]"

    elif pii_type == PIIType.PERSON_NAME:
        parts = value.split()
        if parts:
            masked_parts = [f"{p[0]}***" if len(p) > 1 else p for p in parts]
            return " ".join(masked_parts)
        return "[NAME_REDACTED]"

    elif pii_type == PIIType.DRIVERS_LICENSE:
        if len(value) >= 6:
            return f"{value[:3]}*****{value[-3:]}"
        return "[DL_REDACTED]"

    elif pii_type == PIIType.SALARY_INFO:
        return "[SALARY_REDACTED]"

    elif pii_type == PIIType.MEDICAL_DIAGNOSIS:
        return "[HEALTH_RECORD_REDACTED]"

    elif pii_type == PIIType.BIOMETRIC_TEMPLATE:
        return "[BIOMETRIC_REDACTED]"

    elif pii_type == PIIType.HOME_ADDRESS:
        return "[ADDRESS_REDACTED]"

    elif pii_type == PIIType.IP_ADDRESS:
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return "*.*.*.*"

    type_val = pii_type.value if hasattr(pii_type, "value") else str(pii_type)
    return f"[{type_val}_MASKED]"


class PolicyEngine:
    """
    Evaluates rules and determines appropriate privacy action for each detected entity
    enforcing Credentials Block by Default and Destination-Aware controls.
    """

    def __init__(
        self,
        default_action: PolicyAction = PolicyAction.TOKENIZE,
        destination_allowlists: Optional[Dict[SensitivityCategory, Set[str]]] = None,
        block_credentials_by_default: bool = True,
    ):
        self.default_action = default_action
        self.block_credentials_by_default = block_credentials_by_default
        self._tool_policies: Dict[str, ToolPolicyRule] = {}
        
        # Principle C & A: Authorized destinations per category
        self.destination_allowlists = destination_allowlists or {
            SensitivityCategory.BUSINESS_CONFIDENTIAL: {
                "internal_git_repo",
                "secure_vault",
                "approved_internal_storage",
                "enterprise_compliance_archive",
                "internal_code_analyzer",
            },
            SensitivityCategory.CREDENTIAL: {
                "internal_kms",
                "vault_service",
                "authorized_auth_gateway",
            },
            SensitivityCategory.PERSONAL_INFO: {"*"},
        }

    def add_rule(self, rule: ToolPolicyRule) -> None:
        self._tool_policies[rule.tool_name] = rule

    def authorize_destination_for_category(
        self,
        category: SensitivityCategory,
        tool_name: str,
    ) -> None:
        """Explicitly authorize a destination tool for a sensitivity category."""
        if category not in self.destination_allowlists:
            self.destination_allowlists[category] = set()
        self.destination_allowlists[category].add(tool_name)

    def is_destination_authorized(
        self,
        category: SensitivityCategory,
        tool_name: str,
    ) -> bool:
        """Checks if tool destination is approved to receive category."""
        allowed_set = self.destination_allowlists.get(category, set())
        if "*" in allowed_set:
            return True
        return tool_name in allowed_set

    def get_action_for_entity(
        self,
        tool_name: str,
        pii_type: Union[PIIType, str],
        field_name: Optional[str] = None,
        category: Optional[SensitivityCategory] = None,
    ) -> PolicyAction:
        """Determines the action for a given tool, field, category, and PII type."""
        # 0. Resolve category
        actual_category = category or TYPE_TO_CATEGORY.get(pii_type, SensitivityCategory.PERSONAL_INFO)

        # 1. Check exact tool policy rule
        rule = self._tool_policies.get(tool_name) or self._tool_policies.get("*")

        # Check field whitelist
        if rule and field_name and field_name in rule.whitelisted_fields:
            return PolicyAction.PASS_THROUGH

        # Check if type is explicitly blocked for this tool
        if rule and pii_type in rule.blocked_pii_types:
            return PolicyAction.BLOCK_TOOL

        # 2. Principle A: Credentials — Block by default across unauthorized boundaries
        if actual_category == SensitivityCategory.CREDENTIAL:
            # Check for specifically approved exception workflow
            if rule and pii_type in rule.allowed_credential_exceptions:
                return rule.pii_actions.get(pii_type, PolicyAction.REDACT)

            # Check if destination is an authorized credential gateway
            if self.is_destination_authorized(SensitivityCategory.CREDENTIAL, tool_name):
                return rule.pii_actions.get(pii_type, self.default_action) if rule else self.default_action

            # Strict credentials (PIN, CVV, OTP, Password, Private Key, DB Credential) ALWAYS block
            if pii_type in STRICT_BLOCKED_CREDENTIALS:
                return PolicyAction.BLOCK_TOOL

            # For other credentials (e.g. API keys, access tokens) on external destinations
            if tool_name != "*" or self.block_credentials_by_default:
                if not rule or pii_type not in rule.pii_actions:
                    if tool_name != "*":
                        return PolicyAction.BLOCK_TOOL

        # 3. Principle C: Confidential Business Information — Destination-Aware Controls
        if actual_category == SensitivityCategory.BUSINESS_CONFIDENTIAL:
            # Check destination authorization
            if not self.is_destination_authorized(SensitivityCategory.BUSINESS_CONFIDENTIAL, tool_name):
                return PolicyAction.BLOCK_TOOL
            if rule and pii_type in rule.pii_actions:
                return rule.pii_actions[pii_type]
            return self.default_action

        # 4. Principle B: Personal Information — Policy-Based Action
        if rule and pii_type in rule.pii_actions:
            return rule.pii_actions[pii_type]

        return self.default_action
