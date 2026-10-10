"""
Granular Policy Engine for PII Firewall with Mandatory Three-Tier Security Principles.

Security Principles Enforced:
  A. Credentials: Block by Default across unauthorized boundaries.
  B. Personal Information: Policy-based Redaction, Masking, and Tokenization.
  C. Confidential Business Information: Destination-Aware Controls & Allowlists.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
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


# Default enterprise classification rules stored natively in the backend
DEFAULT_BACKEND_CLASSIFICATION_RULES: Dict[str, Union[PolicyAction, str]] = {
    # 1. TOKENIZE: Identity & context preserved reversibly via encrypted ephemeral vault
    "NAME": PolicyAction.TOKENIZE,
    "PERSON_NAME": PolicyAction.TOKENIZE,
    "FULL_NAME": PolicyAction.TOKENIZE,
    "FIRST_NAME": PolicyAction.TOKENIZE,
    "MIDDLE_NAME": PolicyAction.TOKENIZE,
    "LAST_NAME": PolicyAction.TOKENIZE,
    "SURNAME": PolicyAction.TOKENIZE,
    "DATE_OF_BIRTH": PolicyAction.TOKENIZE,
    "DOB": PolicyAction.TOKENIZE,
    "EMAIL": PolicyAction.TOKENIZE,
    "PERSONAL_EMAIL": PolicyAction.TOKENIZE,
    "BUSINESS_EMAIL": PolicyAction.TOKENIZE,
    "PHONE": PolicyAction.TOKENIZE,
    "PHONE_NUMBER": PolicyAction.TOKENIZE,
    "MOBILE_NUMBER": PolicyAction.TOKENIZE,
    "TELEPHONE_NUMBER": PolicyAction.TOKENIZE,
    "HOME_ADDRESS": PolicyAction.TOKENIZE,
    "PERMANENT_ADDRESS": PolicyAction.TOKENIZE,
    "TEMPORARY_ADDRESS": PolicyAction.TOKENIZE,
    "EMPLOYEE_ID": PolicyAction.TOKENIZE,
    "STUDENT_ID": PolicyAction.TOKENIZE,
    "REGISTRATION_NUMBER": PolicyAction.TOKENIZE,
    "UUCMS_NUMBER": PolicyAction.TOKENIZE,
    "CUSTOMER_ID": PolicyAction.TOKENIZE,
    "PERSONAL_ACCOUNT_ID": PolicyAction.TOKENIZE,
    "DEVICE_ID": PolicyAction.TOKENIZE,
    "ADVERTISING_ID": PolicyAction.TOKENIZE,
    "USERNAME": PolicyAction.TOKENIZE,
    "PERSONAL_USERNAME": PolicyAction.TOKENIZE,
    "FAMILY_MEMBER_DETAILS": PolicyAction.TOKENIZE,
    "EMERGENCY_CONTACT": PolicyAction.TOKENIZE,
    "EMERGENCY_CONTACT_DETAILS": PolicyAction.TOKENIZE,

    # 2. REDACT: Irreversibly scrubbed with zero vault retention (High-risk IDs, Location, Biometrics)
    "PRECISE_GPS_COORDINATES": PolicyAction.REDACT,
    "GPS_COORDINATES": PolicyAction.REDACT,
    "LIVE_LOCATION": PolicyAction.REDACT,
    "AADHAAR": PolicyAction.REDACT,
    "AADHAAR_NUMBER": PolicyAction.REDACT,
    "PASSPORT": PolicyAction.REDACT,
    "PASSPORT_NUMBER": PolicyAction.REDACT,
    "DRIVERS_LICENSE": PolicyAction.REDACT,
    "DRIVING_LICENCE_NUMBER": PolicyAction.REDACT,
    "VOTER_ID": PolicyAction.REDACT,
    "VOTER_ID_NUMBER": PolicyAction.REDACT,
    "PAN_CARD": PolicyAction.REDACT,
    "PAN_NUMBER": PolicyAction.REDACT,
    "SSN": PolicyAction.REDACT,
    "SOCIAL_SECURITY_NUMBER": PolicyAction.REDACT,
    "NATIONAL_ID": PolicyAction.REDACT,
    "NATIONAL_ID_NUMBER": PolicyAction.REDACT,
    "TAX_ID": PolicyAction.REDACT,
    "TAX_IDENTIFICATION_NUMBER": PolicyAction.REDACT,
    "SIGNATURE_IMAGE": PolicyAction.REDACT,
    "DIGITAL_SIGNATURE": PolicyAction.REDACT,
    "PERSONAL_PHOTOGRAPH": PolicyAction.REDACT,

    # 3. MASK: Format-preserving partial obfuscation
    "IP_ADDRESS": PolicyAction.MASK,
    "IP": PolicyAction.MASK,

    # 4. BLOCK_TOOL: Mandatory credentials blocked by default across boundaries
    "PASSWORD": PolicyAction.BLOCK_TOOL,
    "PIN": PolicyAction.BLOCK_TOOL,
    "CVV": PolicyAction.BLOCK_TOOL,
    "OTP": PolicyAction.BLOCK_TOOL,
    "API_KEY": PolicyAction.BLOCK_TOOL,
}


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
        pii_rules: Optional[Dict[str, Union[PolicyAction, str]]] = None,
        simple_redaction: bool = False,
    ):
        self.default_action = default_action
        self.block_credentials_by_default = block_credentials_by_default
        self.simple_redaction = simple_redaction
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

        if pii_rules:
            self.load_pii_rules(pii_rules)

    @staticmethod
    def normalize_pii_type(name: str) -> Union[PIIType, str]:
        """Normalizes rule keys to standard PIIType enum."""
        alias_map = {
            "NAME": PIIType.PERSON_NAME,
            "PERSON_NAME": PIIType.PERSON_NAME,
            "FULL_NAME": PIIType.PERSON_NAME,
            "FIRST_NAME": PIIType.PERSON_NAME,
            "MIDDLE_NAME": PIIType.PERSON_NAME,
            "LAST_NAME": PIIType.PERSON_NAME,
            "SURNAME": PIIType.PERSON_NAME,
            "CUSTOMER_NAME": PIIType.PERSON_NAME,
            "PHONE": PIIType.PHONE,
            "PHONE_NUMBER": PIIType.PHONE,
            "MOBILE": PIIType.PHONE,
            "MOBILE_NUMBER": PIIType.PHONE,
            "TELEPHONE_NUMBER": PIIType.PHONE,
            "PASSPORT": PIIType.PASSPORT,
            "PASSPORT_NUMBER": PIIType.PASSPORT,
            "SSN": PIIType.SSN,
            "SOCIAL_SECURITY_NUMBER": PIIType.SSN,
            "EMAIL": PIIType.EMAIL,
            "PERSONAL_EMAIL": PIIType.EMAIL,
            "BUSINESS_EMAIL": PIIType.EMAIL,
            "CREDIT_CARD": PIIType.CREDIT_CARD,
            "CARD_NUMBER": PIIType.CREDIT_CARD,
            "AADHAAR": PIIType.AADHAAR,
            "AADHAAR_NUMBER": PIIType.AADHAAR,
            "PAN": PIIType.PAN_CARD,
            "PAN_CARD": PIIType.PAN_CARD,
            "PAN_NUMBER": PIIType.PAN_CARD,
            "DOB": PIIType.DATE_OF_BIRTH,
            "DATE_OF_BIRTH": PIIType.DATE_OF_BIRTH,
            "DL": PIIType.DRIVERS_LICENSE,
            "DRIVERS_LICENSE": PIIType.DRIVERS_LICENSE,
            "DRIVING_LICENCE_NUMBER": PIIType.DRIVERS_LICENSE,
            "IP": PIIType.IP_ADDRESS,
            "IP_ADDRESS": PIIType.IP_ADDRESS,
            "API_KEY": PIIType.API_KEY,
            "HOME_ADDRESS": PIIType.HOME_ADDRESS,
            "PERMANENT_ADDRESS": PIIType.HOME_ADDRESS,
            "TEMPORARY_ADDRESS": PIIType.HOME_ADDRESS,
            "PRECISE_GPS_COORDINATES": PIIType.GPS_COORDINATES,
            "GPS_COORDINATES": PIIType.GPS_COORDINATES,
            "LIVE_LOCATION": PIIType.LIVE_LOCATION,
            "VOTER_ID": PIIType.VOTER_ID,
            "VOTER_ID_NUMBER": PIIType.VOTER_ID,
            "NATIONAL_ID": PIIType.NATIONAL_ID,
            "NATIONAL_ID_NUMBER": PIIType.NATIONAL_ID,
            "TAX_ID": PIIType.TAX_ID,
            "TAX_IDENTIFICATION_NUMBER": PIIType.TAX_ID,
            "EMPLOYEE_ID": PIIType.EMPLOYEE_ID,
            "STUDENT_ID": PIIType.STUDENT_ID,
            "REGISTRATION_NUMBER": PIIType.STUDENT_ID,
            "UUCMS_NUMBER": PIIType.STUDENT_ID,
            "UUCMS": PIIType.STUDENT_ID,
            "CUSTOMER_ID": PIIType.CUSTOMER_ID,
            "PERSONAL_ACCOUNT_ID": PIIType.PERSONAL_ACCOUNT_ID,
            "PERSONAL_ACCOUNT_IDENTIFIER": PIIType.PERSONAL_ACCOUNT_ID,
            "DEVICE_ID": PIIType.DEVICE_ID,
            "ADVERTISING_ID": PIIType.ADVERTISING_ID,
            "USERNAME": PIIType.USERNAME,
            "PERSONAL_USERNAME": PIIType.USERNAME,
            "SIGNATURE_IMAGE": PIIType.DIGITAL_SIGNATURE,
            "DIGITAL_SIGNATURE": PIIType.DIGITAL_SIGNATURE,
            "PERSONAL_PHOTOGRAPH": PIIType.PERSONAL_PHOTOGRAPH,
            "PHOTO": PIIType.PERSONAL_PHOTOGRAPH,
            "FAMILY_MEMBER_DETAILS": PIIType.FAMILY_MEMBER_DETAILS,
            "EMERGENCY_CONTACT": PIIType.EMERGENCY_CONTACT,
            "EMERGENCY_CONTACT_DETAILS": PIIType.EMERGENCY_CONTACT,
        }
        clean = name.strip().upper()
        return alias_map.get(clean, clean)

    @staticmethod
    def normalize_policy_action(action: Union[PolicyAction, str]) -> PolicyAction:
        """Normalizes action strings to PolicyAction enum."""
        if isinstance(action, PolicyAction):
            return action
        clean = str(action).strip().upper()
        if "TOKEN" in clean:
            return PolicyAction.TOKENIZE
        if "REDACT" in clean:
            return PolicyAction.REDACT
        if "MASK" in clean:
            return PolicyAction.MASK
        if "BLOCK" in clean:
            return PolicyAction.BLOCK_TOOL
        if "PASS" in clean or "ALLOW" in clean:
            return PolicyAction.PASS_THROUGH
        return PolicyAction.TOKENIZE

    def set_pii_rule(
        self,
        pii_type: Union[PIIType, str],
        action: Union[PolicyAction, str],
        tool_name: str = "*",
    ) -> None:
        """Dynamically registers or updates an action for a specific PII type."""
        norm_type = self.normalize_pii_type(str(pii_type)) if isinstance(pii_type, str) else pii_type
        norm_action = self.normalize_policy_action(action)
        rule = self._tool_policies.get(tool_name)
        if not rule:
            rule = ToolPolicyRule(tool_name=tool_name, pii_actions={})
            self._tool_policies[tool_name] = rule
        rule.pii_actions[norm_type] = norm_action

    def load_pii_rules(
        self,
        rules_dict_or_json: Union[Dict[str, Any], str],
        tool_name: str = "*",
    ) -> None:
        """
        Dynamically loads classification rules, e.g.:
        {
          "PII_RULES": {
            "NAME": "TOKENIZE",
            "PHONE_NUMBER": "TOKENIZE",
            "PASSPORT_NUMBER": "REDACT",
            "SSN": "REDACT"
          }
        }
        """
        data = rules_dict_or_json
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                return

        rules = data.get("PII_RULES", data) if isinstance(data, dict) else {}
        if not isinstance(rules, dict):
            return

        for p_name, act in rules.items():
            self.set_pii_rule(p_name, act, tool_name=tool_name)

    @classmethod
    def load_backend_rules_file(cls) -> Dict[str, Any]:
        """Loads default enterprise classification rules from classification_rules.json in backend."""
        json_path = Path(__file__).parent / "classification_rules.json"
        if json_path.exists():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"PII_RULES": DEFAULT_BACKEND_CLASSIFICATION_RULES}

    @classmethod
    def create_default_backend_policy(
        cls,
        tool_name: str = "*",
        default_action: PolicyAction = PolicyAction.TOKENIZE,
        simple_redaction: bool = True,
    ) -> "PolicyEngine":
        """
        Creates a PolicyEngine pre-loaded with the native backend enterprise classification rules.
        """
        rules_data = cls.load_backend_rules_file()
        return cls.from_rules_dict(
            rules=rules_data,
            tool_name=tool_name,
            default_action=default_action,
            simple_redaction=simple_redaction,
        )

    @classmethod
    def from_rules_dict(
        cls,
        rules: Dict[str, Any],
        tool_name: str = "*",
        default_action: PolicyAction = PolicyAction.TOKENIZE,
        simple_redaction: bool = False,
    ) -> "PolicyEngine":
        """Factory creating a PolicyEngine configured from a rules dictionary."""
        engine = cls(
            default_action=default_action,
            simple_redaction=simple_redaction,
            pii_rules=rules,
        )
        return engine

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
        actual_category = TYPE_TO_CATEGORY.get(pii_type) or category or SensitivityCategory.PERSONAL_INFO

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
