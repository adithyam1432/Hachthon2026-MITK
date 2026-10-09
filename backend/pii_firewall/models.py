"""
Data structures, enums, and exceptions for PII Firewall.
Enhanced with Context-Aware NLP, Semantic Categories, and Mandatory Security Principles.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union


class SensitivityCategory(str, Enum):
    """
    Mandatory Three-Tier Security Classification Architecture:
    1. CREDENTIAL: Block by default across unauthorized boundaries.
    2. PERSONAL_INFO: Policy-based redaction, masking, and purpose-scoped tokenization.
    3. BUSINESS_CONFIDENTIAL: Destination-aware allowlists & confidentiality controls.
    """
    CREDENTIAL = "CREDENTIAL"
    PERSONAL_INFO = "PERSONAL_INFO"
    BUSINESS_CONFIDENTIAL = "BUSINESS_CONFIDENTIAL"


class PIIType(str, Enum):
    # Core Personal & Identity PII
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    PAN_CARD = "PAN_CARD"
    AADHAAR = "AADHAAR"
    PASSPORT = "PASSPORT"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PERSON_NAME = "PERSON_NAME"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    HOME_ADDRESS = "HOME_ADDRESS"
    MEDICAL_DIAGNOSIS = "MEDICAL_DIAGNOSIS"
    BIOMETRIC_TEMPLATE = "BIOMETRIC_TEMPLATE"
    SALARY_INFO = "SALARY_INFO"
    BANK_ACCOUNT = "BANK_ACCOUNT"

    # Credentials & Authentication Secrets (Block by Default)
    PASSWORD = "PASSWORD"
    PIN = "PIN"                          # Debit/ATM/UPI Card PIN
    CVV = "CVV"                          # Card verification value / security code
    OTP = "OTP"                          # One-time password / login code
    API_KEY = "API_KEY"                  # Cloud / Service API Keys
    ACCESS_TOKEN = "ACCESS_TOKEN"        # Bearer tokens, JWTs, OAuth tokens
    PRIVATE_KEY = "PRIVATE_KEY"          # RSA, SSH, PGP private signing keys
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL" # DB login, connection strings

    # Confidential Business Information (Destination-Aware Controls)
    CONFIDENTIAL_SOURCE_CODE = "CONFIDENTIAL_SOURCE_CODE"
    INTERNAL_SYSTEM_INSTRUCTIONS = "INTERNAL_SYSTEM_INSTRUCTIONS" # System prompts, hidden instructions
    CUSTOMER_DATABASE = "CUSTOMER_DATABASE"
    EMPLOYEE_RECORDS = "EMPLOYEE_RECORDS"
    SECURITY_CONFIG = "SECURITY_CONFIG"
    TRADE_SECRET = "TRADE_SECRET"


# Mapping from individual PII/Sensitive types to mandatory sensitivity categories
TYPE_TO_CATEGORY: Dict[Union[PIIType, str], SensitivityCategory] = {
    # 1. Credentials (Principle A: Block by default)
    PIIType.PASSWORD: SensitivityCategory.CREDENTIAL,
    PIIType.PIN: SensitivityCategory.CREDENTIAL,
    PIIType.CVV: SensitivityCategory.CREDENTIAL,
    PIIType.OTP: SensitivityCategory.CREDENTIAL,
    PIIType.API_KEY: SensitivityCategory.CREDENTIAL,
    PIIType.ACCESS_TOKEN: SensitivityCategory.CREDENTIAL,
    PIIType.PRIVATE_KEY: SensitivityCategory.CREDENTIAL,
    PIIType.DATABASE_CREDENTIAL: SensitivityCategory.CREDENTIAL,

    # 2. Personal Information (Principle B: Policy-based sanitization)
    PIIType.EMAIL: SensitivityCategory.PERSONAL_INFO,
    PIIType.PHONE: SensitivityCategory.PERSONAL_INFO,
    PIIType.SSN: SensitivityCategory.PERSONAL_INFO,
    PIIType.CREDIT_CARD: SensitivityCategory.PERSONAL_INFO,
    PIIType.IP_ADDRESS: SensitivityCategory.PERSONAL_INFO,
    PIIType.PAN_CARD: SensitivityCategory.PERSONAL_INFO,
    PIIType.AADHAAR: SensitivityCategory.PERSONAL_INFO,
    PIIType.PASSPORT: SensitivityCategory.PERSONAL_INFO,
    PIIType.DATE_OF_BIRTH: SensitivityCategory.PERSONAL_INFO,
    PIIType.PERSON_NAME: SensitivityCategory.PERSONAL_INFO,
    PIIType.DRIVERS_LICENSE: SensitivityCategory.PERSONAL_INFO,
    PIIType.HOME_ADDRESS: SensitivityCategory.PERSONAL_INFO,
    PIIType.MEDICAL_DIAGNOSIS: SensitivityCategory.PERSONAL_INFO,
    PIIType.BIOMETRIC_TEMPLATE: SensitivityCategory.PERSONAL_INFO,
    PIIType.SALARY_INFO: SensitivityCategory.PERSONAL_INFO,
    PIIType.BANK_ACCOUNT: SensitivityCategory.PERSONAL_INFO,

    # 3. Confidential Business Information (Principle C: Destination-aware controls)
    PIIType.CONFIDENTIAL_SOURCE_CODE: SensitivityCategory.BUSINESS_CONFIDENTIAL,
    PIIType.INTERNAL_SYSTEM_INSTRUCTIONS: SensitivityCategory.BUSINESS_CONFIDENTIAL,
    PIIType.CUSTOMER_DATABASE: SensitivityCategory.BUSINESS_CONFIDENTIAL,
    PIIType.EMPLOYEE_RECORDS: SensitivityCategory.BUSINESS_CONFIDENTIAL,
    PIIType.SECURITY_CONFIG: SensitivityCategory.BUSINESS_CONFIDENTIAL,
    PIIType.TRADE_SECRET: SensitivityCategory.BUSINESS_CONFIDENTIAL,
}


class FirewallException(Exception):
    """Base exception for PII Firewall."""
    pass


class PIILeakageDetectedError(FirewallException):
    """Raised when leakage verification fails (detected original PII found in sanitized payload)."""
    pass


class FirewallBlockedError(FirewallException):
    """Raised when firewall policy blocks execution."""
    pass


@dataclass(frozen=True)
class PIIEntity:
    """Represents a detected PII instance in text with contextual NLP metadata."""
    pii_type: Union[PIIType, str]
    start: int
    end: int
    value: str
    confidence: float = 1.0
    category: SensitivityCategory = SensitivityCategory.PERSONAL_INFO
    context_evidence: Optional[str] = None
    related_entity: Optional[str] = None
    has_exposed_value: bool = True


@dataclass
class FirewallConfig:
    """Configuration options for the PII Firewall."""
    enabled_types: Set[PIIType] = field(
        default_factory=lambda: set(PIIType)
    )
    allow_restoration: bool = True
    allowed_restoration_fields: Optional[List[str]] = None  # None = all fields allowed
    fail_safe_strict: bool = True  # Block request if verification fails or an unexpected error occurs
    token_format_prefix: str = "⟦"
    token_format_suffix: str = "⟧"
    enable_luhn_validation: bool = True  # For credit cards
    enable_verhoeff_validation: bool = True  # For Aadhaar cards
    enable_semantic_nlp: bool = True  # Context-aware NLP & semantic detection
    gemini_api_key: Optional[str] = None  # Google Gemini Free Tier API Key
    gemini_model: str = "gemini-3.5-flash-lite"  # Gemini Model (e.g. gemini-3.5-flash-lite)


@dataclass
class FirewallMetrics:
    """Observability metrics without exposing raw PII."""
    request_id: str
    counts_by_type: Dict[str, int] = field(default_factory=dict)
    total_detected: int = 0
    verification_passed: bool = False
    processing_time_ms: float = 0.0
    restored_count: int = 0
    restoration_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "counts_by_type": self.counts_by_type,
            "total_detected": self.total_detected,
            "verification_passed": self.verification_passed,
            "processing_time_ms": round(self.processing_time_ms, 3),
            "restored_count": self.restored_count,
            "restoration_time_ms": round(self.restoration_time_ms, 3),
        }


@dataclass
class FirewallResult:
    """Result of request inspection and sanitization."""
    request_id: str
    sanitized_payload: Any
    metrics: FirewallMetrics
    blocked: bool = False
    block_reason: Optional[str] = None
