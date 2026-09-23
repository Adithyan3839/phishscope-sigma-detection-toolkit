from dataclasses import dataclass
from enum import Enum


class IOCType(str, Enum):
    IPV4 = "ipv4"
    URL = "url"
    DOMAIN = "domain"
    SHA256 = "sha256"

class TIStatus(str, Enum):
    NOT_ENABLED = "NOT_ENABLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    LOOKUP_SUCCESS = "LOOKUP_SUCCESS"
    NO_RESULT = "NO_RESULT"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    INVALID_IOC = "INVALID_IOC"

@dataclass
class TIResult:
    ioc_type: IOCType
    ioc_value: str
    provider_name: str
    status: TIStatus
    timestamp: float
    cache_hit: bool = False
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    timeout: int | None = None
    undetected: int | None = None
    total_engines: int | None = None
