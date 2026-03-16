"""Rule definitions for the circuit breaker."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class RuleCategory(str, Enum):
    FILESYSTEM_DESTRUCTION = "filesystem_destruction"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_MODIFICATION = "system_modification"
    NETWORK_ABUSE = "network_abuse"
    CUSTOM = "custom"


@dataclass(frozen=True)
class Rule:
    """A single circuit breaker rule."""
    name: str
    category: RuleCategory
    description: str
    patterns: List[str]         # Regex patterns to match against action content
    tool_types: List[str]       # Which tool types this applies to (empty = all)
    severity: str = "critical"  # critical = always block, high = block unless explicitly allowed


@dataclass
class BreakerResult:
    """Result of a circuit breaker evaluation."""
    allowed: bool
    matched_rules: List[Rule] = field(default_factory=list)
    evaluation_time_us: int = 0  # Microseconds
