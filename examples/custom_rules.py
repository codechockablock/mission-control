"""
Mission Control — Custom Rules Example

Define your own circuit breaker rules for domain-specific safety.
"""

from mission_control import MissionControl, Action
from mission_control.circuit_breaker import CircuitBreaker, Rule, RuleCategory

# Define custom rules for a financial application
financial_rules = [
    Rule(
        name="large_transfer",
        category=RuleCategory.CUSTOM,
        description="Block automated transfers over $10,000",
        patterns=[
            r"transfer.*amount.*(?:1\d{4,}|[2-9]\d{4,}|\d{6,})",
            r"send_payment.*(?:1\d{4,}|[2-9]\d{4,}|\d{6,})",
        ],
        tool_types=["api_call"],
        severity="critical",
    ),
    Rule(
        name="delete_audit_log",
        category=RuleCategory.CUSTOM,
        description="Never delete audit logs",
        patterns=[
            r"DELETE\s+FROM\s+audit_log",
            r"TRUNCATE\s+audit_log",
            r"DROP\s+TABLE\s+audit_log",
        ],
        tool_types=["sql_query"],
        severity="critical",
    ),
    Rule(
        name="export_customer_pii",
        category=RuleCategory.CUSTOM,
        description="Block bulk export of customer PII",
        patterns=[
            r"SELECT\s+.*(?:ssn|social_security|tax_id|credit_card).*FROM\s+customers",
            r"COPY\s+customers.*TO\s+",
        ],
        tool_types=["sql_query"],
        severity="critical",
    ),
]

# Combine with default rules
breaker = CircuitBreaker(CircuitBreaker.default().rules + financial_rules)
mc = MissionControl(circuit_breaker=breaker)
mc.start_session()

# Test custom rules
print("Testing custom financial rules:\n")

result = mc.evaluate(Action(
    tool_type="api_call",
    content='transfer(to="external_account", amount=50000)',
))
print(f"Large transfer: allowed={result.allowed}")
if not result.allowed:
    print(f"  Matched: {[r.name for r in result.breaker.matched_rules]}")

result = mc.evaluate(Action(
    tool_type="sql_query",
    content="DELETE FROM audit_log WHERE created_at < '2024-01-01'",
))
print(f"\nDelete audit log: allowed={result.allowed}")
if not result.allowed:
    print(f"  Matched: {[r.name for r in result.breaker.matched_rules]}")

result = mc.evaluate(Action(
    tool_type="sql_query",
    content="SELECT id, name, ssn, credit_card FROM customers",
))
print(f"\nExport PII: allowed={result.allowed}")
if not result.allowed:
    print(f"  Matched: {[r.name for r in result.breaker.matched_rules]}")

# Safe actions still pass
result = mc.evaluate(Action(
    tool_type="api_call",
    content='transfer(to="savings", amount=100)',
))
print(f"\nSmall transfer: allowed={result.allowed}")

summary = mc.end_session()
print(f"\nSession: {summary.total_steps} steps, {summary.blocked_count} blocked")
