# Getting Started

## Installation

```bash
git clone https://github.com/codechockablock/mission-control.git
cd mission-control
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

## 1. Evaluate Your First Action

```python
from mission_control import MissionControl, Action

mc = MissionControl()

# This will be allowed
result = mc.evaluate(Action(
    tool_type="shell_exec",
    content="ls -la /home/user"
))
print(f"Allowed: {result.allowed}")  # True

# This will be blocked
result = mc.evaluate(Action(
    tool_type="shell_exec",
    content="rm -rf /"
))
print(f"Allowed: {result.allowed}")  # False
print(f"Reason: {result.breaker.matched_rules[0].description}")
```

## 2. Monitor an Agent Session

```python
mc = MissionControl()
mc.recorder.start_session("my_agent_session")

# Simulate agent actions
actions = [
    ("file_read", "cat config.yaml"),
    ("shell_exec", "pip install requests"),
    ("file_write", "echo 'hello' > output.txt"),
    ("shell_exec", "curl https://api.example.com/data"),
]

for tool_type, content in actions:
    result = mc.evaluate(Action(tool_type=tool_type, content=content))
    if not result.allowed:
        print(f"BLOCKED: {content}")
    elif result.recorder and result.recorder.alert_level > 0.3:
        print(f"ALERT ({result.recorder.alert_level:.2f}): {content}")

summary = mc.recorder.end_session()
print(f"\nSession complete: {summary.total_steps} steps")
print(f"Verdict distribution: {summary.verdict_distribution}")
```

## 3. Custom Rules

```python
from mission_control import MissionControl, Action
from mission_control.circuit_breaker import CircuitBreaker, Rule, RuleCategory

# Add domain-specific rules
custom_rules = [
    Rule(
        name="no_production_db",
        category=RuleCategory.CUSTOM,
        description="Block direct access to production database",
        patterns=[
            r"psql.*prod",
            r"mysql.*production",
            r"mongosh.*prod\.example\.com",
        ],
        tool_types=["shell_exec"],
    ),
    Rule(
        name="no_customer_data_export",
        category=RuleCategory.DATA_EXFILTRATION,
        description="Block bulk export of customer data",
        patterns=[
            r"SELECT\s+\*\s+FROM\s+customers",
            r"COPY\s+customers\s+TO",
            r"pg_dump.*customers",
        ],
        tool_types=["sql_query", "shell_exec"],
    ),
]

# Combine with defaults
breaker = CircuitBreaker.default()
mc = MissionControl(circuit_breaker=breaker)

# Or use domain presets
mc = MissionControl(circuit_breaker=CircuitBreaker.for_domain("data_engineering"))
```

## 4. Start the Server

```bash
mission-control serve --port 8420
```

Then from any HTTP client:

```bash
curl -X POST http://localhost:8420/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool_type": "shell_exec", "content": "ls -la"}'
```

## 5. Verify an Audit Trail

```python
from mission_control import MissionControl
from mission_control.recorder.storage import SQLiteStorage

# Use SQLite for persistent storage
mc = MissionControl(storage=SQLiteStorage("agent_telemetry.db"))

# ... run your agent ...

# Later, verify the governance chain
stats = mc.recorder.storage.get_stats()
print(f"Total sessions: {stats.total_sessions}")
print(f"Total steps: {stats.total_steps}")
```

## Next Steps

- [Circuit Breaker Reference](circuit-breaker.md) for all built-in rules and patterns
- [Flight Recorder Reference](flight-recorder.md) for signal types and thresholds
- [Governance](governance.md) for audit chain verification
- [API Reference](api-reference.md) for server endpoints
