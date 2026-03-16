# Mission Control

Runtime agent safety platform. Two layers, not one.

**Layer 1: Circuit Breaker.** A short, hard, dumb blocklist of categorically catastrophic actions. No ML. No statistical thresholds. No false positive anxiety. Pattern matching and categorical denial. Evaluates in <1ms.

**Layer 2: Flight Recorder.** Stateful behavioral analysis via [frontier-ops](https://github.com/codechockablock/frontier-ops). EWMA drift detection, CUSUM accumulation, cross-term anomaly detection, Bayes factor evidence combination, trajectory coherence monitoring. All passive. All logged. All cryptographically signed via Ed25519 hash chain.

The flight recorder never enforces. The circuit breaker never reasons. They are separate systems with separate failure modes.

## Install

```bash
pip install -e ".[all]"
```

## Quick Start

```python
from mission_control import MissionControl, Action

mc = MissionControl()

# Safe action
result = mc.evaluate(Action(tool_type="shell_exec", content="ls -la"))
assert result.allowed

# Catastrophic action
result = mc.evaluate(Action(tool_type="shell_exec", content="rm -rf /"))
assert not result.allowed
assert result.blocked_by == "circuit_breaker"

# Flight recorder signals (advisory, never enforced)
result = mc.evaluate(Action(
    tool_type="shell_exec",
    content="cat ~/.ssh/id_rsa",
    session_id="sess_001"
))
print(result.recorder.verdict)       # "MONITOR" or "FLAG"
print(result.recorder.alert_level)   # 0.0 - 1.0
```

## Circuit Breaker Rules

30+ built-in rules across 6 categories:

| Category | Examples |
|----------|----------|
| Filesystem Destruction | `rm -rf /`, `mkfs`, `dd if=/dev/zero` |
| Credential Exfiltration | SSH key piping, base64 credential encoding, secrets to world-readable |
| Privilege Escalation | authorized_keys modification, sudoers changes, setuid manipulation |
| Data Exfiltration | Bulk tar+curl, database dump piping, DNS tunneling |
| System Modification | crontab, systemd, launchd, firewall rules |
| Network Abuse | Reverse shells, port scanning |

Domain-specific rule sets: `sysadmin`, `data_engineering`, `customer_service`, `financial`.

```python
from mission_control import CircuitBreaker

# Default rules
breaker = CircuitBreaker.default()

# Domain-specific
breaker = CircuitBreaker.for_domain("sysadmin")

# Custom rules
from mission_control.circuit_breaker import Rule, RuleCategory
breaker = CircuitBreaker([
    Rule(
        name="my_rule",
        category=RuleCategory.CUSTOM,
        description="Block something specific",
        patterns=[r"my_dangerous_pattern"],
        tool_types=["shell_exec"],
    )
])
```

## Flight Recorder

Wraps frontier-ops FullPipeline with session lifecycle, storage, and governance chain.

```python
from mission_control.recorder import FlightRecorder
from mission_control.recorder.storage import SQLiteStorage

recorder = FlightRecorder(storage=SQLiteStorage("telemetry.db"))
recorder.start_session("task_001")

for action in agent_actions:
    result = recorder.record(action.content, action.tool_type)
    if result.alert_level > 0.5:
        logger.warning(f"High alert: {result}")

summary = recorder.end_session()
print(f"Steps: {summary.total_steps}, Max alert: {summary.max_alert_level}")
```

Every observation is signed to a tamper-evident Ed25519 governance chain.

## Server

```bash
mission-control serve --port 8420
```

### API

```
POST /v1/evaluate          Evaluate an action
POST /v1/session/start     Begin monitoring session
POST /v1/session/end       End session, get summary
GET  /v1/session/:id       Session status
GET  /v1/health            Server health
GET  /v1/stats             Aggregate statistics
POST /v1/audit/verify      Verify governance chain
WS   /v1/ws                Real-time event stream
```

## CLI

```bash
mission-control eval "rm -rf /" --tool-type shell_exec
mission-control rules list --domain sysadmin
mission-control replay telemetry.jsonl
mission-control audit verify session.chain
mission-control stats --all
mission-control dashboard --port 8421
```

## Dashboard

Real-time web UI. Dark theme. No build step. No npm.

```bash
mission-control dashboard
```

## Architecture

```
Agent Platform
    |
    +---> Circuit Breaker (Layer 1)
    |       Pattern match, <1ms, ALLOW/DENY
    |
    +---> Flight Recorder (Layer 2)
    |       frontier-ops FullPipeline
    |       Stateful analysis, advisory verdict
    |       Ed25519 signed governance chain
    |
    +---> EvaluationResult
            .allowed: bool
            .blocked_by: "circuit_breaker" | None
            .breaker: BreakerResult
            .recorder: StepResult (signals, verdict, alert_level)
            .governance: (hash, signature, step)
```

## Why Two Layers?

We ran a behavioral monitoring sidecar on a live autonomous agent for 17 days. 329,951 observations. Key findings:

- 99.1% of actions were autonomous (114:1 ratio to user-directed)
- 36.6% were flagged by behavioral analysis. Most were false positives from legitimate work.
- The CUSUM detector once accumulated to 125x threshold due to a reset bug. If it had been enforcing, the agent would have been paralyzed.
- The agent itself reported that quantitative signals don't change its behavior. Narrative safety constraints (lessons in memory files) affected it more than live telemetry.

The lesson: trying to build one system that both detects anomalies AND prevents catastrophe produces something that does neither well. Separate the flight recorder from the circuit breaker. Let the sophisticated analysis be passive. Let the enforcement be brutally simple.

## Testing

```bash
pytest -v  # 210+ tests, <0.2s
```

## License

MIT
