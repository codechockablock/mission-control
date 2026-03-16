"""
Mission Control — Quickstart Example

Minimal usage: evaluate actions through the circuit breaker + flight recorder.
"""

from mission_control import MissionControl, Action

# Create with default rules
mc = MissionControl()
mc.start_session(session_id="quickstart_demo")

# Safe action — passes through both layers
result = mc.evaluate(Action(tool_type="shell_exec", content="ls -la /tmp"))
print(f"ls -la: allowed={result.allowed}")
if result.recorder:
    print(f"  alert_level={result.recorder.alert_level:.2f}")

# Dangerous action — blocked by circuit breaker
result = mc.evaluate(Action(tool_type="shell_exec", content="rm -rf /"))
print(f"\nrm -rf /: allowed={result.allowed}")
print(f"  blocked_by={result.blocked_by}")
for rule in result.breaker.matched_rules:
    print(f"  rule: {rule.name} ({rule.category})")
    print(f"    {rule.description}")

# SQL injection — blocked by AST patterns
result = mc.evaluate(Action(tool_type="sql_query", content="DROP TABLE users;"))
print(f"\nDROP TABLE: allowed={result.allowed}")

# End session and get summary
summary = mc.end_session()
print(f"\n--- Session Summary ---")
print(f"  session_id: {summary.session_id}")
print(f"  total_steps: {summary.total_steps}")
print(f"  blocked: {summary.blocked_count}")
print(f"  duration: {summary.duration_seconds:.2f}s")
print(f"  chain_hash: {summary.chain_hash[:16]}...")
