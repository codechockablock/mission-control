# Governance Chain

The governance chain provides tamper-evident audit trails using Ed25519 cryptographic signatures in a hash chain.

## How It Works

Every action evaluated by Mission Control (both allowed and blocked) gets an entry in the governance chain:

```
Entry 0 (genesis)
  hash: sha256(content_0)
  signature: ed25519_sign(hash_0)

Entry 1
  hash: sha256(content_1 + hash_0)
  signature: ed25519_sign(hash_1)

Entry N
  hash: sha256(content_N + hash_{N-1})
  signature: ed25519_sign(hash_N)
```

Each entry's hash depends on all previous entries. Modifying any entry invalidates all subsequent hashes.

## What Gets Signed

Each governance entry contains:

```json
{
  "step": 15,
  "timestamp": 1742140020.123,
  "session_id": "sess_abc123",
  "action_hash": "sha256_of_action_content",
  "tool_type": "shell_exec",
  "verdict": "MONITOR",
  "alert_level": 0.23,
  "blocked": false,
  "blocked_by": null,
  "previous_hash": "hash_of_entry_14",
  "hash": "sha256_of_this_entry",
  "signature": "ed25519_signature"
}
```

## Blocked Actions

When the circuit breaker blocks an action, it still gets a governance entry:

```json
{
  "step": 16,
  "blocked": true,
  "blocked_by": "circuit_breaker",
  "blocked_rule": "credential_pipe_to_external",
  "verdict": null,
  "alert_level": null
}
```

This ensures the audit trail captures everything, including what was prevented.

## Verification

```bash
# CLI
mission-control audit verify session_abc.chain

# Python
from frontier_ops.governance.chain import GovernanceAuditor

auditor = GovernanceAuditor()
result = auditor.verify(chain)
print(f"Valid: {result.valid}")
print(f"Entries: {result.entry_count}")
print(f"Breaks: {result.breaks}")  # Empty if chain is intact
```

## Cross-Session Budget Tracking

A compromised agent might try to spread violations across multiple sessions to stay under per-session alert thresholds. The governance chain tracks cumulative budgets across sessions:

- Total flagged actions across all sessions
- Credential access frequency across sessions
- Network egress patterns across sessions

These cross-session metrics are available via the `get_stats()` method on any storage backend.

## Key Management

Ed25519 keys are generated at `FlightRecorder` initialization. For production deployments:

```python
from frontier_ops.governance.chain import GovernanceChain

# Generate and save a key
chain = GovernanceChain()
chain.save_key("mission_control.key")

# Load an existing key
chain = GovernanceChain.from_key("mission_control.key")
```

The public key should be shared with auditors. The private key should be kept secure and rotated periodically.
