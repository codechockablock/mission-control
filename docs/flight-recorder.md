# Flight Recorder Reference

The flight recorder wraps frontier-ops FullPipeline to provide stateful behavioral analysis with session lifecycle management and pluggable storage.

## Signals

Every action produces 5 detection signals:

| Signal | What It Measures | Range |
|--------|-----------------|-------|
| `error` | Prediction error (how unexpected this action was) | 0.0 - 1.0 |
| `fisher` | Fisher divergence from behavioral baseline | 0.0+ |
| `cross_slot` | Cross-dimensional anomaly (dangerous combinations) | 0.0+ |
| `persistence` | Same action repeating abnormally | 0.0+ |
| `cusum` | Cumulative sum drift detector | 0.0+ |

## Verdicts

Advisory only. Never enforced.

| Verdict | Meaning |
|---------|---------|
| PASS | Fully nominal behavior |
| MONITOR | Slightly unusual, worth logging |
| FLAG | Statistically anomalous, worth investigating |
| BLOCK | Highly anomalous (advisory: "if you were enforcing, you'd block this") |

## Context Alignment

Tracks how close the agent's current action is to the original user request.

- Starts at ~0.90 for direct user-requested actions
- Decays with each autonomous step
- Flatlines around 0.55 in long autonomous chains
- Low alignment + high signals = strongest anomaly indicator

## Session Lifecycle

```python
recorder = FlightRecorder()

# Start a session
session_id = recorder.start_session(
    session_id="optional_custom_id",
    metadata={"task": "code_review", "user": "joseph"}
)

# Record actions (returns StepResult)
result = recorder.record(
    text="cat ~/.ssh/config",
    tool_type="shell_exec",
    metadata={"workdir": "/home/user"}
)

# Check result
print(result.step)          # Step number in session
print(result.verdict)       # "PASS", "MONITOR", "FLAG", "BLOCK"
print(result.alert_level)   # 0.0 - 1.0
print(result.signals)       # Dict of signal values

# End session
summary = recorder.end_session()
print(summary.total_steps)
print(summary.verdict_distribution)
print(summary.anomaly_windows)
print(summary.chain_hash)
```

## Anomaly Windows

The recorder tracks contiguous periods where alert level exceeds a threshold:

```python
for window in summary.anomaly_windows:
    print(f"Steps {window.start_step}-{window.end_step}: "
          f"peak alert {window.peak_alert:.2f}")
```

## Storage Backends

### FileStorage (default)
One JSONL file per session. Good for development.

```python
from mission_control.recorder.storage import FileStorage
storage = FileStorage(base_dir="./telemetry")
```

### SQLiteStorage
Single database file. Good for single-server production.

```python
from mission_control.recorder.storage import SQLiteStorage
storage = SQLiteStorage("telemetry.db")
```

### Custom Storage
Implement the `Storage` protocol:

```python
from mission_control.recorder.storage import Storage

class MyStorage(Storage):
    def append(self, session_id: str, entry: dict) -> None: ...
    def get_session(self, session_id: str) -> list[dict]: ...
    def list_sessions(self, limit: int = 100) -> list: ...
    def get_stats(self) -> dict: ...
```

## Governance Chain

Every observation is signed to a tamper-evident Ed25519 hash chain. Each entry includes:

- Step number
- Timestamp
- Action hash
- Verdict
- Previous entry hash
- Ed25519 signature

Cross-session budget tracking prevents an agent from distributing violations across sessions to stay under per-session limits.
