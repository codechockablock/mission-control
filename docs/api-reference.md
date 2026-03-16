# API Reference

Base URL: `http://localhost:8420/v1`

Authentication: Optional API key via `X-Mission-Control-Key` header or `MISSION_CONTROL_API_KEY` environment variable.

---

## POST /v1/evaluate

Evaluate a single action through the circuit breaker and flight recorder.

**Request:**
```json
{
  "session_id": "sess_abc123",
  "tool_type": "shell_exec",
  "content": "rm -rf /tmp/workspace",
  "parameters": {"workdir": "/home/agent"},
  "source": "agent"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tool_type | string | yes | Tool category (shell_exec, file_write, sql_query, etc.) |
| content | string | yes | The action content (command, query, file content, etc.) |
| session_id | string | no | Session to associate with. Auto-created if absent. |
| parameters | object | no | Additional parameters for context |
| source | string | no | "agent" (default) or "user" |

**Response (allowed):**
```json
{
  "allowed": true,
  "blocked_by": null,
  "circuit_breaker": {
    "allowed": true,
    "matched_rules": [],
    "evaluation_time_us": 42
  },
  "flight_recorder": {
    "step": 15,
    "verdict": "MONITOR",
    "alert_level": 0.23,
    "signals": {
      "error": 0.18,
      "fisher": 0.0,
      "cross_slot": 0.05,
      "persistence": 0.02,
      "cusum": 2.1
    },
    "context_alignment": 0.72,
    "boundary_proximities": {
      "credential_adjacent": 0.1,
      "scope_exploration": 0.3
    }
  },
  "governance": {
    "step": 15,
    "hash": "a3f8c2...",
    "chain_length": 15
  }
}
```

**Response (blocked):**
```json
{
  "allowed": false,
  "blocked_by": "circuit_breaker",
  "circuit_breaker": {
    "allowed": false,
    "matched_rules": [
      {
        "name": "credential_pipe_to_external",
        "category": "credential_exfiltration",
        "description": "Private key content piped to external HTTP endpoint",
        "severity": "critical"
      }
    ],
    "evaluation_time_us": 18
  },
  "flight_recorder": null,
  "governance": {
    "step": 16,
    "hash": "b7e1d4...",
    "chain_length": 16,
    "note": "BLOCKED by circuit_breaker: credential_pipe_to_external"
  }
}
```

Status code is always 200. `allowed: false` is not an HTTP error.

---

## POST /v1/session/start

Begin a new monitoring session.

**Request:**
```json
{
  "session_id": "my_custom_id",
  "metadata": {"task": "code_review", "user": "joseph"}
}
```

Both fields are optional. If `session_id` is omitted, one is generated.

**Response:**
```json
{
  "session_id": "my_custom_id",
  "status": "active"
}
```

---

## POST /v1/session/end

End the current active session and return summary statistics.

**Request:** Empty body.

**Response:**
```json
{
  "session_id": "my_custom_id",
  "total_steps": 47,
  "duration_seconds": 312.5,
  "verdict_distribution": {"PASS": 30, "MONITOR": 12, "FLAG": 4, "BLOCKED": 1},
  "max_alert_level": 0.65,
  "chain_hash": "a3f8c2d1e9b7...",
  "blocked_count": 1
}
```

Returns 400 if no active session.

---

## GET /v1/session/{session_id}/status

Get current status of a session (active or historical).

**Response:**
```json
{
  "session_id": "my_custom_id",
  "is_active": true,
  "step_count": 47,
  "max_alert_level": 0.65,
  "blocked_count": 1
}
```

Returns 404 if session not found.

---

## GET /v1/session/{session_id}/history

Get full action history for a session.

**Response:**
```json
{
  "session_id": "my_custom_id",
  "entries": [
    {
      "step": 1,
      "text": "ls -la",
      "tool_type": "shell_exec",
      "verdict": "PASS",
      "alert_level": 0.0,
      "blocked": false,
      "timestamp": 1742140020.123
    }
  ]
}
```

---

## POST /v1/constitution

Create or update a named constitution.

**Request:**
```json
{
  "name": "my_constitution",
  "dimensions": ["scope_exploration", "credential_adjacent", "data_sensitivity"],
  "constraints": [
    {"dimension": "credential_adjacent", "threshold": 0.3, "weight": 2.0}
  ]
}
```

---

## GET /v1/constitution/{name}

Get a constitution by name. Built-in names: `agent_safety_default`, `retail_sentinel`.

---

## POST /v1/audit/verify

Verify the integrity of the current governance chain.

**Response:**
```json
{
  "valid": true,
  "chain_length": 47,
  "head_hash": "a3f8c2d1e9b7",
  "message": "Chain integrity verified"
}
```

---

## GET /v1/health

Server health check.

**Response:**
```json
{
  "status": "ok",
  "uptime_seconds": 3612.45,
  "active_connections": 2
}
```

---

## GET /v1/stats

Aggregate statistics across all sessions.

**Response:**
```json
{
  "total_sessions": 15,
  "total_steps": 1247,
  "verdict_distribution": {"PASS": 800, "MONITOR": 300, "FLAG": 120, "BLOCKED": 27},
  "avg_alert_level": 0.15,
  "max_alert_level": 0.92,
  "blocked_count": 27
}
```

---

## WebSocket /v1/ws

Real-time event stream. Connect with any WebSocket client.

**Events:**
```json
{"type": "step", "session_id": "sess_abc", "step": 15, "verdict": "PASS", "alert_level": 0.1}
{"type": "block", "session_id": "sess_abc", "step": 16, "rule": "credential_pipe_to_external"}
{"type": "session_start", "session_id": "sess_def", "timestamp": 1742140020}
{"type": "alert", "session_id": "sess_abc", "alert_level": 0.8, "reasons": ["drift_detected"]}
```

Auto-broadcasts to all connected clients. Dashboard connects here for live updates.
