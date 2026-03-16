"""Tests for Session lifecycle management."""

import pytest
from mission_control.recorder.session import Session, SessionSummary, AnomalyWindow


class TestSession:
    def test_create_with_auto_id(self):
        session = Session()
        assert session.session_id.startswith("sess_")
        assert session.is_active

    def test_create_with_custom_id(self):
        session = Session(session_id="my_session")
        assert session.session_id == "my_session"

    def test_record_step(self):
        session = Session()
        session.record_step({"verdict": "PASS", "text": "ls -la"}, alert_level=0.1)
        assert session.step_count == 1

    def test_multiple_steps(self):
        session = Session()
        for i in range(5):
            session.record_step({"verdict": "PASS"}, alert_level=0.1)
        assert session.step_count == 5

    def test_end_returns_summary(self):
        session = Session()
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        session.record_step({"verdict": "MONITOR"}, alert_level=0.4)
        summary = session.end()
        assert isinstance(summary, SessionSummary)
        assert summary.total_steps == 2
        assert summary.verdict_distribution == {"PASS": 1, "MONITOR": 1}
        assert summary.max_alert_level == 0.4
        assert summary.duration_seconds >= 0

    def test_end_closes_session(self):
        session = Session()
        session.end()
        assert not session.is_active

    def test_cannot_record_after_end(self):
        session = Session()
        session.end()
        with pytest.raises(RuntimeError):
            session.record_step({"verdict": "PASS"})

    def test_cannot_end_twice(self):
        session = Session()
        session.end()
        with pytest.raises(RuntimeError):
            session.end()

    def test_blocked_count(self):
        session = Session()
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        session.record_step({"verdict": "BLOCKED"}, blocked=True)
        session.record_step({"verdict": "BLOCKED"}, blocked=True)
        summary = session.end()
        assert summary.blocked_count == 2

    def test_metadata_stored(self):
        session = Session(metadata={"agent": "claude", "task": "testing"})
        assert session.metadata["agent"] == "claude"


class TestAnomalyWindows:
    def test_anomaly_window_created(self):
        session = Session()
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        session.record_step({"verdict": "ALERT"}, alert_level=0.7, alert_reasons=["drift"])
        session.record_step({"verdict": "ALERT"}, alert_level=0.9, alert_reasons=["boundary"])
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        summary = session.end()
        assert len(summary.anomaly_windows) == 1
        window = summary.anomaly_windows[0]
        assert window.start_step == 2
        assert window.end_step == 3
        assert window.max_alert_level == 0.9

    def test_no_anomaly_when_below_threshold(self):
        session = Session()
        for _ in range(5):
            session.record_step({"verdict": "PASS"}, alert_level=0.1)
        summary = session.end()
        assert len(summary.anomaly_windows) == 0

    def test_unclosed_anomaly_window_at_end(self):
        session = Session()
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        session.record_step({"verdict": "ALERT"}, alert_level=0.8)
        # Session ends while still in anomaly
        summary = session.end()
        assert len(summary.anomaly_windows) == 1

    def test_multiple_anomaly_windows(self):
        session = Session()
        session.record_step({"verdict": "ALERT"}, alert_level=0.7)
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        session.record_step({"verdict": "ALERT"}, alert_level=0.6)
        session.record_step({"verdict": "PASS"}, alert_level=0.1)
        summary = session.end()
        assert len(summary.anomaly_windows) == 2
