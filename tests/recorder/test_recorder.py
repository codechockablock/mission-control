"""Tests for FlightRecorder."""

import pytest
import tempfile
import os

from mission_control.recorder.recorder import FlightRecorder
from mission_control.recorder.storage import FileStorage


@pytest.fixture
def recorder(tmp_dir):
    storage = FileStorage(base_dir=os.path.join(tmp_dir, "sessions"))
    return FlightRecorder(storage=storage)


class TestFlightRecorder:
    def test_start_session(self, recorder):
        sid = recorder.start_session()
        assert sid.startswith("sess_")
        assert recorder.session is not None
        assert recorder.session.is_active

    def test_start_session_custom_id(self, recorder):
        sid = recorder.start_session(session_id="my_session")
        assert sid == "my_session"

    def test_record_step(self, recorder):
        recorder.start_session()
        result = recorder.record("ls -la", tool_type="shell_exec")
        assert result.step == 1
        assert hasattr(result, "alert_level")

    def test_auto_start_session(self, recorder):
        # Recording without starting session should auto-start
        result = recorder.record("echo hello")
        assert recorder.session is not None

    def test_multiple_steps(self, recorder):
        recorder.start_session()
        for i in range(3):
            result = recorder.record(f"step {i}")
        assert result.step == 3

    def test_end_session(self, recorder):
        recorder.start_session()
        recorder.record("step 1")
        recorder.record("step 2")
        summary = recorder.end_session()
        assert summary is not None
        assert summary.total_steps == 2
        assert summary.duration_seconds >= 0

    def test_governance_chain_integrity(self, recorder):
        recorder.start_session()
        for i in range(5):
            recorder.record(f"step {i}")
        assert recorder.verify_chain()

    def test_record_blocked(self, recorder):
        recorder.start_session()
        recorder.record_blocked("rm -rf /", rule_name="rm_rf_root", tool_type="shell_exec")
        assert recorder.session.step_count == 1

    def test_end_session_when_none(self, recorder):
        summary = recorder.end_session()
        assert summary is None

    def test_chain_hash_in_summary(self, recorder):
        recorder.start_session()
        recorder.record("test step")
        summary = recorder.end_session()
        assert summary.chain_hash != ""

    def test_new_session_resets_pipeline(self, recorder):
        recorder.start_session()
        recorder.record("step 1")
        recorder.end_session()
        recorder.start_session()
        result = recorder.record("step 1 again")
        assert result.step == 1
