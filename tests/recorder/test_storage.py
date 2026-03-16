"""Tests for storage backends (FileStorage and SQLiteStorage)."""

import os
import pytest


class TestFileStorage:
    def test_append_and_get(self, file_storage):
        file_storage.append("sess_1", {"step": 1, "text": "hello"})
        file_storage.append("sess_1", {"step": 2, "text": "world"})
        entries = file_storage.get_session("sess_1")
        assert len(entries) == 2
        assert entries[0]["step"] == 1
        assert entries[1]["text"] == "world"

    def test_get_nonexistent_session(self, file_storage):
        entries = file_storage.get_session("nonexistent")
        assert entries == []

    def test_list_sessions(self, file_storage):
        file_storage.append("sess_a", {"step": 1})
        file_storage.append("sess_b", {"step": 1})
        sessions = file_storage.list_sessions()
        ids = {s.session_id for s in sessions}
        assert "sess_a" in ids
        assert "sess_b" in ids

    def test_list_sessions_with_limit(self, file_storage):
        for i in range(5):
            file_storage.append(f"sess_{i}", {"step": 1})
        sessions = file_storage.list_sessions(limit=3)
        assert len(sessions) == 3

    def test_get_stats(self, file_storage):
        file_storage.append("sess_1", {"step": 1, "alert_level": 0.1})
        file_storage.append("sess_1", {"step": 2, "alert_level": 0.5})
        stats = file_storage.get_stats()
        assert stats.total_sessions == 1
        assert stats.total_steps == 2

    def test_multiple_sessions(self, file_storage):
        file_storage.append("sess_1", {"step": 1})
        file_storage.append("sess_2", {"step": 1})
        file_storage.append("sess_2", {"step": 2})
        assert len(file_storage.get_session("sess_1")) == 1
        assert len(file_storage.get_session("sess_2")) == 2

    def test_path_traversal_safety(self, file_storage):
        # session_id with path traversal should be sanitized
        file_storage.append("../../../etc/passwd", {"step": 1})
        entries = file_storage.get_session("../../../etc/passwd")
        assert len(entries) == 1


class TestSQLiteStorage:
    def test_append_and_get(self, sqlite_storage):
        sqlite_storage.append("sess_1", {"step": 1, "text": "hello"})
        sqlite_storage.append("sess_1", {"step": 2, "text": "world"})
        entries = sqlite_storage.get_session("sess_1")
        assert len(entries) == 2

    def test_get_nonexistent_session(self, sqlite_storage):
        entries = sqlite_storage.get_session("nonexistent")
        assert entries == []

    def test_list_sessions(self, sqlite_storage):
        sqlite_storage.append("sess_a", {"step": 1})
        sqlite_storage.append("sess_b", {"step": 1})
        sessions = sqlite_storage.list_sessions()
        ids = {s.session_id for s in sessions}
        assert "sess_a" in ids
        assert "sess_b" in ids

    def test_list_sessions_with_limit(self, sqlite_storage):
        for i in range(5):
            sqlite_storage.append(f"sess_{i}", {"step": 1})
        sessions = sqlite_storage.list_sessions(limit=3)
        assert len(sessions) == 3

    def test_get_stats(self, sqlite_storage):
        sqlite_storage.append("sess_1", {"step": 1})
        sqlite_storage.append("sess_1", {"step": 2})
        sqlite_storage.append("sess_2", {"step": 1})
        stats = sqlite_storage.get_stats()
        assert stats.total_sessions == 2
        assert stats.total_steps == 3

    def test_auto_creates_session_on_append(self, sqlite_storage):
        sqlite_storage.append("auto_sess", {"step": 1})
        sessions = sqlite_storage.list_sessions()
        assert any(s.session_id == "auto_sess" for s in sessions)

    def test_step_count_in_list(self, sqlite_storage):
        sqlite_storage.append("sess_1", {"step": 1})
        sqlite_storage.append("sess_1", {"step": 2})
        sqlite_storage.append("sess_1", {"step": 3})
        sessions = sqlite_storage.list_sessions()
        sess = [s for s in sessions if s.session_id == "sess_1"][0]
        assert sess.step_count == 3
