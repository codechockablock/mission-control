"""Shared test fixtures for mission-control."""

import os
import tempfile
import pytest

from mission_control.circuit_breaker import CircuitBreaker, Rule, RuleCategory
from mission_control.recorder.storage import FileStorage, SQLiteStorage


@pytest.fixture
def default_breaker():
    """CircuitBreaker with default rules."""
    return CircuitBreaker.default()


@pytest.fixture
def custom_breaker():
    """CircuitBreaker with a single custom rule."""
    rules = [
        Rule(
            name="test_rule",
            category=RuleCategory.CUSTOM,
            description="Test rule for unit tests",
            patterns=[r"DANGEROUS_PATTERN"],
            tool_types=["shell_exec"],
            severity="critical",
        ),
    ]
    return CircuitBreaker(rules)


@pytest.fixture
def tmp_dir():
    """Temporary directory for storage tests."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def file_storage(tmp_dir):
    """FileStorage backed by a temp directory."""
    return FileStorage(base_dir=os.path.join(tmp_dir, "sessions"))


@pytest.fixture
def sqlite_storage(tmp_dir):
    """SQLiteStorage backed by a temp database."""
    db_path = os.path.join(tmp_dir, "test.db")
    storage = SQLiteStorage(db_path=db_path)
    yield storage
    storage.close()
