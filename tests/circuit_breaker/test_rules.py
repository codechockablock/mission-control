"""Tests for Rule and BreakerResult dataclasses."""

from mission_control.circuit_breaker.rules import Rule, RuleCategory, BreakerResult


class TestRuleCategory:
    def test_all_categories_exist(self):
        expected = {
            "filesystem_destruction", "credential_exfiltration",
            "privilege_escalation", "data_exfiltration",
            "system_modification", "network_abuse", "custom",
        }
        actual = {c.value for c in RuleCategory}
        assert actual == expected

    def test_category_is_str_enum(self):
        assert isinstance(RuleCategory.CUSTOM, str)
        assert RuleCategory.CUSTOM == "custom"


class TestRule:
    def test_rule_creation(self):
        rule = Rule(
            name="test",
            category=RuleCategory.CUSTOM,
            description="A test rule",
            patterns=[r"foo.*bar"],
            tool_types=["shell_exec"],
        )
        assert rule.name == "test"
        assert rule.severity == "critical"

    def test_rule_is_frozen(self):
        rule = Rule(
            name="test",
            category=RuleCategory.CUSTOM,
            description="test",
            patterns=[],
            tool_types=[],
        )
        import pytest
        with pytest.raises(AttributeError):
            rule.name = "changed"  # type: ignore

    def test_rule_empty_tool_types_means_all(self):
        rule = Rule(
            name="test",
            category=RuleCategory.CUSTOM,
            description="test",
            patterns=[r"danger"],
            tool_types=[],
        )
        assert rule.tool_types == []


class TestBreakerResult:
    def test_allowed_result(self):
        result = BreakerResult(allowed=True)
        assert result.allowed
        assert result.matched_rules == []
        assert result.evaluation_time_us == 0

    def test_denied_result(self):
        rule = Rule(
            name="test",
            category=RuleCategory.CUSTOM,
            description="test",
            patterns=[],
            tool_types=[],
        )
        result = BreakerResult(allowed=False, matched_rules=[rule], evaluation_time_us=42)
        assert not result.allowed
        assert len(result.matched_rules) == 1
        assert result.evaluation_time_us == 42
