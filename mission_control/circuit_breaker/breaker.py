"""
CircuitBreaker — fast, categorical action blocking.

No ML. No statistical inference. Pre-compiled regex matching.
evaluate() completes in <1ms for any rule set.
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Pattern, Tuple

from mission_control.circuit_breaker.rules import Rule, RuleCategory, BreakerResult
from mission_control.circuit_breaker.builtins import get_default_rules, get_domain_rules
from mission_control.circuit_breaker.ast_patterns import ASTPatternChecker, ASTMatch


class CircuitBreaker:
    """
    Fast, categorical circuit breaker for agent actions.

    All regexes are pre-compiled at __init__ time. evaluate() does only
    matching — no allocation, no I/O, no ML.
    """

    def __init__(self, rules: List[Rule], enable_ast: bool = True):
        self._rules = list(rules)
        self._enable_ast = enable_ast

        # Pre-compile: list of (rule, tool_set, compiled_patterns)
        self._compiled: List[Tuple[Rule, set, List[re.Pattern]]] = []
        for rule in self._rules:
            tool_set = set(rule.tool_types) if rule.tool_types else set()
            compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.patterns]
            self._compiled.append((rule, tool_set, compiled))

        # AST checker (also pre-compiled)
        self._ast_checker = ASTPatternChecker() if enable_ast else None

    @property
    def rules(self) -> List[Rule]:
        return list(self._rules)

    def evaluate(
        self,
        tool_type: str,
        action_content: str,
        parameters: Optional[dict] = None,
    ) -> BreakerResult:
        """
        Evaluate an action against all rules.

        Returns BreakerResult with allowed=False if any rule matches.
        Completes in <1ms for typical rule sets.
        """
        start = time.perf_counter_ns()
        matched: List[Rule] = []

        # Check regex rules
        for rule, tool_set, patterns in self._compiled:
            # Skip if rule is scoped to specific tool types and this isn't one
            if tool_set and tool_type not in tool_set:
                continue
            for pat in patterns:
                if pat.search(action_content):
                    matched.append(rule)
                    break  # One pattern match per rule is enough

        # Check AST patterns for SQL/code tool types
        if self._ast_checker is not None:
            ast_matches = self._ast_checker.check(action_content)
            for ast_match in ast_matches:
                # Create a synthetic rule for the AST match
                synth_rule = Rule(
                    name=f"ast_{ast_match.pattern_name}",
                    category=RuleCategory.CUSTOM,
                    description=ast_match.description,
                    patterns=[],
                    tool_types=[],
                    severity=ast_match.severity,
                )
                # Avoid duplicates if already matched by name
                if not any(r.name == synth_rule.name for r in matched):
                    matched.append(synth_rule)

        elapsed_us = (time.perf_counter_ns() - start) // 1000

        return BreakerResult(
            allowed=len(matched) == 0,
            matched_rules=matched,
            evaluation_time_us=elapsed_us,
        )

    @classmethod
    def default(cls) -> "CircuitBreaker":
        """Create a CircuitBreaker with the full default rule set."""
        return cls(get_default_rules())

    @classmethod
    def for_domain(cls, domain: str) -> "CircuitBreaker":
        """Create a CircuitBreaker with domain-specific rules.

        Available domains: 'sysadmin', 'data_engineering', 'customer_service', 'financial'.
        """
        return cls(get_domain_rules(domain))
