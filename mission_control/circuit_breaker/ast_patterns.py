"""
AST-based pattern detection for SQL and code.

Regex alone can't catch semantic equivalents. This module provides
lightweight structural analysis for SQL destructive operations and
dangerous Python constructs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class ASTMatch:
    """Result of an AST pattern match."""
    pattern_name: str
    description: str
    matched_text: str
    severity: str = "critical"


# ---------------------------------------------------------------------------
# SQL destructive patterns
# ---------------------------------------------------------------------------

_SQL_PATTERNS: List[tuple[str, str, re.Pattern]] = []


def _sql(name: str, desc: str, pattern: str) -> None:
    _SQL_PATTERNS.append((name, desc, re.compile(pattern, re.IGNORECASE | re.DOTALL)))


_sql("drop_table", "DROP TABLE statement",
     r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`\"\']?\w+")
_sql("drop_database", "DROP DATABASE statement",
     r"\bDROP\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?[`\"\']?\w+")
_sql("truncate_table", "TRUNCATE TABLE statement",
     r"\bTRUNCATE\s+(?:TABLE\s+)?[`\"\']?\w+")
_sql("delete_all_rows", "DELETE without meaningful WHERE clause",
     r"\bDELETE\s+FROM\s+[`\"\']?\w+[`\"\']?\s*(?:WHERE\s+(?:1\s*=\s*1|TRUE|1)\s*)?;?\s*$")
_sql("delete_where_true", "DELETE with always-true WHERE",
     r"\bDELETE\s+FROM\s+[`\"\']?\w+[`\"\']?\s+WHERE\s+(?:1\s*=\s*1|TRUE|'[^']*'\s*=\s*'[^']*'|1)")
_sql("update_no_where", "UPDATE without WHERE clause (modifies all rows)",
     r"\bUPDATE\s+[`\"\']?\w+[`\"\']?\s+SET\s+(?:(?!\bWHERE\b).)+;\s*$")
_sql("grant_all", "GRANT ALL PRIVILEGES",
     r"\bGRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+")
_sql("alter_drop_column", "ALTER TABLE DROP COLUMN",
     r"\bALTER\s+TABLE\s+[`\"\']?\w+[`\"\']?\s+DROP\s+COLUMN\s+")


# ---------------------------------------------------------------------------
# Python/shell dangerous code patterns
# ---------------------------------------------------------------------------

_CODE_PATTERNS: List[tuple[str, str, re.Pattern]] = []


def _code(name: str, desc: str, pattern: str) -> None:
    _CODE_PATTERNS.append((name, desc, re.compile(pattern, re.DOTALL)))


_code("os_system_dangerous", "os.system() with dangerous command",
      r"""os\.system\s*\(\s*['\"].*(?:rm\s+-rf|mkfs|dd\s+if=|chmod\s+777|curl.*\|.*sh)""")
_code("subprocess_shell_dangerous", "subprocess with shell=True and dangerous args",
      r"""subprocess\.(?:call|run|Popen)\s*\((?=.*shell\s*=\s*True)(?=.*(?:rm\s+-rf|mkfs|dd\s+if=))""")
_code("eval_exec_input", "eval/exec with external input",
      r"""(?:eval|exec)\s*\(\s*(?:input|request|sys\.argv|os\.environ)""")
_code("eval_exec_format", "eval/exec with string formatting (potential injection)",
      r"""(?:eval|exec)\s*\(\s*(?:f['\"]|['\"].*\.format|.*%\s)""")
_code("shutil_rmtree_root", "shutil.rmtree on root or system paths",
      r"""shutil\.rmtree\s*\(\s*['\"](?:/|/etc|/usr|/var|/home|/Users|/bin|/sbin)""")
_code("pickle_load_untrusted", "pickle.load from untrusted source",
      r"""pickle\.(?:load|loads)\s*\(\s*(?:request|urllib|socket|open)""")
_code("os_chmod_world_writable", "os.chmod making files world-writable",
      r"""os\.chmod\s*\(.*0o?777""")
_code("importlib_remote", "Dynamic import from remote source",
      r"""importlib\.import_module\s*\(.*(?:request|input|sys\.argv)""")


# ---------------------------------------------------------------------------
# Compiled checker
# ---------------------------------------------------------------------------


class ASTPatternChecker:
    """
    Check text against AST-like patterns for SQL and code.

    All patterns are pre-compiled at init time.
    """

    def __init__(self) -> None:
        self._sql_patterns = list(_SQL_PATTERNS)
        self._code_patterns = list(_CODE_PATTERNS)

    def check_sql(self, text: str) -> List[ASTMatch]:
        """Check SQL text for destructive patterns."""
        matches = []
        for name, desc, pattern in self._sql_patterns:
            m = pattern.search(text)
            if m:
                matches.append(ASTMatch(
                    pattern_name=name,
                    description=desc,
                    matched_text=m.group(0)[:200],
                ))
        return matches

    def check_code(self, text: str) -> List[ASTMatch]:
        """Check code text for dangerous patterns."""
        matches = []
        for name, desc, pattern in self._code_patterns:
            m = pattern.search(text)
            if m:
                matches.append(ASTMatch(
                    pattern_name=name,
                    description=desc,
                    matched_text=m.group(0)[:200],
                ))
        return matches

    def check(self, text: str, context: Optional[str] = None) -> List[ASTMatch]:
        """Check text against all patterns (SQL + code)."""
        results = self.check_sql(text) + self.check_code(text)
        return results
