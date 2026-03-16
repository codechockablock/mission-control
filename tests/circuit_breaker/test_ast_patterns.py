"""Tests for AST-based pattern detection (SQL + code)."""

from mission_control.circuit_breaker.ast_patterns import ASTPatternChecker, ASTMatch


class TestSQLPatterns:
    def setup_method(self):
        self.checker = ASTPatternChecker()

    def test_drop_table(self):
        matches = self.checker.check_sql("DROP TABLE users;")
        assert any(m.pattern_name == "drop_table" for m in matches)

    def test_drop_table_if_exists(self):
        matches = self.checker.check_sql("DROP TABLE IF EXISTS users;")
        assert any(m.pattern_name == "drop_table" for m in matches)

    def test_drop_database(self):
        matches = self.checker.check_sql("DROP DATABASE production;")
        assert any(m.pattern_name == "drop_database" for m in matches)

    def test_drop_schema(self):
        matches = self.checker.check_sql("DROP SCHEMA IF EXISTS public;")
        assert any(m.pattern_name == "drop_database" for m in matches)

    def test_truncate(self):
        matches = self.checker.check_sql("TRUNCATE TABLE logs;")
        assert any(m.pattern_name == "truncate_table" for m in matches)

    def test_delete_where_true(self):
        matches = self.checker.check_sql("DELETE FROM users WHERE 1=1;")
        assert any(m.pattern_name == "delete_where_true" for m in matches)

    def test_grant_all(self):
        matches = self.checker.check_sql("GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';")
        assert any(m.pattern_name == "grant_all" for m in matches)

    def test_alter_drop_column(self):
        matches = self.checker.check_sql("ALTER TABLE users DROP COLUMN password_hash;")
        assert any(m.pattern_name == "alter_drop_column" for m in matches)

    def test_safe_select(self):
        matches = self.checker.check_sql("SELECT * FROM users WHERE id = 1;")
        assert len(matches) == 0

    def test_safe_insert(self):
        matches = self.checker.check_sql("INSERT INTO logs (msg) VALUES ('hello');")
        assert len(matches) == 0

    def test_safe_update_with_where(self):
        matches = self.checker.check_sql("UPDATE users SET name = 'bob' WHERE id = 42;")
        assert len(matches) == 0

    def test_case_insensitive(self):
        matches = self.checker.check_sql("drop table USERS;")
        assert any(m.pattern_name == "drop_table" for m in matches)


class TestCodePatterns:
    def setup_method(self):
        self.checker = ASTPatternChecker()

    def test_os_system_rm(self):
        matches = self.checker.check_code("os.system('rm -rf /')")
        assert any(m.pattern_name == "os_system_dangerous" for m in matches)

    def test_os_system_safe(self):
        matches = self.checker.check_code("os.system('ls -la')")
        assert len(matches) == 0

    def test_subprocess_shell_dangerous(self):
        matches = self.checker.check_code("subprocess.call('rm -rf /tmp', shell=True)")
        assert any(m.pattern_name == "subprocess_shell_dangerous" for m in matches)

    def test_eval_input(self):
        matches = self.checker.check_code("eval(input('Enter expression: '))")
        assert any(m.pattern_name == "eval_exec_input" for m in matches)

    def test_eval_format_string(self):
        matches = self.checker.check_code("eval(f'func_{user_input}()')")
        assert any(m.pattern_name == "eval_exec_format" for m in matches)

    def test_shutil_rmtree_root(self):
        matches = self.checker.check_code("shutil.rmtree('/usr/lib')")
        assert any(m.pattern_name == "shutil_rmtree_root" for m in matches)

    def test_shutil_rmtree_safe(self):
        matches = self.checker.check_code("shutil.rmtree('./build')")
        assert len(matches) == 0

    def test_os_chmod_777(self):
        matches = self.checker.check_code("os.chmod('/tmp/script', 0o777)")
        assert any(m.pattern_name == "os_chmod_world_writable" for m in matches)


class TestCheckAll:
    def setup_method(self):
        self.checker = ASTPatternChecker()

    def test_mixed_sql_and_code(self):
        text = "DROP TABLE users; os.system('rm -rf /')"
        matches = self.checker.check(text)
        names = {m.pattern_name for m in matches}
        assert "drop_table" in names
        assert "os_system_dangerous" in names

    def test_safe_text(self):
        matches = self.checker.check("Hello world, this is a normal message")
        assert len(matches) == 0
