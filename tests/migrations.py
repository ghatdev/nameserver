#!/usr/bin/env python3
"""Verify SQL splitting protects literals and refuses incomplete migrations."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("clickhouse_migrations", Path(__file__).resolve().parents[1] / "tools/migrate_clickhouse.py")
MIGRATIONS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATIONS)


class SqlStatements(unittest.TestCase):
    def test_literals_and_comments_do_not_create_extra_statements(self):
        commands = MIGRATIONS.statements("CREATE TABLE t (x String DEFAULT 'a;b'); -- ignored ;\nALTER TABLE t ADD COLUMN y String DEFAULT 'it''s;quoted'; /* final ; */")
        self.assertEqual(len(commands), 2)
        self.assertIn("'a;b'", commands[0])
        self.assertIn("'it''s;quoted'", commands[1])

    def test_unterminated_input_is_rejected_before_execution(self):
        for source in ("SELECT 'unfinished", "SELECT 1; /* unfinished"):
            with self.assertRaises(ValueError):
                MIGRATIONS.statements(source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
