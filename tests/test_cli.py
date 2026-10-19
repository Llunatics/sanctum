"""Unit tests for sanctum.cli — arg validation and clean error paths."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from sanctum import cli


def _cmd(cmd, argv):
    """Parse a subcommand argv through the real CLI parser."""
    return cli.build_parser().parse_args([cmd] + argv)


class TestGenerateValidation(unittest.TestCase):
    def test_count_zero_rejected(self):
        a = _cmd("generate", ["--system-prompt", "x", "--tools", "y",
                              "--count", "0", "--out", "o.json"])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.cmd_generate(a), 2)

    def test_no_llm_writes_seed_cases(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "cases.json")
            a = _cmd("generate", ["--no-llm", "--out", out])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_generate(a), 0)
            cases = json.load(open(out, encoding="utf-8"))
            self.assertEqual(len(cases), 20)

    def test_no_llm_unknown_category_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "cases.json")
            a = _cmd("generate", ["--no-llm", "--category", "__nope__",
                                  "--out", out])
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_generate(a), 2)
            self.assertFalse(os.path.exists(out))


class TestLoadErrors(unittest.TestCase):
    def test_grade_missing_file(self):
        a = _cmd("grade", ["--results", "/tidak/ada.json", "--out", "o.json"])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.cmd_grade(a), 1)
        self.assertIn("cannot read", err.getvalue())

    def test_grade_bad_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            f.write("{bukan json")
            p = f.name
        try:
            a = _cmd("grade", ["--results", p, "--out", "o.json"])
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(cli.cmd_grade(a), 1)
            self.assertIn("bad JSON", err.getvalue())
        finally:
            os.unlink(p)

    def test_report_missing_file(self):
        a = _cmd("report", ["--graded", "/tidak/ada.json", "--title", "t"])
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.cmd_report(a), 1)

    def test_run_bad_tools_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            f.write('{"nope": 1}')
            tools = f.name
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump([{"id": "T1", "category": "c", "title": "t",
                        "payload": "p", "expected_safe": "s",
                        "severity": "high"}], f)
            cases = f.name
        try:
            a = _cmd("run", ["--cases", cases, "--tools", tools,
                             "--out", "o.json"])
            err = io.StringIO()
            with redirect_stderr(err):
                self.assertEqual(cli.cmd_run(a), 1)
            self.assertIn("bad tools file", err.getvalue())
        finally:
            os.unlink(tools)
            os.unlink(cases)


class TestLoadTools(unittest.TestCase):
    def test_bare_array_accepted(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump([{"type": "function"}], f)
            p = f.name
        try:
            self.assertEqual(cli._load_tools(p), [{"type": "function"}])
        finally:
            os.unlink(p)

    def test_tools_key_accepted(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"tools": [{"type": "function"}]}, f)
            p = f.name
        try:
            self.assertEqual(cli._load_tools(p), [{"type": "function"}])
        finally:
            os.unlink(p)

    def test_none_returns_none(self):
        self.assertIsNone(cli._load_tools(None))


if __name__ == "__main__":
    unittest.main()
