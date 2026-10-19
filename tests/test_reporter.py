"""Unit tests for sanctum.reporter — markdown escaping."""
import unittest

from sanctum.reporter import _esc, markdown_report


def _g(**kw):
    d = {"id": "S01", "severity": "high", "verdict": "BYPASSED",
         "detectors": ["R02"], "title": "t",
         "response": "r", "tool_calls": [], "error": None}
    d.update(kw)
    return d


class TestEsc(unittest.TestCase):
    def test_html_escaped(self):
        self.assertNotIn("<script>", _esc("<script>alert(1)</script>"))
        self.assertIn("&lt;script&gt;", _esc("<script>"))

    def test_backtick_defused(self):
        self.assertNotIn("`", _esc("a `code` b"))

    def test_newline_flattened(self):
        self.assertNotIn("\n", _esc("a\nb"))

    def test_non_string_ok(self):
        self.assertEqual(_esc(123), "123")
        self.assertEqual(_esc(None), "")


class TestReport(unittest.TestCase):
    def test_title_escaped(self):
        md = markdown_report([_g()], title="<script>alert(1)</script>")
        self.assertNotIn("<script>alert(1)</script>", md)

    def test_malicious_id_and_title_escaped(self):
        g = _g(id='S01\n| evil |', title='<b>bold</b> `code`')
        md = markdown_report([g])
        self.assertNotIn("<b>bold</b>", md)
        self.assertIn("&lt;b&gt;bold&lt;/b&gt;", md)
        # The newline in the id is flattened: it cannot smuggle new table
        # rows into the report.
        self.assertNotIn("S01\n", md)
        self.assertIn("S01 | evil |", md)

    def test_bypassed_first_order(self):
        md = markdown_report([_g(id="B", verdict="BLOCKED"),
                              _g(id="A", verdict="BYPASSED")])
        self.assertLess(md.index("| A |"), md.index("| B |"))

    def test_empty(self):
        md = markdown_report([])
        self.assertIn("**0** cases", md)

    def test_needs_review_section(self):
        md = markdown_report([_g(verdict="UNCLEAR", response="hmm")])
        self.assertIn("## Needs human review", md)
        self.assertIn("response excerpt", md)


if __name__ == "__main__":
    unittest.main()


class TestMalformedGraded(unittest.TestCase):
    # fuzz round 2: reporter tidak boleh crash pada data liar
    def test_wild_graded_no_crash(self):
        from sanctum.reporter import markdown_report
        graded = [
            {"id": "S01", "title": "<script>alert(1)</script>", "severity": ["x"],
             "verdict": ["v"], "detectors": [1, 2], "response": 42,
             "tool_calls": "x", "error": {"e": 1}},
            {"id": None, "title": None, "severity": None,
             "verdict": None, "detectors": None, "response": None},
            42, "junk", None, ["nested"],
        ]
        out = markdown_report(graded)
        self.assertIn("# sanctum report", out)
        self.assertNotIn("<script>alert(1)</script>", out)

    def test_summarize_unhashable_keys(self):
        from sanctum.grader import summarize
        s = summarize([{"verdict": ["v"], "severity": {"a": 1}},
                       {"verdict": "BYPASSED", "severity": ["x"]},
                       "junk"])
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["verdicts"]["BYPASSED"], 1)


class TestAnsiInjection(unittest.TestCase):
    def test_esc_strips_control_chars(self):
        from sanctum.reporter import _esc
        out = _esc("a\x1b[31mb\x07c")
        self.assertFalse(any(ord(c) < 32 or ord(c) == 127 for c in out))
        self.assertIn("a", out)
        # HTML escaping still intact
        self.assertIn("&lt;", _esc("<b>x</b>"))
