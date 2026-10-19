

import unittest


class TestSummarizeRobustness(unittest.TestCase):
    def test_malformed_message(self):
        from sanctum.runner import _summarize_tool_calls
        self.assertEqual(_summarize_tool_calls(None), [])
        self.assertEqual(_summarize_tool_calls("x"), [])
        self.assertEqual(_summarize_tool_calls({"tool_calls": ["bogus", None]}), [])
        out = _summarize_tool_calls(
            {"tool_calls": [{"function": {"name": "shell_exec",
                                          "arguments": "rm -rf /"}}]})
        self.assertEqual(out[0]["name"], "shell_exec")
