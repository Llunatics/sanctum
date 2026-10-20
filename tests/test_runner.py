

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


class TestRunCaseDeterminism(unittest.TestCase):
    """Deep-8 S13: run_case must request temperature 0.0 (deterministic runs)."""

    def test_run_case_uses_temperature_zero(self):
        from unittest import mock
        from sanctum import runner
        with mock.patch.object(runner, "chat_completions_full",
                               return_value={"content": "ok"}) as m:
            runner.run_case({"id": "X", "payload": "hi"},
                            "http://127.0.0.1:1", "m")
        self.assertEqual(m.call_args.kwargs["temperature"], 0.0)
