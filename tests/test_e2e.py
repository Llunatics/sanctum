"""End-to-end test: stub agent -> run -> grade -> assert verdicts.

Spawns tests/stub_agent.py on 127.0.0.1:18231, drives the real CLI via
subprocess, and asserts the expected verdict per case id. No import-time
side effects: everything runs inside the TestCase.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUB_PORT = 18231
WANT = {"S01": "BLOCKED", "S03": "UNCLEAR", "S07": "BYPASSED",
        "S10": "UNCLEAR", "S15": "BYPASSED"}


class TestE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = subprocess.Popen(
            [sys.executable, "tests/stub_agent.py"], cwd=REPO,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # The stub only serves POST: probe readiness with a minimal POST.
        probe = urllib.request.Request(
            "http://127.0.0.1:%d/v1/chat/completions" % STUB_PORT,
            data=b"{}", method="POST")
        for _ in range(50):
            try:
                urllib.request.urlopen(probe, timeout=1).read()
                break
            except Exception:
                time.sleep(0.2)
        else:
            cls.server.terminate()
            raise RuntimeError("stub agent did not start")
        cls.tmp = tempfile.TemporaryDirectory(prefix="sanctum-e2e-")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=10)
        cls.tmp.cleanup()

    def _path(self, name):
        return os.path.join(self.tmp.name, name)

    def _cli(self, *a):
        r = subprocess.run([sys.executable, "-m", "sanctum.cli", *a],
                           cwd=REPO, capture_output=True, text=True,
                           timeout=120)
        self.assertEqual(r.returncode, 0,
                         msg="cli %s failed:\n%s" % (a, r.stderr))
        return r

    def _cases(self):
        with open(os.path.join(REPO, "sanctum", "data", "seed_cases.json"),
                  encoding="utf-8") as f:
            seeds = json.load(f)
        cases = []
        for s in seeds:
            if s["id"] in WANT:
                c = dict(s)
                c["payload"] = "##CASE:%s##\n%s" % (s["id"], s["payload"])
                cases.append(c)
        p = self._path("cases.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cases, f)
        return p

    def test_verdicts_match_expected(self):
        cases = self._cases()
        results = self._path("results.json")
        graded = self._path("graded.json")
        self._cli("run", "--cases", cases,
                  "--backend-url", "http://127.0.0.1:%d/v1" % STUB_PORT,
                  "--model", "stub", "--out", results, "--workers", "5")
        self._cli("grade", "--results", results, "--out", graded)
        with open(graded, encoding="utf-8") as f:
            got = {g["id"]: g["verdict"] for g in json.load(f)}
        bad = {k: (got.get(k), v) for k, v in WANT.items()
               if got.get(k) != v}
        self.assertEqual(bad, {}, msg="verdict mismatch: %s" % bad)

    def test_transport_failures_grade_as_error(self):
        cases = self._cases()
        results = self._path("results2.json")
        graded = self._path("graded2.json")
        self._cli("run", "--cases", cases,
                  "--backend-url", "http://127.0.0.1:18299/v1",
                  "--model", "stub", "--out", results, "--workers", "5",
                  "--timeout", "5")
        self._cli("grade", "--results", results, "--out", graded)
        with open(graded, encoding="utf-8") as f:
            graded2 = json.load(f)
        self.assertTrue(graded2)
        for g in graded2:
            self.assertEqual(g["verdict"], "ERROR")


if __name__ == "__main__":
    unittest.main()
