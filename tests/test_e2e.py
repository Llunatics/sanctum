"""End-to-end test: stub agent -> run -> grade -> assert verdicts."""
import json
import subprocess
import sys
import time
import urllib.request

REPO = "/home/hatch/workspace/repos/sanctum"
WANT = {"S01": "BLOCKED", "S03": "UNCLEAR", "S07": "BYPASSED",
        "S10": "UNCLEAR", "S15": "BYPASSED"}

server = subprocess.Popen([sys.executable, "tests/stub_agent.py"], cwd=REPO,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:18231/", timeout=1)
            break
        except Exception:
            time.sleep(0.2)

    seeds = json.load(open(REPO + "/sanctum/data/seed_cases.json", encoding="utf-8"))
    cases = []
    for s in seeds:
        if s["id"] in WANT:
            c = dict(s)
            c["payload"] = "##CASE:%s##\n%s" % (s["id"], s["payload"])
            cases.append(c)
    json.dump(cases, open("/tmp/t-cases.json", "w"))

    def cli(*a):
        r = subprocess.run([sys.executable, "-m", "sanctum.cli", *a], cwd=REPO,
                           capture_output=True, text=True, timeout=120)
        print(r.stdout.strip())
        if r.returncode != 0:
            print(r.stderr.strip()); sys.exit(1)

    cli("run", "--cases", "/tmp/t-cases.json",
        "--backend-url", "http://127.0.0.1:18231/v1",
        "--model", "stub", "--out", "/tmp/t-results.json", "--workers", "5")
    cli("grade", "--results", "/tmp/t-results.json", "--out", "/tmp/t-graded.json")

    graded = json.load(open("/tmp/t-graded.json"))
    got = {g["id"]: g["verdict"] for g in graded}
    print("verdicts:", got)
    bad = {k: (got.get(k), v) for k, v in WANT.items() if got.get(k) != v}
    if bad:
        print("MISMATCH:", bad); sys.exit(1)
    print("ALL VERDICTS AS EXPECTED")
finally:
    server.terminate()
