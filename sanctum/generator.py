"""Generate tailored test cases via an LLM backend, or use built-in seed cases."""
import json
import os
import re

from .llm import chat_completions

REQUIRED_KEYS = ("id", "category", "title", "payload", "expected_safe", "severity")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def data_path(name):
    return os.path.join(DATA_DIR, name)


def load_seed_cases(category=None):
    with open(data_path("seed_cases.json"), encoding="utf-8") as f:
        cases = json.load(f)
    if category:
        cases = [c for c in cases if c.get("category") == category]
    return cases


def load_generation_prompt():
    with open(data_path("generation_system.txt"), encoding="utf-8") as f:
        return f.read()


def _extract_json_array(text):
    """Extract the first top-level JSON array from model output."""
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON array found in model output")
    return json.loads(text[start:end + 1])


def _validate(cases):
    clean = []
    for i, c in enumerate(cases):
        if not isinstance(c, dict):
            raise ValueError("case #%d is not an object" % i)
        missing = [k for k in REQUIRED_KEYS if k not in c]
        if missing:
            raise ValueError("case #%d missing keys: %s" % (i, missing))
        if c.get("severity") not in ("critical", "high", "medium"):
            raise ValueError("case %s has bad severity: %r" % (c.get("id"), c.get("severity")))
        clean.append({k: c[k] for k in REQUIRED_KEYS})
    ids = [c["id"] for c in clean]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate case ids: %s" % ids)
    return clean


def generate_cases(system_prompt_text, tools_schema_text, base_url, model,
                   api_key=None, count=20, timeout=180):
    """Ask the LLM backend for tailored cases. Returns validated list."""
    gen_prompt = load_generation_prompt()
    user_msg = (
        "TARGET SYSTEM PROMPT:\n%s\n\n"
        "TARGET TOOL SCHEMA (JSON):\n%s\n\n"
        "Generate exactly %d test cases as a JSON array, nothing else."
        % (system_prompt_text.strip(), tools_schema_text.strip(), count)
    )
    raw = chat_completions(
        base_url, model,
        [{"role": "system", "content": gen_prompt},
         {"role": "user", "content": user_msg}],
        api_key=api_key, timeout=timeout, temperature=0.8, max_tokens=6000,
    )
    return _validate(_extract_json_array(raw))
