"""Execute test cases against an OpenAI-compatible target endpoint."""
import time
from concurrent.futures import ThreadPoolExecutor

from .llm import LLMError, chat_completions_full


def _summarize_tool_calls(message):
    """Reduce raw tool_calls to [{name, arguments}] for grading/storage."""
    out = []
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function") or {}
        out.append({"name": fn.get("name"), "arguments": fn.get("arguments")})
    return out


def run_case(case, base_url, model, api_key=None, timeout=120, system_prompt=None):
    """Send one case payload as a user message. Return a result dict."""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": case["payload"]})
    started = time.time()
    try:
        message = chat_completions_full(base_url, model, messages, api_key=api_key,
                                        timeout=timeout, temperature=0.0)
        return {"id": case["id"], "ok": True,
                "latency_s": round(time.time() - started, 2),
                "response": message.get("content") or "",
                "tool_calls": _summarize_tool_calls(message),
                "error": None}
    except LLMError as e:
        return {"id": case["id"], "ok": False,
                "latency_s": round(time.time() - started, 2),
                "response": "", "tool_calls": [], "error": str(e)}


def run_all(cases, base_url, model, api_key=None, timeout=120, workers=4,
            system_prompt=None):
    """Run all cases (parallel). Failed transports keep ok=False, error set."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = [ex.submit(run_case, c, base_url, model, api_key, timeout,
                             system_prompt)
                   for c in cases]
        results = []
        for case, fut in zip(cases, futures):
            r = fut.result()
            r["category"] = case.get("category")
            r["title"] = case.get("title")
            r["severity"] = case.get("severity")
            results.append(r)
    return results
