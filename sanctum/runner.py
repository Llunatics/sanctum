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


def run_case(case, base_url, model, api_key=None, timeout=120,
             system_prompt=None, tools=None):
    """Send one case payload as a user message. Return a result dict.

    Never raises on malformed case dicts or transport errors — failures are
    recorded in the result (ok=False).
    """
    case_id = case.get("id", "?") if isinstance(case, dict) else "?"
    payload = case.get("payload", "") if isinstance(case, dict) else ""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": payload})
    started = time.time()
    try:
        message = chat_completions_full(base_url, model, messages, api_key=api_key,
                                        timeout=timeout, temperature=0.0,
                                        tools=tools)
        return {"id": case_id, "ok": True,
                "latency_s": round(time.time() - started, 2),
                "response": message.get("content") or "",
                "tool_calls": _summarize_tool_calls(message),
                "error": None}
    except LLMError as e:
        return {"id": case_id, "ok": False,
                "latency_s": round(time.time() - started, 2),
                "response": "", "tool_calls": [], "error": str(e)}
    except Exception as e:  # noqa: BLE001 - one bad case must not kill the batch
        return {"id": case_id, "ok": False,
                "latency_s": round(time.time() - started, 2),
                "response": "", "tool_calls": [],
                "error": "runner bug: %r" % e}


def run_all(cases, base_url, model, api_key=None, timeout=120, workers=4,
            system_prompt=None, tools=None):
    """Run all cases (parallel). Ctrl+C cancels pending futures promptly."""
    ex = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = [ex.submit(run_case, c, base_url, model, api_key, timeout,
                             system_prompt, tools)
                   for c in cases]
        results = []
        for case, fut in zip(cases, futures):
            r = fut.result()
            if isinstance(case, dict):
                r["category"] = case.get("category")
                r["title"] = case.get("title")
                r["severity"] = case.get("severity")
            results.append(r)
        return results
    except KeyboardInterrupt:
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        ex.shutdown(wait=True)
