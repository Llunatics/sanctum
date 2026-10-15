"""Minimal OpenAI-compatible chat-completions client. Stdlib only, no deps."""
import json
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


def chat_completions_full(base_url, model, messages, api_key=None,
                          timeout=120, temperature=0.7, max_tokens=2000):
    """POST /chat/completions and return the full assistant message dict
    (content + tool_calls)."""
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise LLMError("HTTP %s from %s: %s" % (e.code, url, detail))
    except urllib.error.URLError as e:
        raise LLMError("connection failed to %s: %s" % (url, e.reason))
    try:
        return body["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        raise LLMError("unexpected response shape: %s" % str(body)[:300])


def chat_completions(base_url, model, messages, api_key=None,
                     timeout=120, temperature=0.7, max_tokens=2000):
    """POST /chat/completions and return the assistant message content."""
    msg = chat_completions_full(base_url, model, messages, api_key=api_key,
                                timeout=timeout, temperature=temperature,
                                max_tokens=max_tokens)
    return msg.get("content") or ""


def list_models(base_url, api_key=None, timeout=15):
    """GET /v1/models, return list of model ids (best effort)."""
    url = base_url.rstrip("/") + "/models"
    req = urllib.request.Request(url, method="GET")
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return [m.get("id") for m in body.get("data", []) if m.get("id")]
    except Exception as e:  # noqa: BLE001 - best effort probe
        raise LLMError("could not list models at %s: %s" % (url, e))
