"""Minimal OpenAI-compatible chat-completions client. Stdlib only, no deps.

Hardened: http/https scheme enforcement, cross-origin redirects refused
(never leak the Authorization header), 10 MB response cap, strict JSON
decoding tolerant of SSE trailers.
"""
import json
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class LLMError(RuntimeError):
    pass


class _NoCrossOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Follow same-origin redirects; refuse cross-origin ones outright.

    urllib forwards Authorization headers on redirect by default — a
    misconfigured --backend-url (or a malicious proxy) must never receive
    the API key on another host.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlparse(req.full_url)
        new = urllib.parse.urlparse(newurl)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise LLMError("cross-origin redirect refused: %s -> %s"
                           % (req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_url(base_url):
    scheme = urllib.parse.urlparse(base_url).scheme
    if scheme not in ("http", "https"):
        raise LLMError("refusing non-http(s) backend URL: %r" % base_url)


def _post_json(url, payload, api_key, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    opener = urllib.request.build_opener(_NoCrossOriginRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise LLMError("HTTP %s from %s: %s" % (e.code, url, detail))
    except urllib.error.URLError as e:
        raise LLMError("connection failed to %s: %s" % (url, e.reason))
    # Tolerate trailing non-JSON data (some bridges append an SSE
    # "data: [DONE]" trailer): decode only the first JSON document.
    try:
        body, _ = json.JSONDecoder().raw_decode(raw.lstrip())
    except json.JSONDecodeError as e:
        raise LLMError("bad JSON from %s: %s" % (url, e))
    return body


def chat_completions_full(base_url, model, messages, api_key=None,
                          timeout=120, temperature=0.7, max_tokens=2000,
                          tools=None):
    """POST /chat/completions, return the full assistant message dict.

    `tools` is an optional OpenAI-style tools array. Without it, most
    backends never emit tool_calls — pass your agent's tool schema when
    testing tool-abuse vectors.
    """
    _check_url(base_url)
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {"model": model, "messages": messages,
               "temperature": temperature, "max_tokens": max_tokens}
    if tools:
        payload["tools"] = tools
    body = _post_json(url, payload, api_key, timeout)
    try:
        return body["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        raise LLMError("unexpected response shape: %s" % str(body)[:300])


def chat_completions(base_url, model, messages, api_key=None,
                     timeout=120, temperature=0.7, max_tokens=2000,
                     tools=None):
    """POST /chat/completions and return the assistant message content."""
    msg = chat_completions_full(base_url, model, messages, api_key=api_key,
                                timeout=timeout, temperature=temperature,
                                max_tokens=max_tokens, tools=tools)
    return msg.get("content") or ""


def list_models(base_url, api_key=None, timeout=15):
    """GET /v1/models, return list of model ids (best effort)."""
    _check_url(base_url)
    url = base_url.rstrip("/") + "/models"
    req = urllib.request.Request(url, method="GET")
    if api_key:
        req.add_header("Authorization", "Bearer " + api_key)
    opener = urllib.request.build_opener(_NoCrossOriginRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
            body, _ = json.JSONDecoder().raw_decode(raw.lstrip())
        return [m.get("id") for m in body.get("data", []) if m.get("id")]
    except Exception as e:  # noqa: BLE001 - best effort probe
        raise LLMError("could not list models at %s: %s" % (url, e))
