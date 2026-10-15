"""sanctum CLI: generate / run / grade / report adversarial test cases."""
import argparse
import json
import os
import sys

from . import __version__
from .generator import generate_cases, load_seed_cases
from .grader import grade_results, summarize
from .llm import LLMError, list_models
from .reporter import markdown_report
from .runner import run_all

DEFAULT_BACKEND = "http://127.0.0.1:20128/v1"  # 9Router, OpenAI-compatible
DEFAULT_MODEL = "musebridge/muse-spark-1.3"  # via 9Router provider custom:musebridge


def _api_key(args):
    var = args.api_key_env
    return os.environ.get(var)


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _load_tools(path):
    """Load an OpenAI-style {"tools": [...]} file. Returns the tools array."""
    if not path:
        return None
    obj = json.loads(_read(path))
    if isinstance(obj, dict) and isinstance(obj.get("tools"), list):
        return obj["tools"]
    if isinstance(obj, list):
        return obj
    raise ValueError("--tools must be {\"tools\": [...]} or a bare [...] array")


def _load_cases(path):
    from .generator import _validate
    cases = json.loads(_read(path))
    if not isinstance(cases, list) or not cases:
        raise ValueError("no cases in %s" % path)
    return _validate(cases)


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    print("wrote %s (%d items)" % (path, len(obj) if isinstance(obj, list) else 1))


def _common_backend(p):
    p.add_argument("--backend-url", default=DEFAULT_BACKEND,
                   help="OpenAI-compatible base URL (default: %(default)s)")
    p.add_argument("--model", default=DEFAULT_MODEL,
                   help="model id on the backend (default: %(default)s)")
    p.add_argument("--api-key-env", default="SANCTUM_API_KEY",
                   help="env var holding the backend API key (default: %(default)s)")
    p.add_argument("--timeout", type=int, default=120,
                   help="per-request timeout seconds (default: %(default)s)")


def cmd_generate(args):
    if args.no_llm:
        cases = load_seed_cases(category=args.category)
        _write_json(args.out, cases)
        return 0
    if not args.system_prompt or not args.tools:
        print("generate needs --system-prompt and --tools (or use --no-llm)",
              file=sys.stderr)
        return 2
    system_prompt_text = _read(args.system_prompt)
    tools_schema_text = _read(args.tools)
    try:
        cases = generate_cases(system_prompt_text, tools_schema_text,
                               args.backend_url, args.model,
                               api_key=_api_key(args), count=args.count,
                               timeout=args.timeout)
    except (LLMError, ValueError) as e:
        print("generate failed: %s" % e, file=sys.stderr)
        return 1
    _write_json(args.out, cases)
    return 0


def cmd_run(args):
    try:
        cases = _load_cases(args.cases)
    except (ValueError, OSError) as e:
        print("bad cases file: %s" % e, file=sys.stderr)
        return 1
    try:
        tools = _load_tools(args.tools)
    except (ValueError, OSError) as e:
        print("bad tools file: %s" % e, file=sys.stderr)
        return 1
    system_prompt = _read(args.target_system_prompt) if args.target_system_prompt else None
    results = run_all(cases, args.backend_url, args.model,
                      api_key=_api_key(args), timeout=args.timeout,
                      workers=args.workers, system_prompt=system_prompt,
                      tools=tools)
    failed = sum(1 for r in results if not r["ok"])
    _write_json(args.out, results)
    print("%d/%d transport failures" % (failed, len(results)))
    return 0


def cmd_grade(args):
    results = json.loads(_read(args.results))
    graded = grade_results(results)
    _write_json(args.out, graded)
    s = summarize(graded)["verdicts"]
    print("BLOCKED=%d BYPASSED=%d UNCLEAR=%d ERROR=%d"
          % (s["BLOCKED"], s["BYPASSED"], s["UNCLEAR"], s["ERROR"]))
    return 0


def cmd_report(args):
    graded = json.loads(_read(args.graded))
    md = markdown_report(graded, title=args.title)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
        print("wrote %s" % args.out)
    else:
        print(md)
    return 0


def cmd_models(args):
    try:
        for m in list_models(args.backend_url, api_key=_api_key(args)):
            print(m)
    except LLMError as e:
        print("models failed: %s" % e, file=sys.stderr)
        return 1
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="sanctum",
        description="Red-team YOUR OWN AI agents against prompt injection "
                    "and tool abuse. Defensive use only.")
    p.add_argument("--version", action="version", version="sanctum " + __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="create tailored test cases")
    g.add_argument("--system-prompt", help="file: target agent system prompt "
                   "(required unless --no-llm)")
    g.add_argument("--tools", help="file: target tool schema (JSON) "
                   "(required unless --no-llm)")
    g.add_argument("--out", default="cases.json", help="output JSON (default: %(default)s)")
    g.add_argument("--count", type=int, default=20)
    g.add_argument("--no-llm", action="store_true",
                   help="skip the LLM backend, use built-in seed cases")
    g.add_argument("--category", help="with --no-llm: only this category")
    _common_backend(g)
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("run", help="execute cases against a target endpoint")
    r.add_argument("--cases", required=True, help="cases JSON from generate")
    r.add_argument("--out", default="results.json")
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--target-system-prompt",
                   help="file: system prompt to wrap around payloads (optional)")
    r.add_argument("--tools",
                   help='file: {"tools": [...]} OpenAI-style tool definitions '
                        "to send with each request (required for tool_calls "
                        "to be emitted by real backends)")
    _common_backend(r)
    r.set_defaults(func=cmd_run)

    gr = sub.add_parser("grade", help="heuristic grading of run results")
    gr.add_argument("--results", required=True)
    gr.add_argument("--out", default="graded.json")
    gr.set_defaults(func=cmd_grade)

    rp = sub.add_parser("report", help="markdown report from graded results")
    rp.add_argument("--graded", required=True)
    rp.add_argument("--out", help="write to file instead of stdout")
    rp.add_argument("--title", default="sanctum report")
    rp.set_defaults(func=cmd_report)

    m = sub.add_parser("models", help="list models on the backend")
    m.add_argument("--backend-url", default=DEFAULT_BACKEND)
    m.add_argument("--api-key-env", default="SANCTUM_API_KEY")
    m.set_defaults(func=cmd_models)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
