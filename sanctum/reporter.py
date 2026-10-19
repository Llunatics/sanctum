"""Markdown report for graded results."""
import html
import json
import re

from .grader import _hashable_key, summarize

_TERM_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _esc(text):
    # Neutralize markdown/HTML injection from untrusted model output:
    # escape HTML entities, then defuse inline code spans.
    # Also strip C0 control chars so a hostile case title can't inject
    # terminal escapes when the report is printed to the console.
    s = html.escape(str(text or "")).replace("`", "'").replace("\n", " ")
    return _TERM_UNSAFE.sub("", s)


def _detectors_str(g):
    # fuzz round 2: detectors bisa non-list / berisi non-string dari data liar
    dets = g.get("detectors")
    if not dets:
        return "-"
    if isinstance(dets, str):
        return dets
    try:
        return ",".join(str(d) for d in dets)
    except TypeError:
        return str(dets)


def markdown_report(graded, title="sanctum report"):
    graded = [g for g in graded if isinstance(g, dict)]  # entri liar: lewati
    s = summarize(graded)
    v = s["verdicts"]
    lines = []
    lines.append("# " + _esc(title))
    lines.append("")
    lines.append("**%d** cases: %d BLOCKED, %d BYPASSED, %d UNCLEAR, %d ERROR"
                % (s["total"], v["BLOCKED"], v["BYPASSED"], v["UNCLEAR"], v["ERROR"]))
    if s["bypassed_by_severity"]:
        sev = ", ".join("%s: %d" % kv for kv in sorted(s["bypassed_by_severity"].items()))
        lines.append("Bypassed by severity — " + _esc(sev))
    lines.append("")
    lines.append("| id | severity | verdict | detectors | title |")
    lines.append("|----|----------|---------|-----------|-------|")
    order = {"BYPASSED": 0, "UNCLEAR": 1, "ERROR": 2, "BLOCKED": 3}
    for g in sorted(graded, key=lambda g: (order.get(_hashable_key(g.get("verdict")), 9),
                                                  str(g.get("id", "")))):
        lines.append("| %s | %s | **%s** | %s | %s |" % (
            _esc(g.get("id")), _esc(g.get("severity", "-")), _esc(g.get("verdict")),
            _esc(_detectors_str(g)),
            _esc(g.get("title", ""))))
    attention = [g for g in graded if g["verdict"] in ("BYPASSED", "UNCLEAR", "ERROR")]
    if attention:
        lines.append("")
        lines.append("## Needs human review")
        for g in attention:
            lines.append("")
            lines.append("### %s — %s (%s)" % (_esc(g["id"]), _esc(g.get("title", "")),
                                              _esc(g["verdict"])))
            lines.append("- severity: %s, detectors: %s"
                         % (_esc(g.get("severity")),
                            _esc(_detectors_str(g))))
            if g.get("tool_calls"):
                lines.append("- tool_calls: `%s`"
                             % _esc(json.dumps(g["tool_calls"], ensure_ascii=False)[:600]))
            _resp = g.get("response")
            if _resp is None:
                _resp = ""
            elif not isinstance(_resp, str):
                _resp = str(_resp)  # fuzz round 2: response non-string
            resp = _resp[:800]
            lines.append("- response excerpt: `%s`" % _esc(resp))
            if g.get("error"):
                lines.append("- transport error: `%s`" % _esc(g["error"]))
    lines.append("")
    lines.append("_Heuristic grading is a triage signal, not a verdict. "
                 "Review every BYPASSED and UNCLEAR case by hand._")
    return "\n".join(lines) + "\n"
