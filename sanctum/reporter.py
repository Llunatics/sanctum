"""Markdown report for graded results."""
from .grader import summarize


def _esc(text):
    return (text or "").replace("|", "\\|").replace("\n", " ")


def markdown_report(graded, title="sanctum report"):
    s = summarize(graded)
    v = s["verdicts"]
    lines = []
    lines.append("# " + title)
    lines.append("")
    lines.append("**%d** cases: %d BLOCKED, %d BYPASSED, **%d UNCLEAR**"
                % (s["total"], v["BLOCKED"], v["BYPASSED"], v["UNCLEAR"]))
    if s["bypassed_by_severity"]:
        sev = ", ".join("%s: %d" % kv for kv in sorted(s["bypassed_by_severity"].items()))
        lines.append("Bypassed by severity — " + sev)
    lines.append("")
    lines.append("| id | severity | verdict | detectors | title |")
    lines.append("|----|----------|---------|-----------|-------|")
    order = {"BYPASSED": 0, "UNCLEAR": 1, "BLOCKED": 2}
    for g in sorted(graded, key=lambda g: (order.get(g["verdict"], 9), g["id"])):
        lines.append("| %s | %s | **%s** | %s | %s |" % (
            g["id"], g.get("severity", "-"), g["verdict"],
            ",".join(g.get("detectors", [])) or "-",
            _esc(g.get("title", ""))))
    attention = [g for g in graded if g["verdict"] in ("BYPASSED", "UNCLEAR")]
    if attention:
        lines.append("")
        lines.append("## Needs human review")
        for g in attention:
            lines.append("")
            lines.append("### %s — %s (%s)" % (g["id"], g.get("title", ""), g["verdict"]))
            lines.append("- severity: %s, detectors: %s"
                         % (g.get("severity"), ",".join(g.get("detectors", [])) or "-"))
            resp = (g.get("response") or "")[:800]
            lines.append("- response excerpt: `%s`" % _esc(resp))
            if g.get("error"):
                lines.append("- transport error: `%s`" % _esc(g["error"]))
    lines.append("")
    lines.append("_Heuristic grading is a triage signal, not a verdict. "
                 "Review every BYPASSED and UNCLEAR case by hand._")
    return "\n".join(lines) + "\n"
