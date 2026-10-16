from datetime import datetime

def build_report(language, code, result):
    lines = ["# AI Code Review & Security Analysis Report", "",
             f"- Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
             f"- Language: {language}", f"- Total findings: {result['counts']['total']}",
             f"- High: {result['counts']['high']} | Medium: {result['counts']['medium']} | Low: {result['counts']['low']}",
             "", "## Summary", result["summary"], "", "## Findings"]
    if not result["findings"]:
        lines.append("No configured rules matched. This is not proof that the code is secure.")
    for i, f in enumerate(result["findings"], 1):
        lines += ["", f"### {i}. [{f['severity']}] {f['title']}", f"- Rule: `{f['rule_id']}`",
                  f"- Category: {f['category']}", "", f["description"], "",
                  f"**Potential impact:** {f['impact']}", "", f"**Recommendation:** {f['recommendation']}"]
        if f.get("fixed_example"):
            lines += ["", "**Safer example:**", f"```{language.lower()}", f["fixed_example"], "```"]
    lines += ["", "## Limitations", "This report uses heuristic pattern matching. False positives and false negatives are possible; it is not a substitute for full static analysis, dependency auditing, testing, or expert review.",
              "", "## Submitted source", f"```{language.lower()}", code[:12000], "```"]
    return "\n".join(lines).encode("utf-8")
