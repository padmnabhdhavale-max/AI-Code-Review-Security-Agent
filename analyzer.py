import re

def finding(rule_id, title, severity, category, description, impact, recommendation, fixed_example=""):
    return dict(rule_id=rule_id, title=title, severity=severity, category=category,
                description=description, impact=impact, recommendation=recommendation,
                fixed_example=fixed_example)

def analyze_code(code, language):
    lang = language.lower()
    findings = []
    secret = r'(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*=\s*["\'][^"\']{3,}["\']'
    if re.search(secret, code):
        findings.append(finding("SEC-001", "Possible hardcoded secret", "High", "Security",
            "A credential-like variable appears to contain a literal secret.",
            "Credentials committed to source control can be exposed and reused.",
            "Read secrets from environment variables or a secret manager; rotate any real exposed credential.",
            'import os\\npassword = os.environ.get("APP_PASSWORD")'))
    sql = r'(?is)(SELECT|INSERT|UPDATE|DELETE).{0,300}(\+\s*\w+|\{\s*\w+\s*\}|%\s*\w+|f["\'])'
    if re.search(sql, code):
        example = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))' if lang == "python" else 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\\nps.setString(1, userId);\\nResultSet rs = ps.executeQuery();'
        findings.append(finding("SEC-002", "Possible SQL injection", "High", "Security",
            "A SQL query may be assembled with string concatenation or interpolation.",
            "Untrusted input may change the query and expose or modify database records.",
            "Use parameterized queries or prepared statements; do not concatenate user input into SQL.", example))
    if lang == "python" and re.search(r'\b(eval|exec)\s*\(', code):
        findings.append(finding("SEC-003", "Dynamic code execution", "High", "Security",
            "The code calls eval() or exec().", "Untrusted input may cause arbitrary code execution.",
            "Avoid eval/exec for untrusted data. Use safe parsing such as json.loads() where appropriate.",
            "import json\\nvalue = json.loads(user_supplied_json)"))
    if re.search(r'(?i)(innerHTML\s*=|document\.write\s*\()', code):
        findings.append(finding("SEC-004", "Potential unsafe HTML insertion", "Medium", "Security",
            "The code appears to insert content into an HTML sink.",
            "Attacker-controlled content may cause cross-site scripting (XSS).",
            "Prefer textContent or framework auto-escaping; sanitize HTML when required.",
            "element.textContent = userProvidedText;"))
    if lang == "python" and re.search(r'def\s+\w+\s*\([^)]*=\s*(\[\]|\{\})', code):
        findings.append(finding("QUAL-001", "Mutable default argument", "Medium", "Code Quality",
            "A function parameter may use a list or dictionary as a default.",
            "The same mutable object can be reused across calls.",
            "Use None as the default and create a new object inside the function.",
            "def add_item(item, items=None):\\n    if items is None:\\n        items = []\\n    items.append(item)"))
    if lang == "python" and re.search(r'\bprint\s*\(', code):
        findings.append(finding("QUAL-002", "Print statement in application code", "Low", "Code Quality",
            "print() may be leftover debugging output.", "Debug output can clutter logs or expose sensitive values.",
            "Use configured logging and never log secrets."))
    if re.search(r'(?i)\b(TODO|FIXME|HACK)\b', code):
        findings.append(finding("QUAL-003", "Unresolved TODO/FIXME marker", "Low", "Code Quality",
            "The source contains a TODO, FIXME, or HACK marker.", "Incomplete work may be shipped accidentally.",
            "Resolve it or track it as an issue with an owner and acceptance criteria."))
    rank = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: rank[f["severity"]])
    counts = {s.lower(): sum(f["severity"] == s for f in findings) for s in ["High", "Medium", "Low"]}
    counts["total"] = len(findings)
    summary = "No configured rules matched. This does not prove the code is secure." if not findings else f"Found {len(findings)} issue(s): {counts['high']} High, {counts['medium']} Medium, {counts['low']} Low. Fix high-severity security issues first, then test changes."
    return {"language": language, "findings": findings, "counts": counts, "summary": summary}
