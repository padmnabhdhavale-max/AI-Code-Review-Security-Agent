from pathlib import Path
from collections import Counter
import re, math
KB = Path(__file__).parent / "knowledge_base" / "secure_coding.md"

def tokens(text):
    return re.findall(r"[a-zA-Z0-9_+#.-]+", text.lower())

def answer_question(question, review_result=None):
    chunks = [c.strip() for c in KB.read_text(encoding="utf-8").split("\n## ") if c.strip()]
    query = set(tokens(question))
    ranked = []
    for chunk in chunks:
        terms = tokens(chunk)
        counts = Counter(terms)
        score = sum(1 + math.log(counts[t]) for t in query if t in counts)
        if score:
            ranked.append((score / (len(set(terms)) ** .35), chunk))
    ranked.sort(reverse=True)
    answer = "### Retrieved secure-coding guidance\\n"
    answer += "\n".join("- " + c.replace("#", "").strip() for _, c in ranked[:3]) if ranked else "No close match found. Try SQL injection, XSS, secrets, input validation, passwords, or access control."
    if review_result and review_result.get("findings"):
        answer += "\n\n### From your latest review\\n"
        answer += "\n".join(f'- **{f["title"]} ({f["severity"]}):** {f["recommendation"]}' for f in review_result["findings"][:4])
    return answer + "\n\n*Keyword-based retrieval only; verify advice for your framework and context.*"
