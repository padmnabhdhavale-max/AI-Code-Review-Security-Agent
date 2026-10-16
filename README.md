# AI Code Review & Security Analysis Agent

## Run on Windows
1. Install Python 3.10 or newer.
2. Extract this ZIP and open Command Prompt in this folder.
3. Run:
   ```bat
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   streamlit run app.py
   ```
4. Open the local URL shown in the terminal, usually http://localhost:8501.

## Features
- Paste code or upload Python/Java source
- Heuristic code-quality and security checks
- Severity-scored findings, explanations, and remediation suggestions
- PR-style summary and Markdown/JSON report export
- Local secure-coding Q&A retrieval

## Architecture
app.py -> analyzer.py -> findings and report.py
app.py -> rag_assistant.py -> knowledge_base/secure_coding.md

## Mapping to the project document
Code Analysis Agent: code-quality checks.
Security Vulnerability Agent: selected SQL injection, hardcoded-secret, dynamic-execution, and unsafe-HTML patterns.
Remediation Agent: recommendations and safer examples attached to findings.
PR Summary Agent: severity counts and review summary.
Conversational Code Assistant: keyword retrieval from the local guide.

## Limitations
This educational prototype uses regex heuristics, not a complete parser or commercial-grade SAST engine. It may miss vulnerabilities and produce false positives. CSRF and broken access control are covered in the guide but not comprehensively detected. The assistant uses keyword scoring, not embeddings or an LLM. A clean scan does not prove code is secure. Do not upload confidential source code unless permitted.
