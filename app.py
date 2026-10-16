import json
import streamlit as st
from analyzer import analyze_code
from rag_assistant import answer_question
from report import build_report

st.set_page_config(page_title="AI Code Review Agent", page_icon="🛡️", layout="wide")
st.title("AI Code Review & Security Analysis Agent")
st.caption("Educational prototype for Python and Java code. Findings require human verification.")
with st.sidebar:
    language = st.selectbox("Language", ["Python", "Java"])
    st.info("This prototype is not a substitute for a professional security audit.")
review_tab, assistant_tab, about_tab = st.tabs(["Code Review", "Code Assistant", "About"])
with review_tab:
    uploaded = st.file_uploader("Upload a .py or .java file (optional)", type=["py", "java"])
    samples = {
        "Python": 'import sqlite3\\npassword = "admin123"\\ndef get_user(user_id):\\n    query = "SELECT * FROM users WHERE id = " + user_id\\n',
        "Java": 'public class UserService {\\n String password = "admin123";\\n String query = "SELECT * FROM users WHERE id = " + userId;\\n}'
    }
    code = uploaded.read().decode("utf-8", errors="replace") if uploaded else st.text_area("Paste source code", value=samples[language], height=260)
    if st.button("Analyze code", type="primary"):
        if not code.strip():
            st.warning("Paste code or upload a file first.")
        else:
            st.session_state.review = analyze_code(code, language)
            st.session_state.source = code
            st.session_state.language = language
    if "review" in st.session_state:
        result = st.session_state.review
        a, b, c, d = st.columns(4)
        a.metric("Total", result["counts"]["total"])
        b.metric("High", result["counts"]["high"])
        c.metric("Medium", result["counts"]["medium"])
        d.metric("Low", result["counts"]["low"])
        st.subheader("Pull request summary")
        st.write(result["summary"])
        for i, finding in enumerate(result["findings"], 1):
            with st.expander(f'{i}. [{finding["severity"]}] {finding["title"]}'):
                st.write(finding["description"])
                st.markdown("**Potential impact**")
                st.write(finding["impact"])
                st.markdown("**Suggested remediation**")
                st.write(finding["recommendation"])
                if finding.get("fixed_example"):
                    st.code(finding["fixed_example"], language=language.lower())
        st.download_button("Download Markdown report", build_report(st.session_state.language, st.session_state.source, result), "code_review_report.md", "text/markdown")
        st.download_button("Download JSON findings", json.dumps(result, indent=2), "findings.json", "application/json")
with assistant_tab:
    st.write("Ask about secure coding practices or your latest review.")
    question = st.text_input("Question", placeholder="How do I prevent SQL injection?")
    if st.button("Ask") and question.strip():
        st.session_state.answer = answer_question(question, st.session_state.get("review"))
    if st.session_state.get("answer"):
        st.markdown(st.session_state.answer)
with about_tab:
    st.markdown("**Modules:** Code Submission, Code Analysis Agent, Security Vulnerability Agent, Remediation Agent, PR Summary Agent, local RAG-style assistant, report export.\\n\\n**Limitations:** Regex checks can miss issues or report false positives. The assistant uses keyword retrieval, not an LLM or embedding model. A clean scan does not prove code is secure.")
