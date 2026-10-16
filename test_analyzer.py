import unittest
from analyzer import analyze_code

class AnalyzerTests(unittest.TestCase):
    def test_secret(self):
        result = analyze_code('password = "abc12345"', "Python")
        self.assertTrue(any(x["rule_id"] == "SEC-001" for x in result["findings"]))

    def test_eval(self):
        result = analyze_code("x = eval(user_input)", "Python")
        self.assertTrue(any(x["rule_id"] == "SEC-003" for x in result["findings"]))

if __name__ == "__main__":
    unittest.main()
