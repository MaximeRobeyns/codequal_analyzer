"""Tests for the String Concatenation analyzer."""

import unittest
import tempfile
from pathlib import Path

from pycq_analyzer.analyzers.string_concat_analyzer import StringConcatenationAnalyzer


class TestStringConcatenationAnalyzer(unittest.TestCase):
    """Test cases for the String Concatenation analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = StringConcatenationAnalyzer(self.project_path, verbose=True)

        # Create a temporary file with test code
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create a Python file with inefficient string concatenation
        self.inefficient_code = """
def build_large_string(size):
    # Inefficient string concatenation in a loop
    result = ""
    for i in range(size):
        result = result + str(i) + " "  # Inefficient
    return result

def another_inefficient(items):
    text = ""
    for item in items:
        text += str(item)  # Inefficient
    return text

def efficient_code(items):
    # Efficient approach using join
    return "".join(str(item) for item in items)
"""
        self.test_file = self.test_dir / "test_concat.py"
        with open(self.test_file, "w") as f:
            f.write(self.inefficient_code)

    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    def test_analyzer_availability(self):
        """Test that the analyzer is available."""
        self.assertTrue(
            self.analyzer.is_available,
            "String Concatenation Analyzer should be available",
        )
        self.analyzer.log_availability()

    def test_analyze_temp_file(self):
        """Test analysis of a file with known string concatenation issues."""
        # Create analyzer for the temp directory
        analyzer = StringConcatenationAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Check that we found the expected issues
        self.assertGreater(len(findings), 0, "Should find string concatenation issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} string concatenation issues:")
        severity_counts = {}

        for finding in findings:
            severity = finding["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            print(
                f"  {finding['file_path']}:{finding['line']} - {finding['message']} (Severity: {severity})"
            )

        print("\nIssues by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        # Verify we found both inefficient patterns
        found_plus_operator = False
        found_plus_equals = False

        for finding in findings:
            message = finding["message"].lower()
            if "+=" in message:
                found_plus_equals = True
            elif "'+'" in message:
                found_plus_operator = True

        self.assertTrue(found_plus_operator, "Should detect '+' operator in loops")
        self.assertTrue(found_plus_equals, "Should detect '+=' operator in loops")

        # Check that all findings have expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "string_concatenation")
            self.assertEqual(finding["characteristic"], "performance")
            self.assertEqual(finding["cwe_id"], "CWE-1046")
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        # Analyze the actual sample project
        findings = self.analyzer.analyze()

        # Sample project has at least one example of inefficient concatenation
        self.assertGreater(
            len(findings), 0, "Sample project should have string concatenation issues"
        )

        # Print summary
        print(f"\nFound {len(findings)} string concatenation issues in sample project:")
        for finding in findings:
            print(f"  {finding['file_path']}:{finding['line']} - {finding['message']}")


if __name__ == "__main__":
    unittest.main()
