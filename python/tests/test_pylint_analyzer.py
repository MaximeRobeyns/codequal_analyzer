"""Tests for the Pylint analyzer."""

import unittest
from pathlib import Path

from pycq_analyzer.analyzers.pylint_analyzer import PylintAnalyzer


class TestPylintAnalyzer(unittest.TestCase):
    """Test cases for the Pylint analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = PylintAnalyzer(self.project_path, verbose=True)

    def test_analyzer_availability(self):
        """Test that Pylint is available."""
        self.assertTrue(self.analyzer.is_available, "Pylint should be available")
        self.analyzer.log_availability()

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        findings = self.analyzer.analyze()

        # Check that we found some issues
        self.assertGreater(
            len(findings), 0, "Pylint should find issues in the sample project"
        )

        # Check that findings have the expected structure
        for finding in findings:
            self.assertIn("analyzer", finding)
            self.assertEqual(finding["analyzer"], "pylint")
            self.assertIn("characteristic", finding)
            self.assertEqual(finding["characteristic"], "maintainability")
            self.assertIn("rule_id", finding)
            self.assertIn("cwe_id", finding)
            self.assertIn("severity", finding)
            self.assertIn("file_path", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

        # Print summary of findings
        print(f"\nFound {len(findings)} maintainability issues with Pylint:")
        severity_counts = {}
        rule_counts = {}

        for finding in findings:
            severity = finding["severity"]
            rule_id = finding["rule_id"]

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

        print("\nIssues by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        print("\nIssues by rule:")
        for rule_id, count in rule_counts.items():
            print(f"  {rule_id}: {count}")

        # Check for specific issue types we expect to find
        rule_ids = [finding["rule_id"] for finding in findings]
        expected_rules = ["unused-import", "unused-variable", "too-many-arguments"]

        for rule in expected_rules:
            self.assertIn(rule, rule_ids, f"Pylint should detect {rule} issues")


if __name__ == "__main__":
    unittest.main()
