"""Tests for the Radon analyzer."""

import unittest
from pathlib import Path

from pycq_analyzer.analyzers.radon_analyzer import RadonAnalyzer


class TestRadonAnalyzer(unittest.TestCase):
    """Test cases for the Radon analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = RadonAnalyzer(self.project_path, verbose=True)

    def test_analyzer_availability(self):
        """Test that Radon is available."""
        self.assertTrue(self.analyzer.is_available, "Radon should be available")
        self.analyzer.log_availability()

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        findings = self.analyzer.analyze()

        # Check that we found some issues
        self.assertGreater(
            len(findings),
            0,
            "Radon should find complexity issues in the sample project",
        )

        # Check that findings have the expected structure
        for finding in findings:
            self.assertIn("analyzer", finding)
            self.assertEqual(finding["analyzer"], "radon")
            self.assertIn("characteristic", finding)
            self.assertEqual(finding["characteristic"], "maintainability")
            self.assertIn("rule_id", finding)
            self.assertIn("cwe_id", finding)
            self.assertIn("severity", finding)
            self.assertIn("file_path", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

        # Print summary of findings
        print(f"\nFound {len(findings)} complexity issues with Radon:")
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
        # Our sample project has a complex function in maintainability_issues.py
        has_complexity_issue = False
        for finding in findings:
            if "complexity" in finding["rule_id"]:
                has_complexity_issue = True
                break

        self.assertTrue(
            has_complexity_issue, "Radon should detect cyclomatic complexity issues"
        )


if __name__ == "__main__":
    unittest.main()
