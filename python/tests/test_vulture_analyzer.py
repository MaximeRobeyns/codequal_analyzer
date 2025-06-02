"""Tests for the Vulture analyzer."""

import unittest
from pathlib import Path
from unittest.mock import patch

from pycq_analyzer.analyzers.vulture_analyzer import VultureAnalyzer


class TestVultureAnalyzer(unittest.TestCase):
    """Test cases for the Vulture analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = VultureAnalyzer(self.project_path, verbose=True)

    def test_analyzer_availability(self):
        """Test that Vulture is available."""
        self.assertTrue(self.analyzer.is_available, "Vulture should be available")
        self.analyzer.log_availability()

    @patch("pycq_analyzer.analyzers.vulture_analyzer.run_command")
    def test_analyze_with_mock_output(self, mock_run_command):
        """Test analysis with mocked Vulture output."""
        # Create mock Vulture output
        mock_stdout = """
/home/sandbox/pycq_analyzer/sample_project/maintainability_issues.py:3: unused function 'unused_function' (confidence: 100%)
/home/sandbox/pycq_analyzer/sample_project/maintainability_issues.py:45: unused variable 'goto_end' (confidence: 60%)
        """

        # Set up the mock to simulate successful command execution
        mock_run_command.return_value = (0, mock_stdout, "")

        findings = self.analyzer.analyze()

        # Check that we found some issues
        self.assertGreater(len(findings), 0, "Vulture should find issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} dead code issues with Vulture:")
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

        # Check for specific issue types
        found_unused_function = False
        found_unused_variable = False

        for finding in findings:
            if finding["rule_id"] == "unused-function":
                found_unused_function = True
            elif finding["rule_id"] == "unused-variable":
                found_unused_variable = True

        self.assertTrue(found_unused_function, "Vulture should detect unused functions")
        self.assertTrue(found_unused_variable, "Vulture should detect unused variables")

        # Check that all findings have the expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "vulture")
            self.assertEqual(finding["characteristic"], "maintainability")
            self.assertEqual(finding["cwe_id"], "CWE-561")  # Dead Code

    def test_severity_from_confidence(self):
        """Test severity determination from confidence level."""
        self.assertEqual(self.analyzer._severity_from_confidence(50), "low")
        self.assertEqual(self.analyzer._severity_from_confidence(70), "medium")
        self.assertEqual(self.analyzer._severity_from_confidence(95), "high")


if __name__ == "__main__":
    unittest.main()
