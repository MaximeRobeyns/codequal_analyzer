"""Tests for the Xenon analyzer."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Add project root to path to allow imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pycq_analyzer.analyzers.xenon_analyzer import XenonAnalyzer


class TestXenonAnalyzer(unittest.TestCase):
    """Test cases for the Xenon analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        # Use default thresholds for basic tests
        self.analyzer = XenonAnalyzer(self.project_path, verbose=True)

    def test_analyzer_availability(self):
        """Test that Xenon is available."""
        self.assertTrue(self.analyzer.is_available, "Xenon should be available")
        self.analyzer.log_availability()

    @patch("pycq_analyzer.analyzers.xenon_analyzer.run_command")
    def test_analyze_with_mock_output(self, mock_run_command):
        """Test analysis with mocked Xenon output."""
        # Create mock Xenon output for different violation types
        mock_stdout = """
/home/sandbox/pycq_analyzer/sample_project/maintainability_issues.py - too complex module (C > B)
/home/sandbox/pycq_analyzer/sample_project/maintainability_issues.py:10 - 'complex_function' is too complex (D > C)
/home/sandbox/pycq_analyzer/sample_project/maintainability_issues.py - average complexity is ranked C (> A)
        """

        # Set up the mock to simulate command execution with complexity issues
        mock_run_command.return_value = (
            7,
            mock_stdout,
            "",
        )  # 7 = 1+2+4 (all three types of issues)

        findings = self.analyzer.analyze()

        # Check that we found some issues
        self.assertGreater(
            len(findings), 0, "Xenon should find complexity threshold issues"
        )

        # Print summary of findings
        print(f"\nFound {len(findings)} complexity threshold issues with Xenon:")
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
        issue_types_found = set()
        for finding in findings:
            issue_types_found.add(finding["rule_id"])

        self.assertIn(
            "excessive-absolute-complexity",
            issue_types_found,
            "Xenon should detect absolute complexity issues",
        )
        self.assertIn(
            "excessive-modules-complexity",
            issue_types_found,
            "Xenon should detect modules complexity issues",
        )
        self.assertIn(
            "excessive-average-complexity",
            issue_types_found,
            "Xenon should detect average complexity issues",
        )

        # Check that all findings have the expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "xenon")
            self.assertEqual(finding["characteristic"], "maintainability")
            self.assertEqual(
                finding["cwe_id"], "CWE-1121"
            )  # Excessive McCabe Cyclomatic Complexity
            self.assertIn("severity", finding)
            self.assertIn("file_path", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    @patch("pycq_analyzer.analyzers.xenon_analyzer.run_command")
    def test_analyze_with_generic_findings(self, mock_run_command):
        """Test analysis with exit code but no detailed output."""
        # Exit code 7 means all three types of violations were found
        mock_run_command.return_value = (7, "", "")

        findings = self.analyzer.analyze()

        # We should get generic findings based on the exit code
        self.assertGreater(
            len(findings), 0, "Xenon should create generic findings based on exit code"
        )

        # Verify that all three types of generic findings were created
        issue_types = [finding["rule_id"] for finding in findings]
        self.assertIn("excessive-absolute-complexity", issue_types)
        self.assertIn("excessive-modules-complexity", issue_types)
        self.assertIn("excessive-average-complexity", issue_types)

    def test_analyze_sample_project_with_strict_thresholds(self):
        """Test analysis of the sample project with actual Xenon using strict thresholds."""
        # This test will be skipped if Xenon is not available
        if not self.analyzer.is_available:
            self.skipTest("Xenon is not available")

        # Create a new analyzer with very strict thresholds - even good code would fail these
        strict_analyzer = XenonAnalyzer(
            self.project_path,
            verbose=True,
            max_absolute="A",  # Strictest possible threshold for functions
            max_modules="A",  # Strictest possible threshold for modules
            max_average="A",  # Strictest possible threshold for average complexity
        )

        # Run the analysis with strict thresholds
        findings = strict_analyzer.analyze()

        # Check that we found some issues with these strict thresholds
        self.assertGreater(
            len(findings),
            0,
            "Xenon should find complexity issues with strict thresholds in the sample project",
        )

        # Print summary of findings
        print(
            f"\nFound {len(findings)} complexity threshold issues with strict Xenon thresholds:"
        )

        # Check that all findings have the expected structure
        for finding in findings:
            self.assertIn("analyzer", finding)
            self.assertEqual(finding["analyzer"], "xenon")
            self.assertIn("characteristic", finding)
            self.assertEqual(finding["characteristic"], "maintainability")
            self.assertIn("rule_id", finding)
            self.assertIn("cwe_id", finding)
            self.assertIn("severity", finding)
            self.assertIn("file_path", finding)
            self.assertIn("message", finding)


if __name__ == "__main__":
    unittest.main()
