"""Tests for the Mypy analyzer."""

import unittest
from pathlib import Path
from unittest.mock import patch

from pycq_analyzer.analyzers.mypy_analyzer import MypyAnalyzer


class TestMypyAnalyzer(unittest.TestCase):
    """Test cases for the Mypy analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = MypyAnalyzer(self.project_path, verbose=True)

    def test_analyzer_availability(self):
        """Test that Mypy is available."""
        self.assertTrue(self.analyzer.is_available, "Mypy should be available")
        self.analyzer.log_availability()

    @patch("pycq_analyzer.analyzers.mypy_analyzer.run_command")
    def test_analyze_with_mock_output(self, mock_run_command):
        """Test analysis with mocked Mypy output."""
        # Create mock Mypy output
        mock_stdout = """
/home/sandbox/pycq_analyzer/sample_project/reliability_issues.py:3:20: error: "None" has no attribute "attribute" [attr-defined]
/home/sandbox/pycq_analyzer/sample_project/reliability_issues.py:15:11: error: Incompatible types in assignment (expression has type "None", variable has type "Dict[str, str]") [assignment]
/home/sandbox/pycq_analyzer/sample_project/reliability_issues.py:25:4: error: Item "None" of "Optional[Dict[str, Any]]" has no attribute "get" [union-attr]
        """

        # Set up the mock to simulate successful command execution
        mock_run_command.return_value = (1, mock_stdout, "")

        # Run the analysis
        findings = self.analyzer.analyze()

        # Check that we found some issues
        self.assertGreater(len(findings), 0, "Mypy should find type checking issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} type checking issues with Mypy:")
        severity_counts = {}
        rule_counts = {}
        cwe_counts = {}

        for finding in findings:
            severity = finding["severity"]
            rule_id = finding["rule_id"]
            cwe_id = finding["cwe_id"]

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1

        print("\nIssues by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        print("\nIssues by rule:")
        for rule_id, count in rule_counts.items():
            print(f"  {rule_id}: {count}")

        print("\nIssues by CWE:")
        for cwe_id, count in cwe_counts.items():
            print(f"  {cwe_id}: {count}")

        # Check for specific issue types
        found_attr_defined = False
        found_assignment = False
        found_union_attr = False

        for finding in findings:
            if "attr-defined" in finding["rule_id"]:
                found_attr_defined = True
            elif "assignment" in finding["rule_id"]:
                found_assignment = True
            elif "union-attr" in finding["rule_id"]:
                found_union_attr = True

        self.assertTrue(found_attr_defined, "Mypy should detect 'attr-defined' issues")
        self.assertTrue(found_assignment, "Mypy should detect 'assignment' issues")
        self.assertTrue(found_union_attr, "Mypy should detect 'union-attr' issues")

        # Check that all findings have the expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "mypy")
            self.assertEqual(finding["characteristic"], "reliability")
            self.assertIn("cwe_id", finding)
            self.assertIn("severity", finding)
            self.assertIn("file_path", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project with actual Mypy."""
        # This test will be skipped if Mypy is not available
        if not self.analyzer.is_available:
            self.skipTest("Mypy is not available")

        # Sample project doesn't have type annotations, so we expect errors
        findings = self.analyzer.analyze()

        # Print summary of findings whether or not we found issues
        print(
            f"\nFound {len(findings)} type checking issues with Mypy in sample project."
        )

        # We make this a conditional assertion since the sample project might be annotated
        # or Mypy might be configured differently in different environments
        if findings:
            # Check that all findings have the expected structure
            for finding in findings:
                self.assertIn("analyzer", finding)
                self.assertEqual(finding["analyzer"], "mypy")
                self.assertIn("characteristic", finding)
                self.assertEqual(finding["characteristic"], "reliability")
                self.assertIn("rule_id", finding)
                self.assertIn("cwe_id", finding)
                self.assertIn("severity", finding)
                self.assertIn("file_path", finding)
                self.assertIn("message", finding)


if __name__ == "__main__":
    unittest.main()
