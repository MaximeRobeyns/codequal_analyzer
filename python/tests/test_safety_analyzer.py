"""Tests for the Safety analyzer."""

import os
import sys
import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import NamedTemporaryFile

# Add project root to path to allow imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pycq_analyzer.analyzers.safety_analyzer import SafetyAnalyzer


class TestSafetyAnalyzer(unittest.TestCase):
    """Test cases for the Safety analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent

        # Create a temporary requirements file with a known vulnerable package
        self.temp_req_file = NamedTemporaryFile(mode="w+", suffix=".txt", delete=False)
        self.temp_req_file.write("django==1.8.0\n")  # Known vulnerable version
        self.temp_req_file.close()

        # Create analyzer with the temp requirements file
        self.analyzer = SafetyAnalyzer(
            self.project_path, verbose=True, requirements_file=self.temp_req_file.name
        )

    def tearDown(self):
        """Clean up test fixture."""
        # Remove temporary file
        if os.path.exists(self.temp_req_file.name):
            os.unlink(self.temp_req_file.name)

    def test_analyzer_availability(self):
        """Test that Safety is available."""
        self.assertTrue(self.analyzer.is_available, "Safety should be available")
        self.analyzer.log_availability()

    @patch("pycq_analyzer.analyzers.safety_analyzer.run_command")
    def test_analyze_with_mock(self, mock_run_command):
        """Test analysis with mocked Safety output."""
        # Create mock output with known vulnerabilities in the new format
        mock_output = """
        +==================================================================================+

        DEPRECATED: this command (`check`) has been DEPRECATED

        +==================================================================================+

        {
            "report_meta": {
                "vulnerabilities_found": 60
            },
            "affected_packages": {
                "django": {
                    "name": "django",
                    "version": "1.8.0"
                }
            },
            "vulnerabilities": {
                "vuln1": {
                    "vulnerability_id": "12345",
                    "package_name": "django",
                    "advisory": "Security vulnerability in Django 1.8.0",
                    "vulnerable_spec": ["<1.11.0"]
                }
            }
        }

        +==================================================================================+
        """

        # Configure the mock to return our prepared output
        mock_run_command.return_value = (0, mock_output, "")

        # Run the analysis
        findings = self.analyzer.analyze()

        # Verify that the analysis produced findings
        self.assertGreater(len(findings), 0, "Mock Safety should find vulnerabilities")

        # Check that findings have the expected structure
        for finding in findings:
            self.assertIn("analyzer", finding)
            self.assertEqual(finding["analyzer"], "safety")
            self.assertIn("characteristic", finding)
            self.assertEqual(finding["characteristic"], "security")
            self.assertIn("rule_id", finding)
            self.assertIn("cwe_id", finding)
            self.assertIn("severity", finding)
            self.assertIn("file_path", finding)
            self.assertIn("message", finding)

        # Print summary of findings
        print(f"\nFound {len(findings)} security vulnerabilities with Safety:")
        severity_counts = {}

        for finding in findings:
            severity = finding["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print("\nVulnerabilities by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")

        # Verify Django vulnerabilities were found
        django_vuln_found = False
        for finding in findings:
            if "django" in finding["message"].lower():
                django_vuln_found = True
                break

        self.assertTrue(
            django_vuln_found, "Safety should detect vulnerabilities in Django 1.8.0"
        )


if __name__ == "__main__":
    unittest.main()
