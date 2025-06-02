"""Tests for the Resource Consumption Analyzer."""

import unittest
import tempfile
from pathlib import Path

from pycq_analyzer.analyzers.resource_consumption_analyzer import (
    ResourceConsumptionAnalyzer,
)


class TestResourceConsumptionAnalyzer(unittest.TestCase):
    """Test cases for the Resource Consumption Analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = ResourceConsumptionAnalyzer(self.project_path, verbose=True)

        # Create a temporary file with test code
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create a Python file with resource consumption in loops
        self.excessive_resource_code = """
import time
import random
import socket
import requests
from io import StringIO

def resource_intensive_function(iterations):
    # Resource-intensive operations within a loop
    result = []
    for i in range(iterations):
        # Time-consuming operation
        time.sleep(0.01)  # Resource: blocking/time
        # Create large objects
        data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=1000))
        result.append(data)  # Growing data structure
    return result

def multiple_api_calls(items):
    results = []
    for item in items:
        # Network operation in a loop
        response = requests.get(f"https://api.example.com/{item}")
        results.append(response.json())
    return results

def file_operations_in_loop(files):
    content = []
    for file_path in files:
        # File I/O in a loop
        with open(file_path, 'r') as f:
            content.append(f.read())
    return content

def nested_loop_consumption():
    result = []
    # Nested loops with resource consumption
    for i in range(10):
        inner_result = []
        for j in range(10):
            # Resources consumed in nested loop
            time.sleep(0.001)  # Blocking in nested loop
            inner_result.append(random.random())
        result.append(inner_result)
    return result
"""
        self.test_file = self.test_dir / "resource_test.py"
        with open(self.test_file, "w") as f:
            f.write(self.excessive_resource_code)

    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    def test_analyzer_availability(self):
        """Test that the analyzer is available."""
        self.assertTrue(
            self.analyzer.is_available,
            "Resource Consumption Analyzer should be available",
        )
        self.analyzer.log_availability()

    def test_analyze_temp_file(self):
        """Test analysis of a file with known resource consumption issues."""
        # Create analyzer for the temp directory
        analyzer = ResourceConsumptionAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Check that we found the expected issues
        self.assertGreater(len(findings), 0, "Should find resource consumption issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} resource consumption issues:")
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

        # Verify we found both types of issues
        found_sleep = False
        found_io = False

        for finding in findings:
            message = finding["message"].lower()
            if "sleep" in message:
                found_sleep = True
            elif "open" in message or "requests" in message or "get" in message:
                found_io = True

        self.assertTrue(found_sleep, "Should detect sleep/blocking operation in loops")
        self.assertTrue(found_io, "Should detect I/O operations in loops")

        # Check that all findings have expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "resource_consumption")
            self.assertEqual(finding["characteristic"], "performance")
            self.assertEqual(finding["cwe_id"], "CWE-1050")
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        # Analyze the actual sample project
        findings = self.analyzer.analyze()

        # Sample project has at least one example of resource consumption in loops
        self.assertGreater(
            len(findings), 0, "Sample project should have resource consumption issues"
        )

        # Print summary
        print(f"\nFound {len(findings)} resource consumption issues in sample project:")
        for finding in findings:
            print(f"  {finding['file_path']}:{finding['line']} - {finding['message']}")


if __name__ == "__main__":
    unittest.main()
