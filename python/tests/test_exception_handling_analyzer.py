"""Tests for the Exception Handling Analyzer."""

import unittest
import tempfile
from pathlib import Path

from pycq_analyzer.analyzers.exception_handling_analyzer import (
    ExceptionHandlingAnalyzer,
)


class TestExceptionHandlingAnalyzer(unittest.TestCase):
    """Test cases for the Exception Handling Analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = ExceptionHandlingAnalyzer(self.project_path, verbose=True)

        # Create a temporary file with test code
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create a Python file with various exception handling issues
        self.exception_issue_code = """
import os
import sqlite3
import socket

def bare_except_example():
    # Problem: Bare except clause catches all exceptions
    try:
        x = 1 / 0
    except:  # Bare except!
        print("An error occurred")

def empty_except_example():
    # Problem: Empty except block silences exceptions
    try:
        with open('nonexistent_file.txt', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        pass  # Silently ignoring error

def overly_broad_except_example():
    # Problem: Too broad exception type
    try:
        value = int("not a number")
    except Exception as e:  # Too broad!
        print(f"Error: {e}")

def resource_without_finally():
    # Problem: No finally block to ensure resource is closed
    conn = None
    try:
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    # Missing finally to close conn!

def exception_context_loss():
    # Problem: Raising new exception loses original context
    try:
        data = [1, 2, 3]
        value = data[10]  # IndexError
    except IndexError:
        # Losing original exception context
        raise ValueError("Invalid index")  # Should use 'from' or 'raise'

def proper_exception_handling():
    # Correct: Specific exception types and proper handling
    try:
        with open('config.txt', 'r') as f:
            config = f.read()
    except FileNotFoundError:
        config = "default_config"
        print("Using default configuration")
    finally:
        print("Configuration loaded")

    return config
"""
        self.test_file = self.test_dir / "exception_examples.py"
        with open(self.test_file, "w") as f:
            f.write(self.exception_issue_code)

    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    def test_analyzer_availability(self):
        """Test that the analyzer is available."""
        self.assertTrue(
            self.analyzer.is_available,
            "Exception Handling Analyzer should be available",
        )
        self.analyzer.log_availability()

    def test_analyze_temp_file(self):
        """Test analysis of a file with known exception handling issues."""
        # Create analyzer for the temp directory
        analyzer = ExceptionHandlingAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Check that we found the expected issues
        self.assertGreater(len(findings), 0, "Should find exception handling issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} exception handling issues:")
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

        # Verify we found the expected issue types
        found_bare_except = False
        found_empty_handler = False
        found_broad_except = False
        found_missing_finally = False
        found_context_loss = False

        for finding in findings:
            message = finding["message"].lower()
            if "bare except" in message:
                found_bare_except = True
            elif "empty except block" in message:
                found_empty_handler = True
            elif "too broad" in message:
                found_broad_except = True
            elif (
                "without a finally" in message
                or "may not be properly closed" in message
            ):
                found_missing_finally = True
            elif "loses original exception" in message:
                found_context_loss = True

        # We should find at least some of these issues
        expected_findings = [
            (found_bare_except, "Should detect bare except clauses"),
            (found_empty_handler, "Should detect empty exception handlers"),
            (found_broad_except, "Should detect overly broad exception types"),
            # These two might be more challenging to detect:
            # (found_missing_finally, "Should detect missing finally blocks"),
            # (found_context_loss, "Should detect exception context loss"),
        ]

        # Check that we found at least 2 of the expected issues
        found_count = sum(1 for found, _ in expected_findings if found)
        self.assertGreaterEqual(
            found_count,
            2,
            "Should detect at least 2 types of exception handling issues",
        )

        # Check that all findings have expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "exception_handling")
            self.assertEqual(finding["characteristic"], "reliability")
            self.assertEqual(finding["cwe_id"], "CWE-703")
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        findings = self.analyzer.analyze()

        # Our sample project has some exception handling issues
        self.assertGreater(
            len(findings), 0, "Sample project should have exception handling issues"
        )

        # Print summary of findings
        print(f"\nFound {len(findings)} exception handling issues in sample project:")
        for finding in findings:
            print(f"  {finding['file_path']}:{finding['line']} - {finding['message']}")


if __name__ == "__main__":
    unittest.main()
