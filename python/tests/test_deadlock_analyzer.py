"""Tests for the Deadlock Detector Analyzer."""

import unittest
import tempfile
from pathlib import Path

from pycq_analyzer.analyzers.deadlock_analyzer import DeadlockAnalyzer


class TestDeadlockAnalyzer(unittest.TestCase):
    """Test cases for the Deadlock Detector Analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = DeadlockAnalyzer(self.project_path, verbose=True)

        # Create a temporary file with test code
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create a Python file with various deadlock scenarios
        self.deadlock_code = """
import threading

class PotentialDeadlock:
    def __init__(self):
        self.lock_a = threading.Lock()
        self.lock_b = threading.Lock()

    def operation_a(self):
        # Acquire locks in one order
        with self.lock_a:
            print("Holding lock_a")
            # Do something while holding lock_a
            with self.lock_b:
                print("Holding lock_a and lock_b")
                # Do something while holding both locks
        return "Done with operation_a"

    def operation_b(self):
        # Acquire locks in the opposite order - potential deadlock!
        with self.lock_b:
            print("Holding lock_b")
            # Do something while holding lock_b
            with self.lock_a:
                print("Holding lock_b and lock_a")
                # Do something while holding both locks
        return "Done with operation_b"

class NoDeadlock:
    def __init__(self):
        self.lock = threading.Lock()

    def operation_a(self):
        with self.lock:
            print("Safely using lock")
        return "Done safely"

    def operation_b(self):
        with self.lock:
            print("Also safely using lock")
        return "Also done safely"

class UnreleasedLock:
    def __init__(self):
        self.lock = threading.Lock()

    def bad_operation(self):
        # Manually acquire without release
        self.lock.acquire()
        print("Acquired lock but never releasing it")
        # Missing lock.release()
        return "Oops, didn't release the lock"

class NestedLocks:
    def __init__(self):
        self.lock_a = threading.Lock()
        self.lock_b = threading.Lock()
        self.lock_c = threading.Lock()

    def nested_operation(self):
        # Nested locks in a safe order
        with self.lock_a:
            print("Acquired lock_a")
            with self.lock_b:
                print("Acquired lock_b")
                with self.lock_c:
                    print("Acquired lock_c")
        return "Safely released all locks"
"""
        self.test_file = self.test_dir / "deadlock_examples.py"
        with open(self.test_file, "w") as f:
            f.write(self.deadlock_code)

    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    def test_analyzer_availability(self):
        """Test that the analyzer is available."""
        self.assertTrue(
            self.analyzer.is_available, "Deadlock Analyzer should be available"
        )
        self.analyzer.log_availability()

    def test_analyze_temp_file(self):
        """Test analysis of a file with known deadlock issues."""
        # Create analyzer for the temp directory
        analyzer = DeadlockAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Check that we found the expected issues
        self.assertGreater(len(findings), 0, "Should find deadlock issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} deadlock issues:")
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

        # Verify we found at least potential deadlock due to lock ordering
        found_potential_deadlock = False
        found_unreleased_lock = False

        for finding in findings:
            message = finding["message"].lower()
            if "potential deadlock" in message or "different orders" in message:
                found_potential_deadlock = True
            elif "not release all" in message or "may not release" in message:
                found_unreleased_lock = True

        # We should find at least the potential deadlock issue
        self.assertTrue(
            found_potential_deadlock,
            "Should detect potential deadlocks due to different lock ordering",
        )

        # Check that all findings have expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "deadlock_detection")
            self.assertEqual(finding["characteristic"], "reliability")
            self.assertEqual(finding["cwe_id"], "CWE-833")
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        # Analyze the actual sample project
        findings = self.analyzer.analyze()

        # Print summary of findings
        print(f"\nFound {len(findings)} deadlock issues in sample project:")
        for finding in findings:
            print(f"  {finding['file_path']}:{finding['line']} - {finding['message']}")

        # Sample project may or may not have deadlock issues
        # Just verify the analysis runs without crashing


if __name__ == "__main__":
    unittest.main()
