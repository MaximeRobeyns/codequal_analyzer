"""Tests for the Data Structure Complexity Analyzer."""

import unittest
import tempfile
from pathlib import Path

from pycq_analyzer.analyzers.data_structure_analyzer import (
    DataStructureComplexityAnalyzer,
)


class TestDataStructureAnalyzer(unittest.TestCase):
    """Test cases for the Data Structure Complexity Analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = DataStructureComplexityAnalyzer(self.project_path, verbose=True)

        # Create a temporary file with test code
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create a Python file with complex data structures
        self.complex_data_code = """
# Complex data structure with excessive nesting
class ComplexNestedData:
    def __init__(self):
        # Excessive nesting
        self.data = {
            'level1': {
                'a': 1,
                'b': 2,
                'level2': {
                    'c': 3,
                    'd': 4,
                    'level3': {
                        'e': 5,
                        'f': 6,
                        'level4': {
                            'g': 7,
                            'h': 8,
                            'level5': {
                                'i': 9,
                                'j': 10,
                                'level6': {
                                    'k': 11,
                                    'l': 12
                                }
                            }
                        }
                    }
                }
            }
        }

# Class with too many attributes
class TooManyAttributes:
    def __init__(self):
        self.attr1 = 1
        self.attr2 = 2
        self.attr3 = 3
        self.attr4 = 4
        self.attr5 = 5
        self.attr6 = 6
        self.attr7 = 7
        self.attr8 = 8
        self.attr9 = 9
        self.attr10 = 10
        self.attr11 = 11
        self.attr12 = 12

# Large dictionary literal
def create_large_dict():
    return {
        'key1': 'value1',
        'key2': 'value2',
        'key3': 'value3',
        'key4': 'value4',
        'key5': 'value5',
        'key6': 'value6',
        'key7': 'value7',
        'key8': 'value8',
        'key9': 'value9',
        'key10': 'value10',
        'key11': 'value11',
        'key12': 'value12'
    }

# Complex object creation with many arguments
def create_complex_object():
    return ComplexObject(
        param1='value1',
        param2='value2',
        param3='value3',
        param4='value4',
        param5='value5',
        param6='value6',
        param7='value7',
        param8='value8',
        param9='value9',
        param10='value10',
        param11='value11'
    )
"""
        self.test_file = self.test_dir / "complex_data.py"
        with open(self.test_file, "w") as f:
            f.write(self.complex_data_code)

    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    def test_analyzer_availability(self):
        """Test that the analyzer is available."""
        self.assertTrue(
            self.analyzer.is_available,
            "Data Structure Complexity Analyzer should be available",
        )
        self.analyzer.log_availability()

    def test_analyze_temp_file(self):
        """Test analysis of a file with known complex data structures."""
        # Create analyzer for the temp directory
        analyzer = DataStructureComplexityAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Check that we found the expected issues
        self.assertGreater(
            len(findings), 0, "Should find complex data structure issues"
        )

        # Print summary of findings
        print(f"\nFound {len(findings)} complex data structure issues:")
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

        # Verify we found both too many attributes and excessive nesting
        found_too_many_attributes = False
        found_excessive_nesting = False

        for finding in findings:
            message = finding["message"].lower()
            if "attributes" in message and "class" in message:
                found_too_many_attributes = True
            elif "nesting" in message and (
                "dict" in message or "dictionary" in message
            ):
                found_excessive_nesting = True

        self.assertTrue(
            found_too_many_attributes, "Should detect classes with too many attributes"
        )
        self.assertTrue(
            found_excessive_nesting,
            "Should detect excessive nesting in data structures",
        )

        # Check that all findings have expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "data_structure_complexity")
            self.assertEqual(finding["characteristic"], "performance")
            self.assertEqual(finding["cwe_id"], "CWE-1043")
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        # Analyze the actual sample project
        findings = self.analyzer.analyze()

        # Sample project has at least one example of a complex data structure
        self.assertGreater(
            len(findings), 0, "Sample project should have complex data structure issues"
        )

        # Print summary
        print(
            f"\nFound {len(findings)} complex data structure issues in sample project:"
        )
        for finding in findings:
            print(f"  {finding['file_path']}:{finding['line']} - {finding['message']}")


if __name__ == "__main__":
    unittest.main()
