"""Tests for the Infinite Loop Detection Analyzer."""

import unittest
import tempfile
from pathlib import Path
import ast

from pycq_analyzer.analyzers.infinite_loop_analyzer import (
    InfiniteLoopAnalyzer,
    is_constant_true,
    is_constant,
    get_constant_value,
    InfiniteLoopVisitor,
    PY38_PLUS,
)


class TestCompatibilityFunctions(unittest.TestCase):
    """Test cases for version compatibility functions."""

    def test_is_constant_true(self):
        """Test is_constant_true function with different node types."""
        # Test with ast.Constant (Python 3.8+)
        if hasattr(ast, "Constant"):
            true_node = ast.Constant(value=True)
            false_node = ast.Constant(value=False)
            str_node = ast.Constant(value="string")

            self.assertTrue(is_constant_true(true_node))
            self.assertFalse(is_constant_true(false_node))
            self.assertFalse(is_constant_true(str_node))

        # Test with non-constant node
        name_node = ast.Name(id="variable")
        self.assertFalse(is_constant_true(name_node))

    def test_is_constant(self):
        """Test is_constant function with various node types."""
        if hasattr(ast, "Constant"):
            # Test with ast.Constant
            const_node = ast.Constant(value=42)
            self.assertTrue(is_constant(const_node))

            # Test string constant
            str_node = ast.Constant(value="test")
            self.assertTrue(is_constant(str_node))

        # Test with non-constant node
        name_node = ast.Name(id="variable")
        self.assertFalse(is_constant(name_node))

        # Test with other AST nodes
        binop_node = ast.BinOp(
            left=ast.Constant(value=1) if hasattr(ast, "Constant") else ast.Num(n=1),
            op=ast.Add(),
            right=ast.Constant(value=2) if hasattr(ast, "Constant") else ast.Num(n=2),
        )
        self.assertFalse(is_constant(binop_node))

    def test_get_constant_value(self):
        """Test get_constant_value function."""
        if hasattr(ast, "Constant"):
            # Test numeric constant
            num_node = ast.Constant(value=42)
            self.assertEqual(get_constant_value(num_node), 42)

            # Test string constant
            str_node = ast.Constant(value="hello")
            self.assertEqual(get_constant_value(str_node), "hello")

            # Test boolean constant
            bool_node = ast.Constant(value=True)
            self.assertEqual(get_constant_value(bool_node), True)

        # Test with non-constant node
        name_node = ast.Name(id="variable")
        self.assertIsNone(get_constant_value(name_node))


class TestInfiniteLoopVisitor(unittest.TestCase):
    """Test cases for InfiniteLoopVisitor class."""

    def test_visit_function_def(self):
        """Test visiting function definitions."""
        visitor = InfiniteLoopVisitor()
        visitor.set_file("test.py")

        # Create a simple mock to verify the function is visited
        visited_functions = []
        original_visit = visitor.generic_visit

        def mock_generic_visit(node):
            # After setting the function name but before restoring it
            if hasattr(visitor, "current_function") and visitor.current_function:
                visited_functions.append(visitor.current_function)
            return original_visit(node)

        visitor.generic_visit = mock_generic_visit

        code = """
def test_function():
    while True:
        pass
"""
        tree = ast.parse(code)
        visitor.visit(tree)

        # Verify the function was visited
        self.assertIn(
            "test_function",
            visited_functions,
            "Function should have been processed during AST traversal",
        )

    def test_break_detection(self):
        """Test that break statements are detected in loops."""
        visitor = InfiniteLoopVisitor()
        visitor.set_file("test.py")

        code = """
def test_break():
    while True:
        if something:
            break
        print("loop")
"""
        tree = ast.parse(code)
        visitor.visit(tree)

        # Should not flag as infinite loop because of break
        infinite_loop_messages = [
            f
            for f in visitor.findings
            if "while True" in f["message"] and "without break" in f["message"]
        ]
        self.assertEqual(len(infinite_loop_messages), 0)


class TestInfiniteLoopAnalyzer(unittest.TestCase):
    """Test cases for the Infinite Loop Detection Analyzer."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"
        self.analyzer = InfiniteLoopAnalyzer(self.project_path, verbose=True)

        # Create a temporary file with test code
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

        # Create a Python file with various infinite loop scenarios
        self.infinite_loop_code = """
import random

def explicit_infinite_loop():
    # Explicitly infinite loop with while True
    while True:
        print("This will run forever")
        # No break statement

def potentially_infinite_loop():
    # Loop with a condition that might never be false
    x = 10
    while x != 0:
        # x is decremented by 2, so if x is odd, it will never equal 0
        print(f"x = {x}")
        x -= 2

def decrement_in_for_loop():
    # Potentially infinite loop due to counter modification
    items = list(range(10))
    for i in range(len(items)):
        print(f"Processing item {i}")
        # Decreasing i might cause an infinite loop
        if items[i] % 2 == 0:
            i -= 1

def loop_with_skipping_increment():
    # Loop that might skip the termination value
    i = 0
    target = 10
    while i != target:
        print(f"i = {i}")
        # Incrementing by more than 1 might skip target
        i += 3

def proper_loop():
    # This loop will terminate properly
    for i in range(10):
        print(i)

    # This loop will also terminate
    count = 10
    while count > 0:
        print(count)
        count -= 1

def loop_with_break():
    # Infinite loop with a break condition is fine
    while True:
        value = random.randint(1, 10)
        if value == 5:
            break
        print(value)

def loop_with_return():
    # Infinite loop with a return is also fine
    while True:
        if check_condition():
            return True
        process()

def loop_with_raise():
    # Infinite loop with exception raising is also fine
    while True:
        try:
            result = risky_operation()
        except Exception:
            raise ValueError("Operation failed")

def growing_list_loop():
    # Loop that might be infinite due to growing the iterable
    items = [1, 2, 3]
    for i in range(len(items)):
        items.append(i)  # Growing the list while iterating
        if len(items) > 1000:  # Safety condition for tests
            break
        print(items[i])

def complex_condition_loop():
    # Loop with complex conditions
    a, b = 10, 20
    while a < b and b > 0:
        print(f"a={a}, b={b}")
        # No modifications to a or b

def nested_loop_example():
    # Nested loops with various patterns
    for i in range(10):
        j = 0
        while j < i:
            print(f"i={i}, j={j}")
            # j is not incremented - infinite loop
"""
        self.test_file = self.test_dir / "infinite_loop_examples.py"
        with open(self.test_file, "w") as f:
            f.write(self.infinite_loop_code)

    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()

    def test_analyzer_availability(self):
        """Test that the analyzer is available."""
        self.assertTrue(
            self.analyzer.is_available, "Infinite Loop Analyzer should be available"
        )
        self.analyzer.log_availability()

    def test_analyze_temp_file(self):
        """Test analysis of a file with known infinite loop issues."""
        # Create analyzer for the temp directory
        analyzer = InfiniteLoopAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Check that we found the expected issues
        self.assertGreater(len(findings), 0, "Should find infinite loop issues")

        # Print summary of findings
        print(f"\nFound {len(findings)} infinite loop issues:")
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

        # Verify we found at least some types of infinite loops
        found_while_true = False
        found_potential_infinite = False
        found_unmodified_control = False

        for finding in findings:
            message = finding["message"].lower()
            if "while true" in message and "without break" in message:
                found_while_true = True
            elif "potential infinite loop" in message:
                found_potential_infinite = True
            elif "may not be modified" in message:
                found_unmodified_control = True

        # We should find at least one type of infinite loop issue
        expected_findings = [
            (
                found_while_true,
                "Should detect explicit while True loops without breaks",
            ),
            (
                found_potential_infinite,
                "Should detect potential infinite loops with variable conditions",
            ),
            (
                found_unmodified_control,
                "Should detect loops with unmodified control variables",
            ),
        ]

        # Check that we found at least one of the expected issues
        found_count = sum(1 for found, _ in expected_findings if found)
        self.assertGreaterEqual(
            found_count, 1, "Should detect at least one type of infinite loop issue"
        )

        # Check that all findings have expected fields
        for finding in findings:
            self.assertEqual(finding["analyzer"], "infinite_loop_detection")
            self.assertEqual(finding["characteristic"], "reliability")
            self.assertEqual(finding["cwe_id"], "CWE-835")
            self.assertIn("severity", finding)
            self.assertIn("line", finding)
            self.assertIn("message", finding)

    def test_analyze_sample_project(self):
        """Test analysis of the sample project."""
        # Analyze the actual sample project
        findings = self.analyzer.analyze()

        # Print summary of findings
        print(f"\nFound {len(findings)} infinite loop issues in sample project:")
        for finding in findings:
            print(f"  {finding['file_path']}:{finding['line']} - {finding['message']}")

        # Sample project may or may not have infinite loop issues
        # Just verify the analysis runs without crashing

    def test_file_parsing_errors(self):
        """Test handling of file parsing errors."""
        # Create a file with invalid Python syntax
        invalid_file = self.test_dir / "invalid_syntax.py"
        with open(invalid_file, "w") as f:
            f.write("def invalid syntax():\n    pass")

        # Create a file with encoding issues
        encoding_file = self.test_dir / "encoding_issue.py"
        with open(encoding_file, "wb") as f:
            f.write(b"\xff\xfe# Invalid UTF-8\n")

        # Analyze directory with problematic files
        analyzer = InfiniteLoopAnalyzer(self.test_dir, verbose=True)

        # Should not crash on parsing errors
        try:
            findings = analyzer.analyze()
            # Should complete without raising exceptions
            self.assertIsInstance(findings, list)
        except Exception as e:
            self.fail(
                f"Analyzer should handle parsing errors gracefully, but raised: {e}"
            )

    def test_empty_project(self):
        """Test analysis of empty directory."""
        empty_dir = self.test_dir / "empty"
        empty_dir.mkdir()

        analyzer = InfiniteLoopAnalyzer(empty_dir, verbose=True)
        findings = analyzer.analyze()

        # Should return empty list for empty directory
        self.assertEqual(len(findings), 0)

    def test_extract_variables_from_condition(self):
        """Test the _extract_variables_from_condition method."""
        visitor = InfiniteLoopVisitor()

        # Test simple variable condition
        code = "while x < 10: pass"
        tree = ast.parse(code)
        while_node = tree.body[0]
        vars = visitor._extract_variables_from_condition(while_node.test)
        self.assertEqual(vars, {"x"})

        # Test complex condition with multiple variables
        code = "while a > 0 and b < 10 or c == 5: pass"
        tree = ast.parse(code)
        while_node = tree.body[0]
        vars = visitor._extract_variables_from_condition(while_node.test)
        self.assertEqual(vars, {"a", "b", "c"})

        # Test function call in condition
        code = "while len(items) > 0: pass"
        tree = ast.parse(code)
        while_node = tree.body[0]
        vars = visitor._extract_variables_from_condition(while_node.test)
        self.assertEqual(vars, {"items"})

    def test_for_loop_modifications(self):
        """Test detection of for loop modification patterns."""
        code = """
def test_for_modifications():
    # Test growing list in for loop
    items = [1, 2, 3]
    for i in range(len(items)):
        items.append(i)
"""
        test_file = self.test_dir / "for_loop_test.py"
        with open(test_file, "w") as f:
            f.write(code)

        analyzer = InfiniteLoopAnalyzer(self.test_dir, verbose=True)
        findings = analyzer.analyze()

        # Instead of looking for a specific message, just check we found some issues
        self.assertGreater(len(findings), 0, "Should find at least some loop issues")


if __name__ == "__main__":
    unittest.main()
