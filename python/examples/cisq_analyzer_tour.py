"""
PyCQ Analyzer Feature Tour

This script provides a comprehensive tour of all the functionality offered by the PyCQ Analyzer library.
It demonstrates each feature with examples, practical use cases, and explanations.

Topics covered:
1. Basic usage (high-level API)
2. Detailed analysis with all analyzers
3. Individual analyzer usage
4. Working with findings and scores
5. Visualizing results
6. Performance optimization
7. Integration patterns
8. Advanced configuration
"""

import tempfile
import time
from pathlib import Path

# Import core functionality
from pycq_analyzer import get_quality_score, assess_code_string, analyze_file
from pycq_analyzer.api import assess_code_with_feedback, run_selected_analyzers
from pycq_analyzer.main import run_analyzers, calculate_scores

# Import individual analyzers for specific demonstrations
from pycq_analyzer.analyzers.pylint_analyzer import PylintAnalyzer
from pycq_analyzer.analyzers.bandit_analyzer import BanditAnalyzer
from pycq_analyzer.analyzers.radon_analyzer import RadonAnalyzer
from pycq_analyzer.analyzers.vulture_analyzer import VultureAnalyzer
from pycq_analyzer.analyzers.exception_handling_analyzer import (
    ExceptionHandlingAnalyzer,
)
from pycq_analyzer.analyzers.string_concat_analyzer import StringConcatenationAnalyzer


# Utility for creating temporary files/directories
def create_temp_file(code: str, filename: str = "temp.py") -> Path:
    """Create a temporary file with the given code."""
    temp_dir = tempfile.mkdtemp(prefix="pycq_analyzer_")
    temp_file = Path(temp_dir) / filename
    with open(temp_file, "w") as f:
        f.write(code)
    return Path(temp_dir)


# Sample code with various quality issues for demonstrations
SAMPLE_CODE_WITH_ISSUES = """
import random
import subprocess
import os

# Function with various quality issues
def process_data(items):
    result = ""  # Inefficient string concatenation
    for i in range(len(items)):  # Could use enumerate or direct iteration
        # Potentially unsafe random number generation for security contexts
        if random.random() > 0.5:
            # Nested conditions increase complexity
            try:
                # Shell injection vulnerability potential
                os.system("echo " + str(items[i]))

                # Inefficient string concatenation
                result = result + str(items[i])
            except:
                # Bare except clause - bad practice
                pass
    return result

def unused_function():
    # This function is never called - dead code
    pass

class ComplexClass:
    def __init__(self):
        self.a = 1
        self.b = 2
        self.c = 3
        self.d = 4
        self.e = 5
        self.f = 6
        self.g = 7
        self.h = 8
        self.i = 9
        self.j = 10
        self.k = 11

    def complex_method(self, x, y, z, a, b, c, d, e, f):
        # Too many parameters and complexity
        if x > 0:
            if y > 0:
                if z > 0:
                    if a > 0:
                        if b > 0:
                            if c > 0:
                                if d > 0:
                                    if e > 0:
                                        if f > 0:
                                            return True
        return False

# Risk of infinite loop
def risky_loop(data):
    i = 0
    while i < len(data):
        if data[i] == 0:
            i -= 1  # Potential infinite loop if data contains consecutive zeros
        i += 1
    return data

# Resource consumption in loop
def resource_intensive(items):
    results = []
    for item in items:
        for i in range(1000000):  # Computationally expensive
            item = item * 2
        results.append(item)
    return results

# Module-level code
if __name__ == "__main__":
    data = [1, 2, 3, 4, 5]
    print(process_data(data))
"""

# Sample code with good practices
SAMPLE_GOOD_CODE = """
from typing import List, Optional

def process_data(items: List[int]) -> str:
    \"\"\"
    Process a list of integers and return a formatted string.

    Args:
        items: A list of integers to process

    Returns:
        A string representation of the processed items
    \"\"\"
    # Use a list to build the result for better efficiency
    result_parts = []

    # Enumerate for clearer iteration with index
    for i, item in enumerate(items):
        try:
            # Append to list instead of string concatenation
            result_parts.append(f"Item {i}: {item}")
        except Exception as e:
            # Specific exception handling with error logging
            print(f"Error processing item {i}: {e}")

    # Join at the end for efficient string creation
    return "\\n".join(result_parts)

def calculate_average(numbers: List[float]) -> Optional[float]:
    \"\"\"
    Calculate the average of a list of numbers.

    Args:
        numbers: A list of numbers

    Returns:
        The average or None if the list is empty
    \"\"\"
    if not numbers:
        return None
    return sum(numbers) / len(numbers)

if __name__ == "__main__":
    data = [1, 2, 3, 4, 5]
    print(process_data(data))
    print(f"Average: {calculate_average(data)}")
"""

# Sample code with security issues
SAMPLE_SECURITY_CODE = """
import os
import subprocess
import pickle
import yaml

def run_command(cmd):
    # Shell injection vulnerability
    os.system("echo " + cmd)

    # Command injection vulnerability
    subprocess.call(cmd, shell=True)

    return "Command executed"

def load_data(filename):
    # Unsafe deserialization
    with open(filename, 'rb') as f:
        return pickle.load(f)

def parse_yaml(data):
    # Unsafe YAML parsing
    return yaml.load(data)

def get_user_file(user_input):
    # Path traversal vulnerability
    filename = user_input
    with open(filename, 'r') as f:
        return f.read()

def authenticate(username, password):
    # Hard-coded credentials
    if username == "admin" and password == "password123":
        return True
    return False
"""


def section_1_basic_usage():
    """Section 1: Demonstrate basic usage with the high-level API."""
    print("\n" + "=" * 80)
    print("SECTION 1: BASIC USAGE (HIGH-LEVEL API)")
    print("=" * 80)

    # Create temporary project with problematic code
    temp_dir = create_temp_file(SAMPLE_CODE_WITH_ISSUES)

    print("\n1.1 Analyzing a project directory")
    print("-" * 50)
    score = get_quality_score(temp_dir, verbose=True)
    print(f"Overall Quality Score: {score:.2f}/100")

    print("\n1.2 Analyzing a single file")
    print("-" * 50)
    file_path = Path(temp_dir) / "temp.py"
    score = analyze_file(file_path, verbose=True)
    print(f"File Quality Score: {score:.2f}/100")

    print("\n1.3 Analyzing code from a string")
    print("-" * 50)
    code_snippet = """
def bad_function():
    try:
        return 1/0
    except:  # Bare except
        pass
    """
    score = assess_code_string(code_snippet, verbose=True)
    print(f"Code Snippet Quality Score: {score:.2f}/100")

    # Clean up
    import shutil

    shutil.rmtree(temp_dir)


def section_2_detailed_analysis():
    """Section 2: Demonstrate detailed analysis with full analyzer suite."""
    print("\n" + "=" * 80)
    print("SECTION 2: DETAILED ANALYSIS WITH ALL ANALYZERS")
    print("=" * 80)

    # Create temporary project with issues
    temp_dir = create_temp_file(SAMPLE_CODE_WITH_ISSUES)

    print("\n2.1 Running all analyzers")
    print("-" * 50)
    findings = run_analyzers(
        project_path=temp_dir,
        static_only=True,
        verbose=True,
        max_jobs=4,
        complexity_threshold="C",
        min_confidence=60,
        max_absolute="C",
        max_modules="B",
        max_average="A",
    )

    print("\n2.2 Calculating quality scores")
    print("-" * 50)
    scores = calculate_scores(findings)

    print("\nQuality Scores by Characteristic:")
    for characteristic, score in scores.items():
        if characteristic != "overall":
            print(f"{characteristic.capitalize():20}: {score:.2f}/100")
    print("-" * 40)
    print(f"{'Overall':20}: {scores['overall']:.2f}/100")

    print("\n2.3 Displaying detailed issue information")
    print("-" * 50)
    total_issues = sum(len(issues) for issues in findings.values())
    print(f"Found {total_issues} issues across all analyzers\n")

    # Display a sample of the findings
    for characteristic, issues in findings.items():
        if issues:
            print(f"{characteristic.capitalize()}: {len(issues)} issues")

    print("\nFirst few issues from each characteristic:")
    for characteristic, characteristic_findings in findings.items():
        if not characteristic_findings:
            continue

        print(
            f"\n{characteristic.upper()} (showing 1 of {len(characteristic_findings)}):"
        )
        finding = characteristic_findings[0]
        print(f"  Analyzer: {finding.get('analyzer', 'unknown')}")
        print(f"  Severity: {finding.get('severity', 'unknown')}")
        print(f"  File: {finding.get('file_path', 'unknown')}")
        print(f"  Line: {finding.get('line', 0)}")
        print(f"  Rule ID: {finding.get('rule_id', 'unknown')}")
        print(f"  CWE ID: {finding.get('cwe_id', 'unknown')}")
        print(f"  Message: {finding.get('message', 'No message')}")

    # Clean up
    import shutil

    shutil.rmtree(temp_dir)


def section_3_individual_analyzers():
    """Section 3: Demonstrate using individual analyzers."""
    print("\n" + "=" * 80)
    print("SECTION 3: INDIVIDUAL ANALYZER USAGE")
    print("=" * 80)

    # Create temp files for different types of issues
    temp_dir1 = create_temp_file(SAMPLE_CODE_WITH_ISSUES, "issues.py")
    temp_dir2 = create_temp_file(SAMPLE_SECURITY_CODE, "security.py")

    # Choose one directory for demonstration
    temp_dir = temp_dir1

    print("\n3.1 Using single analyzers directly")
    print("-" * 50)

    # Using the Pylint analyzer for code style and maintainability
    print("\nPylintAnalyzer (Maintainability):")
    pylint = PylintAnalyzer(temp_dir, verbose=True)
    if pylint.is_available:
        pylint_findings = pylint.analyze()
        print(f"Found {len(pylint_findings)} code style and quality issues")
        if pylint_findings:
            print(f"Sample: {pylint_findings[0]['message']}")

    # Using the Bandit analyzer for security issues
    print("\nBanditAnalyzer (Security):")
    bandit = BanditAnalyzer(temp_dir, verbose=True)
    if bandit.is_available:
        bandit_findings = bandit.analyze()
        print(f"Found {len(bandit_findings)} security issues")
        if bandit_findings:
            print(f"Sample: {bandit_findings[0]['message']}")

    # Using the Radon analyzer for code complexity
    print("\nRadonAnalyzer (Maintainability/Complexity):")
    radon = RadonAnalyzer(temp_dir, verbose=True, complexity_threshold="C")
    if radon.is_available:
        radon_findings = radon.analyze()
        print(f"Found {len(radon_findings)} complexity issues")
        if radon_findings:
            print(f"Sample: {radon_findings[0]['message']}")

    print("\n3.2 Specialized analyzers for specific issues")
    print("-" * 50)

    # Performance-focused analyzer
    print("\nStringConcatenationAnalyzer (Performance):")
    str_concat = StringConcatenationAnalyzer(temp_dir, verbose=True)
    if str_concat.is_available:
        str_concat_findings = str_concat.analyze()
        print(
            f"Found {len(str_concat_findings)} inefficient string concatenation issues"
        )
        if str_concat_findings:
            print(f"Sample: {str_concat_findings[0]['message']}")

    # Reliability-focused analyzer
    print("\nExceptionHandlingAnalyzer (Reliability):")
    except_handling = ExceptionHandlingAnalyzer(temp_dir, verbose=True)
    if except_handling.is_available:
        except_findings = except_handling.analyze()
        print(f"Found {len(except_findings)} exception handling issues")
        if except_findings:
            print(f"Sample: {except_findings[0]['message']}")

    # Clean up
    import shutil

    shutil.rmtree(temp_dir1)
    shutil.rmtree(temp_dir2)


def section_4_working_with_findings():
    """Section 4: Demonstrate working with findings and scores."""
    print("\n" + "=" * 80)
    print("SECTION 4: WORKING WITH FINDINGS AND SCORES")
    print("=" * 80)

    # Create temporary project
    temp_dir = create_temp_file(SAMPLE_CODE_WITH_ISSUES)

    print("\n4.1 Getting feedback for code")
    print("-" * 50)

    # Using assess_code_with_feedback to get detailed feedback
    code_snippet = """
def risky_function(user_input):
    # Security issue: command injection
    import os
    os.system("echo " + user_input)

    # Performance issue: inefficient string concatenation
    result = ""
    for i in range(100):
        result = result + str(i)

    # Reliability issue: bare except
    try:
        return int(user_input)
    except:
        pass

    return result
"""

    score, feedback = assess_code_with_feedback(code_snippet, verbose=True)
    print(f"\nCode Quality Score: {score:.2f}/100")
    print("\nDetailed Feedback:")
    print(f"{feedback}")

    print("\n4.2 Filtering findings by severity")
    print("-" * 50)

    # Get findings for the project
    findings = run_analyzers(
        project_path=temp_dir,
        static_only=True,
        verbose=False,
        max_jobs=4,
    )

    # Group findings by severity
    severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for characteristic, characteristic_findings in findings.items():
        for finding in characteristic_findings:
            severity = finding.get("severity", "medium")
            severity_groups[severity].append(finding)

    # Display findings by severity
    for severity, severity_findings in severity_groups.items():
        print(f"{severity.capitalize()} severity issues: {len(severity_findings)}")

    print("\n4.3 Filtering findings by characteristic")
    print("-" * 50)

    # Display findings count by characteristic
    for characteristic, characteristic_findings in findings.items():
        print(f"{characteristic.capitalize()} issues: {len(characteristic_findings)}")

        # Display rule IDs for this characteristic
        if characteristic_findings:
            rule_ids = set(
                finding.get("rule_id", "unknown") for finding in characteristic_findings
            )
            print(f"  Rule IDs: {', '.join(sorted(rule_ids))}")

    # Clean up
    import shutil

    shutil.rmtree(temp_dir)


def section_5_visualizing_results():
    """Section 5: Demonstrate visualizing analysis results."""
    print("\n" + "=" * 80)
    print("SECTION 5: VISUALIZING RESULTS")
    print("=" * 80)

    # Create temporary projects with different code quality
    bad_dir = create_temp_file(SAMPLE_CODE_WITH_ISSUES, "bad_code.py")
    good_dir = create_temp_file(SAMPLE_GOOD_CODE, "good_code.py")
    security_dir = create_temp_file(SAMPLE_SECURITY_CODE, "security_code.py")

    print("\n5.1 Comparing different code samples")
    print("-" * 50)

    # Analyze each sample
    bad_score = get_quality_score(bad_dir, verbose=False)
    good_score = get_quality_score(good_dir, verbose=False)
    security_score = get_quality_score(security_dir, verbose=False)

    print(f"Bad code quality score: {bad_score:.2f}/100")
    print(f"Security issues code quality score: {security_score:.2f}/100")
    print(f"Good code quality score: {good_score:.2f}/100")

    print("\n5.2 Comparing characteristic scores")
    print("-" * 50)

    # Get detailed scores for each sample
    bad_findings = run_analyzers(bad_dir, verbose=False)
    good_findings = run_analyzers(good_dir, verbose=False)
    security_findings = run_analyzers(security_dir, verbose=False)

    bad_scores = calculate_scores(bad_findings)
    good_scores = calculate_scores(good_findings)
    security_scores = calculate_scores(security_findings)

    characteristics = ["maintainability", "security", "performance", "reliability"]

    print("Characteristic scores by sample:")
    for characteristic in characteristics:
        print(
            f"{characteristic.capitalize():15}: "
            f"Bad: {bad_scores[characteristic]:.2f}, "
            f"Security: {security_scores[characteristic]:.2f}, "
            f"Good: {good_scores[characteristic]:.2f}"
        )

    # Clean up
    import shutil

    shutil.rmtree(bad_dir)
    shutil.rmtree(good_dir)
    shutil.rmtree(security_dir)


def section_6_performance_optimization():
    """Section 6: Demonstrate performance optimization strategies."""
    print("\n" + "=" * 80)
    print("SECTION 6: PERFORMANCE OPTIMIZATION")
    print("=" * 80)

    # Create a larger project with multiple files for performance testing
    temp_dir = tempfile.mkdtemp(prefix="pycq_analyzer_")

    # Create multiple files with the same content
    for i in range(5):
        file_path = Path(temp_dir) / f"module_{i}.py"
        with open(file_path, "w") as f:
            f.write(SAMPLE_CODE_WITH_ISSUES)

    # Create an __init__.py file
    with open(Path(temp_dir) / "__init__.py", "w") as f:
        f.write("# Package initialization file")

    print("\n6.1 Comparing analysis speed with different settings")
    print("-" * 50)

    # Measure time for full analysis
    print("Running full analysis (all analyzers):")
    start_time = time.time()
    full_findings = run_analyzers(
        project_path=temp_dir,
        static_only=True,
        verbose=False,
        max_jobs=1,  # Single job for baseline
    )
    full_time = time.time() - start_time
    print(f"Full analysis time (1 job): {full_time:.2f} seconds")

    # Measure time with parallel jobs
    print("\nRunning full analysis with multiple jobs:")
    start_time = time.time()
    parallel_findings = run_analyzers(
        project_path=temp_dir,
        static_only=True,
        verbose=False,
        max_jobs=4,  # Use parallel jobs
    )
    parallel_time = time.time() - start_time
    print(f"Full analysis time (4 jobs): {parallel_time:.2f} seconds")
    print(f"Speedup: {full_time / parallel_time:.2f}x")

    # Measure time for selected analyzers
    print("\nRunning with selected analyzers only:")
    start_time = time.time()
    selected_findings = run_selected_analyzers(
        project_path=temp_dir,
        verbose=False,
        max_jobs=4,
    )
    selected_time = time.time() - start_time
    print(f"Selected analyzers time: {selected_time:.2f} seconds")
    print(f"Speedup vs full analysis: {full_time / selected_time:.2f}x")

    print("\n6.2 Analyzing a single file vs. full project")
    print("-" * 50)

    # Measure time for single file
    single_file = Path(temp_dir) / "module_0.py"
    print(f"Analyzing single file: {single_file.name}")

    start_time = time.time()
    file_score = analyze_file(single_file, verbose=False)
    file_time = time.time() - start_time
    print(f"Single file analysis time: {file_time:.2f} seconds")

    # Clean up
    import shutil

    shutil.rmtree(temp_dir)


def section_7_integration_patterns():
    """Section 7: Demonstrate integration patterns."""
    print("\n" + "=" * 80)
    print("SECTION 7: INTEGRATION PATTERNS")
    print("=" * 80)

    print("\n7.1 Continuous Integration Quality Gate")
    print("-" * 50)

    # Create sample files with different quality
    bad_code = create_temp_file(SAMPLE_CODE_WITH_ISSUES, "bad.py")
    good_code = create_temp_file(SAMPLE_GOOD_CODE, "good.py")

    # Function demonstrating CI quality gate
    def quality_gate(project_path, threshold=70.0):
        """Check if code quality meets the threshold."""
        print(f"Running quality gate with threshold: {threshold}")
        score = get_quality_score(project_path, verbose=False)
        print(f"Quality score: {score:.2f}/100")
        if score < threshold:
            print(
                f"❌ Quality gate failed: score {score:.2f} is below threshold {threshold}"
            )
            return False
        else:
            print(
                f"✅ Quality gate passed: score {score:.2f} meets threshold {threshold}"
            )
            return True

    # Try both samples
    print("\nChecking bad code quality:")
    bad_result = quality_gate(bad_code)

    print("\nChecking good code quality:")
    good_result = quality_gate(good_code)

    print("\n7.2 Developer Feedback Integration")
    print("-" * 50)

    # Function simulating IDE/editor integration
    def developer_feedback(code_string):
        """Provide immediate feedback on code quality."""
        print("Analyzing code snippet for immediate feedback...")
        score, feedback = assess_code_with_feedback(code_string, verbose=False)

        # Simulating IDE feedback with condensed output
        print(f"\nCode Quality: {score:.2f}/100 {'👍' if score > 70 else '⚠️'}")

        # Extract most critical issues (first 3)
        lines = feedback.split("\n")
        issue_count = 0
        for line in lines:
            if "CRITICAL" in line or "HIGH" in line:
                print(f"❗ {line.strip()}")
                issue_count += 1
                if issue_count >= 3:
                    break

        if issue_count == 0 and "No issues found" not in feedback:
            for line in lines:
                if "MEDIUM" in line:
                    print(f"⚠️ {line.strip()}")
                    issue_count += 1
                    if issue_count >= 3:
                        break

        # Show suggestion to view full report
        if "No issues found" not in feedback:
            print("💡 Tip: Run full analysis for comprehensive feedback")

    # Test with different code snippets
    print("\nFeedback for security-focused code:")
    developer_feedback(SAMPLE_SECURITY_CODE)

    # Clean up
    import shutil

    shutil.rmtree(bad_code)
    shutil.rmtree(good_code)


def section_8_advanced_configuration():
    """Section 8: Demonstrate advanced configuration options."""
    print("\n" + "=" * 80)
    print("SECTION 8: ADVANCED CONFIGURATION")
    print("=" * 80)

    # Create temporary project
    temp_dir = create_temp_file(SAMPLE_CODE_WITH_ISSUES)

    print("\n8.1 Customizing analyzer behavior")
    print("-" * 50)

    # Create a list of custom analyzers with different configurations
    print("Setting up customized analyzers:")
    custom_analyzers = [
        PylintAnalyzer(temp_dir, verbose=True),  # General code quality
        BanditAnalyzer(temp_dir, verbose=True),  # Security issues
        RadonAnalyzer(
            temp_dir, verbose=True, complexity_threshold="D"
        ),  # Less strict complexity
        VultureAnalyzer(
            temp_dir, verbose=True, min_confidence=80
        ),  # Higher confidence for dead code
    ]

    # Create empty findings dictionary
    findings = {
        "maintainability": [],
        "security": [],
        "performance": [],
        "reliability": [],
    }

    # Run each analyzer
    for analyzer in custom_analyzers:
        if analyzer.is_available:
            print(f"Running {analyzer.__class__.__name__}...")
            analyzer_findings = analyzer.analyze()
            characteristic = analyzer.characteristic
            findings[characteristic].extend(analyzer_findings)
            print(f"Found {len(analyzer_findings)} issues")

    # Calculate scores
    scores = calculate_scores(findings)
    print("\nScores with customized analyzers:")
    for characteristic, score in scores.items():
        if characteristic != "overall":
            print(f"{characteristic.capitalize():20}: {score:.2f}/100")
    print("-" * 40)
    print(f"{'Overall':20}: {scores['overall']:.2f}/100")

    print("\n8.2 Creating a custom scoring model")
    print("-" * 50)

    def custom_calculate_scores(findings, weights=None):
        """
        Calculate custom weighted scores based on findings.

        Args:
            findings: Dictionary of findings by characteristic
            weights: Dictionary of characteristic weights (should sum to 1.0)

        Returns:
            Dictionary of scores by characteristic
        """
        if weights is None:
            # Custom weights for different characteristics
            weights = {
                "maintainability": 0.4,  # Higher emphasis on maintainability
                "security": 0.3,  # Higher emphasis on security
                "performance": 0.15,  # Lower emphasis on performance
                "reliability": 0.15,  # Lower emphasis on reliability
            }

        # Calculate individual characteristic scores (same as original)
        severity_weights = {
            "low": 1.0,
            "medium": 2.5,
            "high": 5.0,
            "critical": 10.0,
            "info": 0.5,
        }
        base_score = 100.0
        scores = {}

        for characteristic, characteristic_findings in findings.items():
            if not characteristic_findings:
                weighted_sum = 0.01
            else:
                weighted_sum = 0.0
                for finding in characteristic_findings:
                    severity = finding.get("severity", "medium")
                    weight = severity_weights.get(severity, severity_weights["medium"])
                    weighted_sum += weight

            # Use asymptotic function to calculate score
            scale_factor = 0.05  # Same for all characteristics in custom model
            score = base_score * (1 / (1 + scale_factor * weighted_sum))
            scores[characteristic] = round(score, 2)

        # Calculate weighted overall score
        if scores:
            weighted_scores = [scores[char] * weights[char] for char in weights]
            scores["overall"] = round(sum(weighted_scores), 2)
        else:
            scores["overall"] = 99.99

        return scores

    # Run analysis and get findings
    findings = run_analyzers(temp_dir, verbose=False)

    # Compare standard scoring with custom scoring
    standard_scores = calculate_scores(findings)
    custom_scores = custom_calculate_scores(findings)

    print("Standard vs Custom Scoring Comparison:")
    print(f"{'Characteristic':<20} {'Standard':<10} {'Custom':<10}")
    print("-" * 40)
    for characteristic in [
        "maintainability",
        "security",
        "performance",
        "reliability",
        "overall",
    ]:
        print(
            f"{characteristic.capitalize():<20} {standard_scores[characteristic]:<10.2f} {custom_scores[characteristic]:<10.2f}"
        )

    # Clean up
    import shutil

    shutil.rmtree(temp_dir)


def main():
    """Run all sections of the PyCQ Analyzer Tour."""
    print("PyCQ Analyzer Feature Tour")
    print("=========================")
    print("\nThis script demonstrates all major features of the PyCQ Analyzer library.")

    # Run each section
    section_1_basic_usage()
    section_2_detailed_analysis()
    section_3_individual_analyzers()
    section_4_working_with_findings()
    section_5_visualizing_results()
    section_6_performance_optimization()
    section_7_integration_patterns()
    section_8_advanced_configuration()

    print("\n" + "=" * 80)
    print("PyCQ Analyzer Tour Complete!")
    print("=" * 80)


if __name__ == "__main__":
    main()
