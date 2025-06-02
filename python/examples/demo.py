"""
PyCQ Quality Analyzer Library Demo.

This script demonstrates how to use the pycq_analyzer as a library
to analyze a Python project for code quality issues.
"""

import os
from pathlib import Path

from pycq_analyzer.main import run_analyzers, calculate_scores


def main():
    """Run the PyCQ analyzer on the sample project and display results."""
    print("PyCQ Quality Analyzer Library Demo")
    print("==================================\n")

    # Define path to the sample project - using relative path
    parent_dir = Path(os.path.dirname(os.path.abspath(__file__))).parent
    sample_project_path = parent_dir / "sample_project"

    print(f"Analyzing project: {sample_project_path}\n")

    # Run analyzers with library API
    findings = run_analyzers(
        project_path=sample_project_path,
        static_only=True,  # Only use static analyzers
        verbose=True,  # Enable verbose output
        max_jobs=4,  # Run with 4 parallel jobs
        complexity_threshold="C",  # Complexity threshold
        requirements_file=None,  # No specific requirements file
        min_confidence=60,  # Minimum confidence for dead code detection
        max_absolute="C",  # Maximum absolute complexity
        max_modules="B",  # Maximum modules complexity
        max_average="A",  # Maximum average complexity
    )

    # Calculate scores based on findings
    scores = calculate_scores(findings)

    # Display findings summary
    print("\nFindings Summary:")
    print("----------------")

    for characteristic, characteristic_findings in findings.items():
        print(f"{characteristic.capitalize()}: {len(characteristic_findings)} issues")

    # Display scores
    print("\nQuality Scores:")
    print("--------------")

    for characteristic, score in scores.items():
        if characteristic != "overall":
            print(f"{characteristic.capitalize():20}: {score:.2f} / 100.00")

    print("-" * 40)
    print(f"{'Overall':20}: {scores['overall']:.2f} / 100.00\n")

    # Display a sample of findings from each characteristic
    for characteristic, characteristic_findings in findings.items():
        if not characteristic_findings:
            continue

        print(f"\n{characteristic.upper()} ISSUES (Sample):")
        print("-" * 80)

        # Show at most 3 issues per characteristic
        for i, finding in enumerate(characteristic_findings[:3]):
            file_path = finding.get("file_path", "unknown")
            line = finding.get("line", 0)
            message = finding.get("message", "No message")
            severity = finding.get("severity", "unknown")
            rule_id = finding.get("rule_id", "unknown")
            cwe_id = finding.get("cwe_id", "unknown")

            print(f"{i+1}. [{severity.upper()}] {file_path}:{line}")
            print(f"   Rule: {rule_id}, CWE: {cwe_id}")
            print(f"   Message: {message}")
            print()


if __name__ == "__main__":
    main()
