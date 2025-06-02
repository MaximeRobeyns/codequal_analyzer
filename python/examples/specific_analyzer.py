"""
PyCQ Quality Analyzer - Specific Analyzer Demo.

This script demonstrates how to use individual analyzers directly
instead of using the run_analyzers function.
"""

import os
from pathlib import Path
import concurrent.futures

from pycq_analyzer.analyzers.pylint_analyzer import PylintAnalyzer
from pycq_analyzer.analyzers.bandit_analyzer import BanditAnalyzer
from pycq_analyzer.analyzers.resource_consumption_analyzer import (
    ResourceConsumptionAnalyzer,
)
from pycq_analyzer.main import calculate_scores


def run_specific_analyzers(project_path, analyzers, max_jobs=4):
    """
    Run specific analyzers on the project.

    Args:
        project_path: Path to the project to analyze
        analyzers: List of analyzer instances to run
        max_jobs: Maximum number of analyzers to run in parallel

    Returns:
        Dictionary of findings by characteristic
    """
    findings = {
        "maintainability": [],
        "security": [],
        "performance": [],
        "reliability": [],
    }

    # Run analyzers in parallel with controlled concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_jobs) as executor:
        future_to_analyzer = {}

        for analyzer in analyzers:
            if analyzer.is_available:
                print(f"Running {analyzer.__class__.__name__}...")
                future = executor.submit(analyzer.analyze)
                future_to_analyzer[future] = analyzer
            else:
                print(f"{analyzer.__class__.__name__} is not available.")

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_analyzer):
            analyzer = future_to_analyzer[future]
            try:
                analyzer_findings = future.result()
                findings[analyzer.characteristic].extend(analyzer_findings)
                print(
                    f"Found {len(analyzer_findings)} issues with {analyzer.__class__.__name__}"
                )
            except Exception as e:
                print(f"Analyzer {analyzer.__class__.__name__} failed: {e}")

    return findings


def main():
    """Run specific analyzers on the sample project and display results."""
    print("PyCQ Quality Analyzer - Specific Analyzer Demo")
    print("=============================================\n")

    # Define path to the sample project
    current_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    sample_project_path = current_dir / "sample_project"

    print(f"Analyzing project: {sample_project_path}\n")

    # Create specific analyzer instances
    analyzers = [
        PylintAnalyzer(sample_project_path, verbose=True),
        BanditAnalyzer(sample_project_path, verbose=True),
        ResourceConsumptionAnalyzer(sample_project_path, verbose=True),
    ]

    # Run only these analyzers
    findings = run_specific_analyzers(sample_project_path, analyzers)

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

    # Show how to extract specific types of issues
    print("\nExtracted Security Issues:")
    print("--------------------------")

    security_issues = findings.get("security", [])
    for i, issue in enumerate(security_issues[:3], 1):
        print(
            f"{i}. [{issue.get('severity', 'unknown').upper()}] {issue.get('file_path', 'unknown')}"
        )
        print(
            f"   Rule: {issue.get('rule_id', 'unknown')}, CWE: {issue.get('cwe_id', 'unknown')}"
        )
        print(f"   Message: {issue.get('message', 'No message')}")


if __name__ == "__main__":
    main()
