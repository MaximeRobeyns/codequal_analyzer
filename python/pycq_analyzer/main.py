"""
PyCQ Analyzer - Main entrypoint.

This module provides the main command-line interface for the program.
"""

import argparse
import concurrent.futures
import logging
import sys
import threading
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional

from .analyzers.pylint_analyzer import PylintAnalyzer
from .analyzers.bandit_analyzer import BanditAnalyzer
from .analyzers.radon_analyzer import RadonAnalyzer
from .analyzers.safety_analyzer import SafetyAnalyzer
from .analyzers.vulture_analyzer import VultureAnalyzer
from .analyzers.xenon_analyzer import XenonAnalyzer
from .analyzers.mypy_analyzer import MypyAnalyzer
from .analyzers.string_concat_analyzer import StringConcatenationAnalyzer
from .analyzers.resource_consumption_analyzer import ResourceConsumptionAnalyzer
from .analyzers.data_structure_analyzer import DataStructureComplexityAnalyzer
from .analyzers.exception_handling_analyzer import ExceptionHandlingAnalyzer
from .analyzers.deadlock_analyzer import DeadlockAnalyzer
from .analyzers.infinite_loop_analyzer import InfiniteLoopAnalyzer
from .utils import configure_logging


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PyCQ Analyzer - Measure python software quality"
    )

    parser.add_argument(
        "project_path", type=str, help="Path to the Python project to analyze"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="./pycq_reports",
        help="Directory to store analysis reports (default: ./pycq_reports)",
    )

    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run only static analyzers (no execution required)",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=4,
        help="Maximum number of analyzers to run in parallel (default: 4)",
    )

    parser.add_argument(
        "--complexity-threshold",
        type=str,
        default="C",
        choices=["A", "B", "C", "D", "E", "F"],
        help="Minimum code complexity threshold to report (A-F, default: C)",
    )

    parser.add_argument(
        "--requirements-file",
        type=str,
        default=None,
        help="Path to requirements file for dependency analysis (default: auto-detect)",
    )

    parser.add_argument(
        "--min-confidence",
        type=int,
        default=60,
        help="Minimum confidence threshold for dead code detection (0-100, default: 60)",
    )

    # Xenon specific arguments
    parser.add_argument(
        "--max-absolute",
        type=str,
        default="C",
        choices=["A", "B", "C", "D", "E", "F"],
        help="Maximum absolute complexity rank allowed (A-F, default: C)",
    )

    parser.add_argument(
        "--max-modules",
        type=str,
        default="B",
        choices=["A", "B", "C", "D", "E", "F"],
        help="Maximum modules complexity rank allowed (A-F, default: B)",
    )

    parser.add_argument(
        "--max-average",
        type=str,
        default="A",
        choices=["A", "B", "C", "D", "E", "F"],
        help="Maximum average complexity rank allowed (A-F, default: A)",
    )

    # Mypy specific arguments
    parser.add_argument(
        "--mypy-config",
        type=str,
        default=None,
        help="Path to Mypy configuration file (default: None, using built-in defaults)",
    )

    # Display options
    parser.add_argument(
        "-di",
        "--display-issues",
        action="store_true",
        help="Display detailed information about issues found, grouped by characteristic",
    )

    return parser.parse_args()


def run_analyzer(analyzer):
    """
    Run a single analyzer.

    Args:
        analyzer: Analyzer instance to run

    Returns:
        Tuple of (characteristic, findings)
    """
    characteristic = analyzer.characteristic
    findings = analyzer.analyze()
    return (characteristic, findings)


def run_analyzers(
    project_path: Path,
    static_only: bool = True,
    verbose: bool = False,
    max_jobs: int = 4,
    complexity_threshold: str = "C",
    requirements_file: Optional[str] = None,
    min_confidence: int = 60,
    max_absolute: str = "C",
    max_modules: str = "B",
    max_average: str = "A",
    mypy_config: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run all analyzers on the project.

    Args:
        project_path: Path to the project to analyze
        static_only: Whether to run only static analyzers
        verbose: Whether to enable verbose output
        max_jobs: Maximum number of analyzers to run in parallel
        complexity_threshold: Minimum complexity threshold for Radon
        requirements_file: Optional path to requirements file for Safety
        min_confidence: Minimum confidence threshold for dead code detection
        max_absolute: Maximum absolute complexity rank allowed (Xenon)
        max_modules: Maximum modules complexity rank allowed (Xenon)
        max_average: Maximum average complexity rank allowed (Xenon)
        mypy_config: Optional path to Mypy configuration file

    Returns:
        Dictionary of findings by characteristic
    """
    findings = {
        "maintainability": [],
        "security": [],
        "performance": [],
        "reliability": [],
    }

    # Create all analyzers
    analyzers = [
        PylintAnalyzer(project_path, verbose),
        BanditAnalyzer(project_path, verbose),
        RadonAnalyzer(project_path, verbose, complexity_threshold),
        SafetyAnalyzer(project_path, verbose, requirements_file),
        VultureAnalyzer(project_path, verbose, min_confidence),
        XenonAnalyzer(project_path, verbose, max_absolute, max_modules, max_average),
        MypyAnalyzer(project_path, verbose, mypy_config),
        StringConcatenationAnalyzer(project_path, verbose),
        ResourceConsumptionAnalyzer(project_path, verbose),
        DataStructureComplexityAnalyzer(project_path, verbose),
        ExceptionHandlingAnalyzer(project_path, verbose),
        DeadlockAnalyzer(project_path, verbose),
        InfiniteLoopAnalyzer(project_path, verbose),
        # Add more analyzers as they are implemented
    ]

    # Filter out analyzers based on static_only flag if needed
    if static_only:
        # Currently all analyzers are static, so no filtering needed
        pass

    # Create a semaphore to limit concurrency
    semaphore = threading.Semaphore(max_jobs)

    # Run analyzers in parallel with controlled concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_jobs) as executor:
        # Submit all analyzer jobs
        future_to_analyzer = {}
        for analyzer in analyzers:
            # Check if analyzer is available
            if analyzer.is_available:
                future = executor.submit(run_analyzer, analyzer)
                future_to_analyzer[future] = analyzer
            else:
                analyzer.log_availability()

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_analyzer):
            analyzer = future_to_analyzer[future]
            try:
                characteristic, analyzer_findings = future.result()
                findings[characteristic].extend(analyzer_findings)
            except Exception as e:
                logging.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")

    return findings


def calculate_scores(findings: Dict[str, List[Dict[str, Any]]]) -> Dict[str, float]:
    """
    Calculate PyCQ quality scores based on findings.

    Args:
        findings: Dictionary of findings by characteristic

    Returns:
        Dictionary of scores by characteristic
    """
    scores = {}

    # Severity weights for calculation
    severity_weights = {
        "low": 1.0,
        "medium": 2.5,
        "high": 5.0,
        "critical": 10.0,
        "info": 0.5,
    }

    # Base score value
    base_score = 100.0

    # Calculate score for each characteristic
    for characteristic, characteristic_findings in findings.items():
        if not characteristic_findings:
            # Even with 0 findings, scores should approach but not quite reach 100
            # Use a tiny non-zero value as the weighted sum
            weighted_sum = 0.01
        else:
            # Calculate weighted sum of findings based on severity
            weighted_sum = 0.0
            for finding in characteristic_findings:
                severity = finding.get("severity", "medium")
                weight = severity_weights.get(severity, severity_weights["medium"])
                weighted_sum += weight

        # Use asymptotic function to calculate score
        # This approaches 0 as weighted_sum increases, but never reaches it
        # Formula: score = base_score * (1 / (1 + factor * weighted_sum))
        # where factor controls how quickly the score drops

        # Scale factor adjusts how quickly the score drops based on characteristic
        scale_factors = {
            "maintainability": 0.05,
            "security": 0.1,  # Security issues have a stronger impact
            "performance": 0.08,
            "reliability": 0.07,
        }

        scale_factor = scale_factors.get(characteristic, 0.05)
        score = base_score * (1 / (1 + scale_factor * weighted_sum))

        # Round to 2 decimal places for readability
        scores[characteristic] = round(score, 2)

    # Calculate overall score as average of all characteristics
    if scores:
        scores["overall"] = round(sum(scores.values()) / len(scores), 2)
    else:
        scores["overall"] = 99.99  # Never quite 100

    return scores


def display_issues(findings: Dict[str, List[Dict[str, Any]]]) -> None:
    """
    Display detailed information about issues found, grouped by characteristic.

    Args:
        findings: Dictionary of findings by characteristic
    """
    total_issues = sum(len(issues) for issues in findings.values())
    if total_issues == 0:
        print("\nNo issues found.")
        return

    print(f"\nFound {total_issues} issues across all analyzers:")

    # Group findings by characteristic
    for characteristic, characteristic_findings in findings.items():
        if not characteristic_findings:
            continue

        print(f"\n{characteristic.upper()} ISSUES ({len(characteristic_findings)}):")
        print("-" * 80)

        # Group by analyzer
        analyzer_groups = defaultdict(list)
        for finding in characteristic_findings:
            analyzer = finding.get("analyzer", "unknown")
            analyzer_groups[analyzer].append(finding)

        # Display each analyzer's findings
        for analyzer, analyzer_findings in analyzer_groups.items():
            print(f"\n  {analyzer.capitalize()} ({len(analyzer_findings)} issues):")

            # Group by severity
            severity_groups = defaultdict(list)
            for finding in analyzer_findings:
                severity = finding.get("severity", "unknown")
                severity_groups[severity].append(finding)

            # Display by severity (highest to lowest)
            severity_order = ["critical", "high", "medium", "low", "info"]
            for severity in severity_order:
                if severity not in severity_groups:
                    continue

                severity_findings = severity_groups[severity]
                print(f"\n    {severity.upper()} ({len(severity_findings)} issues):")

                # Display each finding
                for i, finding in enumerate(severity_findings, 1):
                    file_path = finding.get("file_path", "unknown")
                    line = finding.get("line", 0)
                    message = finding.get("message", "No message")
                    rule_id = finding.get("rule_id", "unknown")
                    cwe_id = finding.get("cwe_id", "unknown")

                    print(f"      {i}. {file_path}:{line} - [{rule_id}] {message}")
                    print(f"         CWE: {cwe_id}")

        print("\n" + "-" * 80)


def main():
    """Main entry point for the PyCQ analyzer."""
    args = parse_args()

    # Configure logging
    logger = configure_logging(args.verbose)

    # Validate project path
    project_path = Path(args.project_path)
    if not project_path.exists():
        logger.error(f"Project path does not exist: {project_path}")
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)

    logger.info(f"Analyzing project: {project_path}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Maximum concurrent analyzers: {args.jobs}")
    logger.info(f"Complexity threshold: {args.complexity_threshold}")
    logger.info(f"Dead code confidence threshold: {args.min_confidence}")
    logger.info(
        f"Complexity limits (Xenon) - Absolute: {args.max_absolute}, Modules: {args.max_modules}, Average: {args.max_average}"
    )

    # Run analyzers
    findings = run_analyzers(
        project_path,
        args.static_only,
        args.verbose,
        args.jobs,
        args.complexity_threshold,
        args.requirements_file,
        args.min_confidence,
        args.max_absolute,
        args.max_modules,
        args.max_average,
        args.mypy_config,
    )

    # Calculate scores
    scores = calculate_scores(findings)

    # Print scores to console
    print("\nPyCQ Quality Scores:")
    print("-" * 40)
    for characteristic, score in scores.items():
        if characteristic != "overall":
            print(f"{characteristic.capitalize():20}: {score:.2f} / 100.00")
    print("-" * 40)
    print(f"{'Overall':20}: {scores['overall']:.2f} / 100.00")

    # Display detailed issues if requested
    if args.display_issues:
        display_issues(findings)

    # TODO: Generate detailed report

    return 0


if __name__ == "__main__":
    sys.exit(main())
