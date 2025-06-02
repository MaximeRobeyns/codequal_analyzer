"""
Quick Quality Check - A streamlined interface for the PyCQ Analyzer.

This module provides simple functions to quickly assess Python code quality:
1. get_quality_score: Evaluate a Python project and get a single quality score
2. assess_code_string: Evaluate Python code from a string and get a quality score
"""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

from pycq_analyzer.main import run_analyzers, calculate_scores
from pycq_analyzer.analyzers.pylint_analyzer import PylintAnalyzer
from pycq_analyzer.analyzers.bandit_analyzer import BanditAnalyzer
from pycq_analyzer.analyzers.radon_analyzer import RadonAnalyzer
from pycq_analyzer.analyzers.vulture_analyzer import VultureAnalyzer
from pycq_analyzer.analyzers.exception_handling_analyzer import (
    ExceptionHandlingAnalyzer,
)
from pycq_analyzer.analyzers.data_structure_analyzer import (
    DataStructureComplexityAnalyzer,
)
from pycq_analyzer.analyzers.resource_consumption_analyzer import (
    ResourceConsumptionAnalyzer,
)
from pycq_analyzer.analyzers.string_concat_analyzer import StringConcatenationAnalyzer


def get_quality_score(
    project_path: Union[str, Path],
    verbose: bool = False,
    selected_analyzers_only: bool = True,
    max_jobs: int = 4,
    complexity_threshold: str = "C",
) -> float:
    """
    Analyze a Python project quickly and return a single quality score.

    Args:
        project_path: Path to the Python project to analyze
        verbose: Enable verbose output
        selected_analyzers_only: Use only efficient analyzers for quicker analysis
        max_jobs: Maximum number of parallel analyzers
        complexity_threshold: Complexity threshold (A-F)

    Returns:
        A float between 0-100 representing the overall code quality
    """
    if isinstance(project_path, str):
        project_path = Path(project_path)

    if not project_path.exists():
        raise ValueError(f"Project path does not exist: {project_path}")

    if selected_analyzers_only:
        findings = run_selected_analyzers(
            project_path, verbose, max_jobs, complexity_threshold
        )
    else:
        findings = run_analyzers(
            project_path=project_path,
            static_only=True,
            verbose=verbose,
            max_jobs=max_jobs,
            complexity_threshold=complexity_threshold,
        )

    # Calculate scores based on findings
    scores = calculate_scores(findings)

    # Return the overall quality score
    return scores["overall"]


def assess_code_string(
    code: str,
    filename: str = "temp_file.py",
    verbose: bool = False,
) -> float:
    """
    Analyze Python code from a string and return a quality score.

    Args:
        code: Python code as a string
        filename: Filename to use for the temporary file
        verbose: Enable verbose output

    Returns:
        A float between 0-100 representing the code quality
    """
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="pycq_analyzer_")
    try:
        # Write the code to a temporary file
        temp_file = Path(temp_dir) / filename
        with open(temp_file, "w") as f:
            f.write(code)

        # Analyze the temporary file
        score = get_quality_score(
            project_path=temp_dir,
            verbose=verbose,
            selected_analyzers_only=True,
        )

        return score

    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)


def run_selected_analyzers(
    project_path: Path,
    verbose: bool = False,
    max_jobs: int = 4,
    complexity_threshold: str = "C",
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run a selected set of efficient analyzers on the project.

    Select analyzers that provide quick but useful analysis for common issues.

    Args:
        project_path: Path to the project to analyze
        verbose: Enable verbose output
        max_jobs: Maximum number of parallel analyzers
        complexity_threshold: Complexity threshold for Radon

    Returns:
        Dictionary of findings by characteristic
    """
    # Create an empty findings dictionary
    findings = {
        "maintainability": [],
        "security": [],
        "performance": [],
        "reliability": [],
    }

    # Create analyzer instances
    analyzers = [
        PylintAnalyzer(project_path, verbose),  # General code quality
        BanditAnalyzer(project_path, verbose),  # Security issues
        RadonAnalyzer(project_path, verbose, complexity_threshold),  # Code complexity
        VultureAnalyzer(project_path, verbose),  # Dead code
        ExceptionHandlingAnalyzer(project_path, verbose),  # Exception handling
        DataStructureComplexityAnalyzer(
            project_path, verbose
        ),  # Data structure complexity
        ResourceConsumptionAnalyzer(project_path, verbose),  # Resource consumption
        StringConcatenationAnalyzer(project_path, verbose),  # String concatenation
    ]

    # Run analyzers and collect findings
    for analyzer in analyzers:
        if analyzer.is_available:
            characteristic = analyzer.characteristic
            analyzer_findings = analyzer.analyze()
            findings[characteristic].extend(analyzer_findings)
            if verbose:
                print(
                    f"Found {len(analyzer_findings)} issues with {analyzer.__class__.__name__}"
                )

    return findings


if __name__ == "__main__":
    # Example usage
    import sys

    # Check if a path was provided
    if len(sys.argv) > 1:
        project_path = sys.argv[1]
        score = get_quality_score(project_path, verbose=True)
        print(f"\nOverall Quality Score: {score:.2f}/100")
    else:
        # Demonstrate in-memory code analysis with a sample file
        sample_code = """
import random

# Function with various quality issues
def process_data(items):
    result = ""  # Inefficient string concatenation
    for i in range(len(items)):  # Could use enumerate or direct iteration
        # Potentially unsafe random number generation for security contexts
        if random.random() > 0.5:
            # Nested conditions increase complexity
            try:
                result = result + str(items[i])  # Inefficient string concatenation
            except:
                # Bare except clause - bad practice
                pass
    return result

def unused_function():
    # This function is never called
    pass

# Analyze this string
if __name__ == "__main__":
    data = [1, 2, 3, 4, 5]
    print(process_data(data))
"""
        score = assess_code_string(sample_code, verbose=True)
        print(f"\nOverall Quality Score for in-memory code: {score:.2f}/100")
