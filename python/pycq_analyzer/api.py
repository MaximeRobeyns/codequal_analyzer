"""
PyCQ Analyzer API.

This module provides a streamlined API for the quality analyzer, making it easy to:
1. Get quality scores for Python projects
2. Analyze Python code from strings
3. Run selected analyzers for quick assessments
"""

import tempfile
import shutil
import concurrent.futures
from collections import defaultdict
from pathlib import Path

from typing import Dict, List, Union, Any
from pathlib import Path

from .analyzers.pylint_analyzer import PylintAnalyzer
from .analyzers.bandit_analyzer import BanditAnalyzer
from .analyzers.radon_analyzer import RadonAnalyzer
from .analyzers.vulture_analyzer import VultureAnalyzer
from .analyzers.exception_handling_analyzer import ExceptionHandlingAnalyzer
from .analyzers.data_structure_analyzer import DataStructureComplexityAnalyzer
from .analyzers.resource_consumption_analyzer import ResourceConsumptionAnalyzer
from .analyzers.string_concat_analyzer import StringConcatenationAnalyzer
from .main import run_analyzers, calculate_scores
from .utils import format_findings_as_string, count_lines_of_code


def get_quality_score(
    project_path: Union[str, Path],
    verbose: bool = False,
    quick: bool = True,
    max_jobs: int = 16,
    complexity_threshold: str = "C",
) -> float:
    """
    Analyze a Python project and return a single quality score.

    Args:
        project_path: Path to the Python project to analyze
        verbose: Enable verbose output
        quick: Use only selected efficient analyzers for faster analysis
        max_jobs: Maximum number of parallel analyzers
        complexity_threshold: Complexity threshold (A-F)

    Returns:
        A float between 0-100 representing the overall code quality
    """
    if isinstance(project_path, str):
        project_path = Path(project_path)

    if not project_path.exists():
        raise ValueError(f"Project path does not exist: {project_path}")

    if quick:
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
    quick: bool = True,
) -> float:
    """
    Analyze Python code from a string and return a quality score.

    Args:
        code: Python code as a string
        filename: Filename to use for the temporary file
        verbose: Enable verbose output
        quick: Use only selected efficient analyzers for faster analysis

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
            quick=quick,
        )

        return score

    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)


def assess_code_with_feedback(
    code: str,
    filename: str = "temp_file.py",
    verbose: bool = False,
    quick: bool = True,
) -> tuple[float, str]:
    """
    Analyze Python code from a string and return both a quality score and formatted feedback.

    Args:
        code: Python code as a string
        filename: Filename to use for the temporary file
        verbose: Enable verbose output
        quick: Use only selected efficient analyzers for faster analysis

    Returns:
        Tuple of (quality_score, formatted_feedback_string)
    """
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp(prefix="pycq_analyzer_")
    try:
        # Write the code to a temporary file
        temp_file = Path(temp_dir) / filename
        with open(temp_file, "w") as f:
            f.write(code)

        # Run the analyzers on the temporary directory
        if quick:
            findings = run_selected_analyzers(
                temp_dir,
                verbose,
                max_jobs=4,
                complexity_threshold="C",
            )
        else:
            findings = run_analyzer(
                project_path=temp_dir,
                static_only=True,
                verbose=verbose,
                max_jobs=4,
                complexity_threshold="C",
            )

        # Calculate scores based on findings
        scores = calculate_scores(findings)

        # Format findings as string
        feedback = format_findings_as_string(findings)

        return scores["overall"], feedback

    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)


def assess_dir_with_feedback(
    directory: Path,
    verbose: bool = False,
    quick: bool = True,
    max_jobs: int = 16,
    complexity_threshold="C",
    ignore_solution_unused: bool = True,
) -> tuple[float, str]:
    """
    Analyze Python code from a target directory and return both a quality score
    and formatted feedback.

    Args:
        directory: Source code directory
        verbose: Enable verbose output
        quick: Use only selected efficient analyzers for faster analysis

    Returns:
        Tuple of (quality_score, formatted_feedback_string)
    """
    # Run the analyzers on the temporary directory
    if quick:
        findings = run_selected_analyzers(
            directory,
            verbose,
            max_jobs=max_jobs,
            complexity_threshold="C",
            ignore_solution_unused=ignore_solution_unused,
        )
    else:
        findings = run_analyzers(
            project_path=directory,
            static_only=True,
            verbose=verbose,
            max_jobs=max_jobs,
            complexity_threshold=complexity_threshold,
            ignore_solution_unused=ignore_solution_unused,
        )

    # Calculate scores based on findings
    scores = calculate_scores(findings)

    # Format findings as string
    feedback = format_findings_as_string(findings)

    return scores["overall"], feedback


def analyze_file(
    filepath: Union[str, Path],
    verbose: bool = False,
    quick: bool = True,
) -> float:
    """
    Analyze a single file and return its quality score.

    Args:
        filepath: Path to the Python file to analyze
        verbose: Enable verbose output
        quick: Use only selected efficient analyzers for faster analysis

    Returns:
        A float between 0-100 representing the code quality
    """
    if isinstance(filepath, str):
        filepath = Path(filepath)

    if not filepath.exists():
        raise ValueError(f"File does not exist: {filepath}")

    # Read the file content and use assess_code_string
    with open(filepath, "r") as f:
        file_content = f.read()

    return assess_code_string(
        code=file_content, filename=filepath.name, verbose=verbose, quick=quick
    )


def run_selected_analyzers(
    project_path: Path,
    verbose: bool = False,
    max_jobs: int = 4,
    complexity_threshold: str = "C",
    ignore_solution_unused: bool = True,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run a selected set of efficient analyzers on the project.

    Uses a curated set of analyzers that provide a good balance between
    speed and coverage of common issues.

    Args:
        project_path: Path to the project to analyze
        verbose: Enable verbose output
        max_jobs: Maximum number of parallel analyzers
        complexity_threshold: Complexity threshold for Radon
        ignore_solution_unused: If True, filters out unused 'solution' function warning

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

    # Run analyzers in parallel with controlled concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_jobs) as executor:
        future_to_analyzer = {}
        for analyzer in analyzers:
            if analyzer.is_available:
                future = executor.submit(analyzer.analyze)
                future_to_analyzer[future] = analyzer

        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_analyzer):
            analyzer = future_to_analyzer[future]
            try:
                analyzer_findings = future.result()
                characteristic = analyzer.characteristic

                if ignore_solution_unused:
                    analyzer_findings = _filter_solution_unused(analyzer_findings)

                findings[characteristic].extend(analyzer_findings)
                if verbose:
                    print(
                        f"Found {len(analyzer_findings)} issues with {analyzer.__class__.__name__}"
                    )
            except Exception as e:
                if verbose:
                    print(f"Analyzer {analyzer.__class__.__name__} failed: {e}")

    return findings


def _filter_solution_unused(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter out unused 'solution' function warnings from findings.

    Args:
        findings: List of analyzer findings

    Returns:
        Filtered list with unused 'solution' function warnings removed
    """
    filtered_findings = []

    for finding in findings:
        # Check if this is an unused function warning for 'solution'
        should_filter = False

        # Check various possible patterns for unused function warnings
        message = finding.get("message", "").lower()
        rule_id = finding.get("rule_id", "").lower()

        # Common patterns for unused function warnings
        if any(
            [
                # Pylint patterns
                "unused-variable" in rule_id and "solution" in message,
                "unused-function" in rule_id and "solution" in message,
                "unused-import" in rule_id and "solution" in message,
                # Vulture patterns
                "unused" in rule_id and "solution" in message,
                # Generic patterns
                (
                    "unused" in message
                    and "function" in message
                    and "'solution'" in message
                ),
                ("unused" in message and "def solution" in message),
                ("unused" in message and "solution(" in message),
            ]
        ):
            should_filter = True

        # Also check if the finding specifically mentions solution function
        if not should_filter:
            # More specific checks for function definitions
            if "unused" in message and any(
                pattern in message
                for pattern in ["solution'", 'solution"', "solution(", "def solution"]
            ):
                should_filter = True

        if not should_filter:
            filtered_findings.append(finding)

    return filtered_findings


class MetricsCalculator:
    """Calculates rich insights and metrics from analyzer findings."""

    def __init__(
        self,
        project_path: Path,
        findings: Dict[str, List[Dict]],
        metadata: Dict[str, Any],
    ):
        self.project_path = project_path
        self.findings = findings
        self.metadata = metadata

    def calculate_overall_metrics(self) -> Dict[str, Any]:
        """Calculate project-wide metrics."""
        # Count Python files
        python_files = list(Path(self.project_path).glob("**/*.py"))
        total_files = len(python_files)

        # Count lines of code
        loc_data = count_lines_of_code(self.project_path)

        # Count code structures (rough estimates)
        total_functions = self.metadata.get(
            "total_functions", self._estimate_functions()
        )
        total_classes = self.metadata.get("total_classes", self._estimate_classes())

        # Calculate overall score
        overall_score = calculate_scores(self.findings)["overall"]

        return {
            "total_files": total_files,
            "total_lines": loc_data["total_lines"],
            "code_lines": loc_data["code_lines"],
            "total_functions": total_functions,
            "total_classes": total_classes,
            "quality_score": overall_score,
        }

    def calculate_maintainability_metrics(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate maintainability-specific metrics with rates."""
        # Dead code metrics
        dead_code_issues = [f for f in findings if "unused" in f.get("rule_id", "")]
        dead_code_count = len(dead_code_issues)

        # Breakdown by type
        dead_code_breakdown = {
            "unused_functions": len(
                [f for f in dead_code_issues if "function" in f.get("rule_id", "")]
            ),
            "unused_variables": len(
                [f for f in dead_code_issues if "variable" in f.get("rule_id", "")]
            ),
            "unused_classes": len(
                [f for f in dead_code_issues if "class" in f.get("rule_id", "")]
            ),
            "unused_imports": len(
                [f for f in dead_code_issues if "import" in f.get("rule_id", "")]
            ),
        }

        # Dead code rate (normalized by total code structures)
        total_structures = self.metadata.get("total_functions", 0) + self.metadata.get(
            "total_classes", 0
        )
        dead_code_rate = dead_code_count / max(total_structures, 1)

        # Complexity metrics
        complexity_issues = [
            f for f in findings if "complexity" in f.get("rule_id", "")
        ]
        complexity_count = len(complexity_issues)
        complexity_rate = complexity_count / max(
            self.metadata.get("total_functions", 1), 1
        )

        # Breakdown by type
        complexity_breakdown = {
            "high_cyclomatic": len(
                [
                    f
                    for f in complexity_issues
                    if "cyclomatic" in f.get("message", "").lower()
                    or "complexity-" in f.get("rule_id", "")
                ]
            ),
            "excessive_parameters": len(
                [
                    f
                    for f in complexity_issues
                    if "parameter" in f.get("message", "").lower()
                ]
            ),
            "large_files": len(
                [
                    f
                    for f in complexity_issues
                    if "file" in f.get("message", "").lower()
                    and "length" in f.get("message", "").lower()
                    or "excessive-file-length" in f.get("rule_id", "")
                ]
            ),
        }

        # Distribution from Radon if available
        distribution = self._calculate_complexity_distribution(findings)

        # Duplication metrics
        duplication_issues = [
            f for f in findings if "duplicate" in f.get("rule_id", "")
        ]
        duplication_count = len(duplication_issues)
        duplication_rate = (
            duplication_count / max(self.metadata.get("total_lines", 1), 1) * 1000
        )  # per 1000 lines

        return {
            "metrics": {
                "dead_code": {
                    "count": dead_code_count,
                    "rate": dead_code_rate,
                    "breakdown": dead_code_breakdown,
                },
                "complexity": {
                    "count": complexity_count,
                    "rate": complexity_rate,
                    "breakdown": complexity_breakdown,
                    "distribution": distribution,
                },
                "duplication": {
                    "count": duplication_count,
                    "rate": duplication_rate,
                    "breakdown": {"duplicate_blocks": duplication_count},
                },
            }
        }

    def calculate_security_metrics(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate security-specific metrics with rates."""
        # Vulnerable dependencies
        vulnerable_deps = [
            f for f in findings if "vulnerable-dependency" in f.get("rule_id", "")
        ]
        vuln_count = len(vulnerable_deps)

        # Breakdown by severity
        vuln_breakdown = {
            "critical": len(
                [f for f in vulnerable_deps if f.get("severity") == "critical"]
            ),
            "high": len([f for f in vulnerable_deps if f.get("severity") == "high"]),
            "medium": len(
                [f for f in vulnerable_deps if f.get("severity") == "medium"]
            ),
            "low": len([f for f in vulnerable_deps if f.get("severity") == "low"]),
        }

        # Security anti-patterns
        security_antipatterns = [f for f in findings if f.get("analyzer") == "bandit"]
        security_count = len(security_antipatterns)
        security_rate = (
            security_count / max(self.metadata.get("total_lines", 1), 1) * 1000
        )

        # Breakdown by type
        security_breakdown = {
            "hardcoded_credentials": len(
                [
                    f
                    for f in security_antipatterns
                    if any(
                        x in f.get("message", "").lower()
                        for x in ["password", "credential", "secret"]
                    )
                ]
            ),
            "sql_injection": len(
                [
                    f
                    for f in security_antipatterns
                    if "sql" in f.get("message", "").lower()
                ]
            ),
            "command_injection": len(
                [
                    f
                    for f in security_antipatterns
                    if any(
                        x in f.get("message", "").lower()
                        for x in ["command", "shell", "subprocess"]
                    )
                ]
            ),
            "insecure_crypto": len(
                [
                    f
                    for f in security_antipatterns
                    if any(
                        x in f.get("message", "").lower()
                        for x in ["crypto", "hash", "cipher", "random"]
                    )
                ]
            ),
        }

        return {
            "metrics": {
                "vulnerable_dependencies": {
                    "count": vuln_count,
                    "rate": vuln_count
                    / max(self.metadata.get("total_dependencies", 1), 1),
                    "breakdown": vuln_breakdown,
                },
                "security_antipatterns": {
                    "count": security_count,
                    "rate": security_rate,
                    "breakdown": security_breakdown,
                },
            }
        }

    def calculate_performance_metrics(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate performance-specific metrics with rates."""
        # String concatenation issues
        string_concat_issues = [
            f for f in findings if f.get("analyzer") == "string_concatenation"
        ]
        string_count = len(string_concat_issues)

        # Resource consumption issues
        resource_issues = [
            f for f in findings if f.get("analyzer") == "resource_consumption"
        ]
        resource_count = len(resource_issues)

        # Data structure complexity issues
        data_structure_issues = [
            f for f in findings if f.get("analyzer") == "data_structure_complexity"
        ]
        data_structure_count = len(data_structure_issues)

        return {
            "metrics": {
                "inefficient_string_operations": {
                    "count": string_count,
                    "rate": string_count / max(self.metadata.get("total_loops", 1), 1),
                    "breakdown": {"string_concat_in_loops": string_count},
                },
                "resource_consumption": {
                    "count": resource_count,
                    "rate": resource_count
                    / max(self.metadata.get("total_loops", 1), 1),
                    "breakdown": {
                        "io_in_loops": len(
                            [
                                f
                                for f in resource_issues
                                if "io" in f.get("message", "").lower()
                            ]
                        ),
                        "growing_structures": len(
                            [
                                f
                                for f in resource_issues
                                if "growing" in f.get("message", "").lower()
                            ]
                        ),
                    },
                },
                "data_structure_complexity": {
                    "count": data_structure_count,
                    "rate": data_structure_count
                    / max(self.metadata.get("total_classes", 1), 1),
                    "breakdown": {
                        "excessive_attributes": len(
                            [
                                f
                                for f in data_structure_issues
                                if "attributes" in f.get("message", "")
                            ]
                        ),
                        "deep_nesting": len(
                            [
                                f
                                for f in data_structure_issues
                                if "nesting" in f.get("message", "")
                            ]
                        ),
                    },
                },
            }
        }

    def calculate_reliability_metrics(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate reliability-specific metrics with rates."""
        # Exception handling issues
        exception_issues = [
            f for f in findings if f.get("analyzer") == "exception_handling"
        ]
        exception_count = len(exception_issues)

        # Type safety issues (mypy)
        type_issues = [f for f in findings if f.get("analyzer") == "mypy"]
        type_count = len(type_issues)

        # Threading issues
        threading_issues = [
            f
            for f in findings
            if f.get("analyzer") in ["deadlock_detection", "infinite_loop_detection"]
        ]
        threading_count = len(threading_issues)

        return {
            "metrics": {
                "exception_handling_issues": {
                    "count": exception_count,
                    "rate": exception_count
                    / max(self.metadata.get("total_try_blocks", 1), 1),
                    "breakdown": {
                        "bare_except": len(
                            [
                                f
                                for f in exception_issues
                                if "bare except" in f.get("message", "")
                            ]
                        ),
                        "empty_handlers": len(
                            [
                                f
                                for f in exception_issues
                                if "empty" in f.get("message", "")
                            ]
                        ),
                    },
                },
                "type_safety_issues": {
                    "count": type_count,
                    "rate": type_count
                    / max(self.metadata.get("total_functions", 1), 1),
                    "breakdown": {"type_errors": type_count},
                },
                "threading_issues": {
                    "count": threading_count,
                    "rate": threading_count
                    / max(self.metadata.get("total_threading_operations", 1), 1),
                    "breakdown": {
                        "potential_deadlocks": len(
                            [
                                f
                                for f in threading_issues
                                if f.get("analyzer") == "deadlock_detection"
                            ]
                        ),
                        "infinite_loops": len(
                            [
                                f
                                for f in threading_issues
                                if f.get("analyzer") == "infinite_loop_detection"
                            ]
                        ),
                    },
                },
            }
        }

    def calculate_file_level_insights(self) -> List[Dict[str, Any]]:
        """Calculate insights at the file level."""
        file_metrics = defaultdict(
            lambda: {
                "dead_code_items": 0,
                "complexity_violations": 0,
                "security_issues": 0,
                "performance_issues": 0,
                "reliability_issues": 0,
            }
        )

        # Aggregate findings by file
        for characteristic, findings_list in self.findings.items():
            for finding in findings_list:
                file_path = finding.get("file_path", "unknown")
                if file_path == "unknown":
                    continue

                # Categorize by issue type
                if characteristic == "maintainability":
                    if "unused" in finding.get("rule_id", ""):
                        file_metrics[file_path]["dead_code_items"] += 1
                    elif "complexity" in finding.get("rule_id", ""):
                        file_metrics[file_path]["complexity_violations"] += 1
                elif characteristic == "security":
                    file_metrics[file_path]["security_issues"] += 1
                elif characteristic == "performance":
                    file_metrics[file_path]["performance_issues"] += 1
                elif characteristic == "reliability":
                    file_metrics[file_path]["reliability_issues"] += 1

        # Convert to list format, sorted by total issues
        result = []
        for file_path, metrics in file_metrics.items():
            total_issues = sum(metrics.values())
            result.append(
                {
                    "file_path": str(file_path),
                    "total_issues": total_issues,
                    "metrics": metrics,
                }
            )

        # Sort by total issues (descending)
        result.sort(key=lambda x: x["total_issues"], reverse=True)

        return result

    def _calculate_complexity_distribution(
        self, findings: List[Dict]
    ) -> Dict[str, int]:
        """Calculate complexity distribution from Radon findings."""
        distribution = {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0}

        for finding in findings:
            if finding.get("analyzer") == "radon" and "complexity-" in finding.get(
                "rule_id", ""
            ):
                # Extract rank from rule_id (e.g., 'complexity-D' -> 'D')
                rule_id = finding.get("rule_id", "")
                if "-" in rule_id:
                    rank = rule_id.split("-")[-1]
                    if rank in distribution:
                        distribution[rank] += 1

        return distribution

    def _estimate_functions(self) -> int:
        """Rough estimation of total functions from common patterns."""
        try:
            python_files = list(Path(self.project_path).glob("**/*.py"))
            total_functions = 0
            for file_path in python_files:
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                        # Simple regex-based counting
                        import re

                        func_matches = re.findall(r"^\s*def\s+", content, re.MULTILINE)
                        total_functions += len(func_matches)
                except:
                    continue
            return total_functions
        except:
            return 100  # Default fallback

    def _estimate_classes(self) -> int:
        """Rough estimation of total classes from common patterns."""
        try:
            python_files = list(Path(self.project_path).glob("**/*.py"))
            total_classes = 0
            for file_path in python_files:
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                        # Simple regex-based counting
                        import re

                        class_matches = re.findall(
                            r"^\s*class\s+", content, re.MULTILINE
                        )
                        total_classes += len(class_matches)
                except:
                    continue
            return total_classes
        except:
            return 20  # Default fallback


def get_rich_insights(
    project_path: Union[str, Path],
    verbose: bool = False,
    include_rates: bool = True,
    include_distributions: bool = True,
) -> Dict[str, Any]:
    """
    Analyze a Python project and return rich insights with detailed metrics breakdown.

    Args:
        project_path: Path to the Python project to analyze
        verbose: Enable verbose output
        include_rates: Include rate calculations in the results
        include_distributions: Include distribution analysis in the results

    Returns:
        A comprehensive dictionary with detailed breakdowns of code quality metrics
    """
    if isinstance(project_path, str):
        project_path = Path(project_path)

    if not project_path.exists():
        raise ValueError(f"Project path does not exist: {project_path}")

    # Run all analyzers and get findings
    findings = run_analyzers(
        project_path=project_path,
        static_only=True,
        verbose=verbose,
        max_jobs=16,
        complexity_threshold="C",
    )

    # Calculate basic scores
    scores = calculate_scores(findings)

    # Collect metadata about the project
    metadata = _collect_project_metadata(project_path)

    # Create metrics calculator
    calculator = MetricsCalculator(project_path, findings, metadata)

    # Calculate overall metrics
    overall_metrics = calculator.calculate_overall_metrics()

    # Calculate characteristic-specific metrics
    characteristics_data = {}
    for characteristic, characteristic_findings in findings.items():
        if characteristic == "maintainability":
            char_data = calculator.calculate_maintainability_metrics(
                characteristic_findings
            )
        elif characteristic == "security":
            char_data = calculator.calculate_security_metrics(characteristic_findings)
        elif characteristic == "performance":
            char_data = calculator.calculate_performance_metrics(
                characteristic_findings
            )
        elif characteristic == "reliability":
            char_data = calculator.calculate_reliability_metrics(
                characteristic_findings
            )
        else:
            char_data = {"metrics": {}}

        # Apply filters based on parameters
        if not include_rates:
            # Remove rate calculations if not requested
            for metric_name, metric_data in char_data.get("metrics", {}).items():
                if isinstance(metric_data, dict) and "rate" in metric_data:
                    del metric_data["rate"]

        if not include_distributions:
            # Remove distribution data if not requested
            for metric_name, metric_data in char_data.get("metrics", {}).items():
                if isinstance(metric_data, dict) and "distribution" in metric_data:
                    del metric_data["distribution"]

        characteristics_data[characteristic] = {
            "score": scores.get(characteristic, 0),
            "total_issues": len(characteristic_findings),
            **char_data,
        }

    # Calculate file-level insights
    file_level_insights = calculator.calculate_file_level_insights()

    # Construct the result
    result = {
        "overall_metrics": overall_metrics,
        "characteristics": characteristics_data,
        "file_level_insights": file_level_insights,
    }

    return result


def _collect_project_metadata(project_path: Path) -> Dict[str, Any]:
    """Collect metadata about the project for rate calculations."""
    metadata = {}

    try:
        # Count lines of code
        loc_data = count_lines_of_code(project_path)
        metadata.update(loc_data)

        # Estimate code structures
        python_files = list(project_path.glob("**/*.py"))
        metadata["total_files"] = len(python_files)

        # Simple estimation of code structures
        total_functions = 0
        total_classes = 0
        total_loops = 0
        total_try_blocks = 0

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Simple regex-based counting
                import re

                total_functions += len(re.findall(r"^\s*def\s+", content, re.MULTILINE))
                total_classes += len(re.findall(r"^\s*class\s+", content, re.MULTILINE))
                total_loops += len(
                    re.findall(r"^\s*(for|while)\s+", content, re.MULTILINE)
                )
                total_try_blocks += len(
                    re.findall(r"^\s*try\s*:", content, re.MULTILINE)
                )

            except (UnicodeDecodeError, FileNotFoundError):
                continue

        metadata.update(
            {
                "total_functions": total_functions,
                "total_classes": total_classes,
                "total_loops": total_loops,
                "total_try_blocks": total_try_blocks,
                "total_dependencies": _estimate_dependencies(project_path),
                "total_threading_operations": _estimate_threading_operations(
                    project_path
                ),
            }
        )

    except Exception as e:
        # Fallback values
        metadata.update(
            {
                "total_lines": 1000,
                "code_lines": 800,
                "total_functions": 50,
                "total_classes": 10,
                "total_loops": 20,
                "total_try_blocks": 10,
                "total_dependencies": 10,
                "total_threading_operations": 1,
            }
        )

    return metadata


def _estimate_dependencies(project_path: Path) -> int:
    """Estimate number of dependencies from requirements files."""
    try:
        # Look for common requirements files
        requirements_files = [
            project_path / "requirements.txt",
            project_path / "setup.py",
            project_path / "pyproject.toml",
            project_path / "Pipfile",
        ]

        total_deps = 0
        for req_file in requirements_files:
            if req_file.exists():
                try:
                    with open(req_file, "r") as f:
                        content = f.read()
                        if req_file.suffix == ".txt":
                            # Count lines that aren't comments
                            lines = [
                                line.strip()
                                for line in content.split("\n")
                                if line.strip() and not line.strip().startswith("#")
                            ]
                            total_deps += len(lines)
                        elif req_file.suffix == ".py":
                            # Count requires/install_requires entries
                            import re

                            matches = re.findall(
                                r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL
                            )
                            for match in matches:
                                deps = [
                                    dep.strip().strip("\"'")
                                    for dep in match.split(",")
                                    if dep.strip()
                                ]
                                total_deps += len([d for d in deps if d])
                except:
                    continue

        return max(total_deps, 1)  # At least 1 to avoid division by zero

    except:
        return 10  # Default fallback


def _estimate_threading_operations(project_path: Path) -> int:
    """Estimate number of threading operations."""
    try:
        python_files = list(project_path.glob("**/*.py"))
        threading_ops = 0

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Look for common threading patterns
                import re

                threading_ops += len(
                    re.findall(
                        r"(threading\.|multiprocessing\.|\.Lock\(|\.acquire\(|\.release\()",
                        content,
                    )
                )

            except (UnicodeDecodeError, FileNotFoundError):
                continue

        return max(threading_ops, 1)  # At least 1 to avoid division by zero

    except:
        return 1  # Default fallback
