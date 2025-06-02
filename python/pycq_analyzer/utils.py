"""Utility functions for PyCQ analyzer."""

import os
import logging
import subprocess

from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from collections import defaultdict


# Configure logging
def configure_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return logger with appropriate verbosity level."""
    log_level = logging.INFO if verbose else logging.WARNING

    # Create logger
    logger = logging.getLogger("pycq_analyzer")
    logger.setLevel(log_level)

    # Clear any existing handlers
    if logger.handlers:
        logger.handlers = []

    # Create console handler with formatter
    console = logging.StreamHandler()
    console.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(console)

    return logger


# Run external command
def run_command(
    cmd: List[str], cwd: Optional[Union[str, Path]] = None
) -> Tuple[int, str, str]:
    """
    Run an external command and return exit code, stdout, and stderr.

    Args:
        cmd: Command and arguments as a list
        cwd: Working directory for the command

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)


def is_tool_installed(tool_name: str) -> bool:
    """
    Check if a command-line tool is installed.

    Args:
        tool_name: Name of the tool to check

    Returns:
        True if the tool is installed, False otherwise
    """
    try:
        result = subprocess.run(
            ["which", tool_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode == 0
    except:
        return False


def count_lines_of_code(
    path: Union[str, Path], extensions: List[str] = None
) -> Dict[str, int]:
    """
    Count lines of code in a file or directory.

    Args:
        path: Path to file or directory
        extensions: List of file extensions to count (default: ['.py'])

    Returns:
        Dictionary with counts for total_lines, code_lines, comment_lines, blank_lines
    """
    if extensions is None:
        extensions = [".py"]

    path = Path(path)

    # Initialize counters
    total_lines = 0
    code_lines = 0
    comment_lines = 0
    blank_lines = 0

    if path.is_file() and path.suffix in extensions:
        # Process single file
        try:
            with open(path, "r", encoding="utf-8") as file:
                in_multiline_comment = False

                for line in file:
                    total_lines += 1
                    stripped = line.strip()

                    # Check for blank lines
                    if not stripped:
                        blank_lines += 1
                        continue

                    # Check for comments
                    if stripped.startswith("#"):
                        comment_lines += 1
                    elif stripped.startswith('"""') or stripped.startswith("'''"):
                        comment_lines += 1
                        # Toggle multiline comment state if the line also ends with triple quotes
                        if stripped.endswith('"""') or stripped.endswith("'''"):
                            if len(stripped) > 3:  # Not just a single triple quote
                                # This is a single line docstring
                                pass
                            else:
                                in_multiline_comment = not in_multiline_comment
                        else:
                            in_multiline_comment = not in_multiline_comment
                    elif in_multiline_comment:
                        comment_lines += 1
                        # Check if this line ends the multiline comment
                        if stripped.endswith('"""') or stripped.endswith("'''"):
                            in_multiline_comment = False
                    else:
                        code_lines += 1
        except Exception as e:
            logging.warning(f"Error counting lines in {path}: {e}")

    elif path.is_dir():
        # Process directory recursively
        for root, _, files in os.walk(path):
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix in extensions:
                    file_counts = count_lines_of_code(file_path, extensions)
                    total_lines += file_counts["total_lines"]
                    code_lines += file_counts["code_lines"]
                    comment_lines += file_counts["comment_lines"]
                    blank_lines += file_counts["blank_lines"]

    return {
        "total_lines": total_lines,
        "code_lines": code_lines,
        "comment_lines": comment_lines,
        "blank_lines": blank_lines,
    }


def load_cwe_data() -> Dict[str, Dict[str, Any]]:
    """
    Load CWE data from internal mapping.

    Returns:
        Dictionary mapping CWE IDs to their metadata
    """
    # This is a simplified version - in a production system,
    # this would load from a more complete database
    cwe_data = {
        # Maintainability
        "CWE-407": {
            "name": "Algorithmic Complexity",
            "categories": ["maintainability"],
            "description": "An algorithm has inefficient worst-case computational complexity.",
        },
        "CWE-478": {
            "name": "Missing Default Case in Switch Statement",
            "categories": ["maintainability"],
            "description": "The code does not have a default case in a switch statement.",
        },
        "CWE-561": {
            "name": "Dead Code",
            "categories": ["maintainability"],
            "description": "The software contains dead code that can never be executed.",
        },
        # Performance
        "CWE-1046": {
            "name": "Creation of Immutable Text Using String Concatenation",
            "categories": ["performance"],
            "description": "Creation of immutable string objects using concatenation operations.",
        },
        "CWE-1050": {
            "name": "Excessive Platform Resource Consumption within a Loop",
            "categories": ["performance"],
            "description": "The software has a loop that can consume excessive resources.",
        },
        # Security
        "CWE-78": {
            "name": "OS Command Injection",
            "categories": ["security"],
            "description": "The software constructs an OS command using externally-influenced input.",
        },
        "CWE-89": {
            "name": "SQL Injection",
            "categories": ["security"],
            "description": "The software constructs an SQL command using externally-influenced input.",
        },
        # Reliability
        "CWE-476": {
            "name": "NULL Pointer Dereference",
            "categories": ["reliability"],
            "description": "The application dereferences a pointer that it expects to be valid, but is NULL.",
        },
        "CWE-662": {
            "name": "Improper Synchronization",
            "categories": ["reliability"],
            "description": "The software uses a shared resource without proper synchronization.",
        },
    }

    return cwe_data


def format_findings_as_string(
    findings: dict[str, list[dict]], max_items_per_category: int | None = None
) -> str:
    """
    Format findings dictionary into a human-readable string.

    Similar to display_issues in main.py but returns a string instead of printing.

    Args:
        findings: Dictionary of findings by characteristic
        max_items_per_category: The maximum number of items to display per characteristic

    Returns:
        Formatted string with detailed feedback
    """
    total_issues = sum(len(issues) for issues in findings.values())
    if total_issues == 0:
        return "No issues found."

    feedback_lines = [f"Found {total_issues} issues:"]

    # Process each characteristic
    for characteristic, characteristic_findings in findings.items():
        items = 0

        if not characteristic_findings:
            continue

        if (
            max_items_per_category is not None
            and len(characteristic_findings) > max_items_per_category
        ):
            feedback_lines.append(
                f"\n{characteristic.upper()} ({len(characteristic_findings)} issues - showing {max_items_per_category}):"
            )
        else:
            feedback_lines.append(
                f"\n{characteristic.upper()} ({len(characteristic_findings)} issues):"
            )

        # Group by severity for better readability
        severity_groups = defaultdict(list)
        for finding in characteristic_findings:
            severity = finding.get("severity", "medium")
            severity_groups[severity].append(finding)

        # Add issues by severity (highest first)
        severity_order = ["critical", "high", "medium", "low", "info"]
        for severity in severity_order:
            severity_issues = severity_groups.get(severity, [])
            if not severity_issues:
                continue

            feedback_lines.append(f"  {severity} severity:")
            for finding in severity_issues:
                file_path = finding.get("file_path", "unknown")
                if isinstance(file_path, Path):
                    file_path = file_path.name
                else:
                    file_path = Path(file_path).name

                line = finding.get("line", "?")
                message = finding.get("message", "No details")
                rule_id = finding.get("rule_id", "")
                feedback_lines.append(
                    f"    - {file_path}:{line} - {message} (Rule: {rule_id})"
                )
                items += 1

                # Limit the number of items displayed
                if (
                    max_items_per_category is not None
                    and items >= max_items_per_category
                ):
                    break

            if max_items_per_category is not None and items >= max_items_per_category:
                break

    return "\n".join(feedback_lines)
