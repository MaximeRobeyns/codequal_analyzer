"""Xenon analyzer for complexity threshold enforcement."""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

class XenonAnalyzer(BaseAnalyzer):
    """Analyzer for Xenon, enforcing complexity thresholds."""

    def __init__(
        self,
        project_path: Union[str, Path],
        verbose: bool = False,
        max_absolute: str = "C",
        max_modules: str = "B",
        max_average: str = "A"
    ):
        """
        Initialize the Xenon analyzer.

        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            max_absolute: Maximum absolute complexity rank allowed (A-F)
            max_modules: Maximum modules complexity rank allowed (A-F)
            max_average: Maximum average complexity rank allowed (A-F)
        """
        super().__init__(project_path, 'maintainability', verbose)
        self.max_absolute = max_absolute
        self.max_modules = max_modules
        self.max_average = max_average

    def _check_availability(self) -> bool:
        """Check if Xenon is installed."""
        return is_tool_installed('xenon')

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Xenon analysis for complexity threshold enforcement.

        Returns:
            List of findings
        """
        self.findings = []

        if not self.is_available:
            self.logger.warning("Xenon is not installed. Skipping analysis.")
            return self.findings

        self.logger.info("Running Xenon analysis for complexity threshold enforcement...")

        # Build command for Xenon
        cmd = [
            "xenon",
            "--max-absolute", self.max_absolute,
            "--max-modules", self.max_modules,
            "--max-average", self.max_average,
            str(self.project_path)
        ]

        # Run Xenon
        exit_code, stdout, stderr = run_command(cmd)

        # If Xenon returns exit code 0, it means no violations were found
        # For non-zero exit codes, it indicates violations found:
        # 1 = modules complexity violations
        # 2 = average complexity violations
        # 4 = absolute complexity violations
        # (these can be combined, e.g., 7 means all three types of violations)
        if exit_code > 0:
            self._process_xenon_violations(exit_code, stdout, stderr)

        self.logger.info(f"Found {len(self.findings)} complexity threshold issues with Xenon")
        return self.findings

    def _process_xenon_violations(self, exit_code: int, stdout: str, stderr: str) -> None:
        """
        Process Xenon violations based on exit code and output.

        Args:
            exit_code: Xenon exit code (1, 2, 4, or combinations)
            stdout: Standard output
            stderr: Standard error output
        """
        # Check bitwise flags in exit code to determine violation types
        has_modules_violations = (exit_code & 1) != 0
        has_average_violations = (exit_code & 2) != 0
        has_absolute_violations = (exit_code & 4) != 0

        # Process output to extract detailed information
        # Xenon doesn't always provide detailed output for each violation,
        # so we need to handle this gracefully

        # Parse stdout for specific violation information
        if stdout:
            self._process_xenon_findings(stdout)

        # Parse stderr for additional information
        if stderr:
            self._process_xenon_findings(stderr)

        # If no detailed findings were extracted but we have violations,
        # create generic findings based on the exit code
        if not self.findings:
            if has_modules_violations:
                self._add_generic_finding("excessive-modules-complexity", "high",
                                        "Modules complexity exceeds threshold")

            if has_average_violations:
                self._add_generic_finding("excessive-average-complexity", "medium",
                                        "Average complexity exceeds threshold")

            if has_absolute_violations:
                self._add_generic_finding("excessive-absolute-complexity", "high",
                                        "Absolute function complexity exceeds threshold")

    def _add_generic_finding(self, issue_type: str, severity: str, message: str) -> None:
        """
        Add a generic finding when specific details aren't available.

        Args:
            issue_type: Type of issue
            severity: Severity level
            message: Issue message
        """
        finding = {
            'analyzer': 'xenon',
            'characteristic': self.characteristic,
            'rule_id': issue_type,
            'cwe_id': 'CWE-1121',  # Excessive McCabe Cyclomatic Complexity
            'severity': severity,
            'file_path': str(self.project_path),  # Use project path when specific file isn't known
            'line': 1,  # Default line number
            'message': message,
            'raw_data': {
                'exit_code': issue_type
            }
        }

        self.findings.append(finding)

    def _process_xenon_findings(self, output: str) -> None:
        """
        Process Xenon output and convert to findings.

        Args:
            output: Xenon output text
        """
        # Regular expression to match file paths and issues
        # Example output lines:
        # /path/to/file.py - too complex module (X > Y)
        # /path/to/file.py:10 - 'function_name' is too complex (X > Y)
        complexity_regex = r'(.+?)(?::\s*(\d+))?\s*-\s*(.+)'

        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            match = re.match(complexity_regex, line)
            if match:
                file_path = match.group(1).strip()
                line_no = int(match.group(2)) if match.group(2) else 1
                issue_desc = match.group(3).strip()

                # Determine issue type and severity
                if "too complex module" in issue_desc:
                    issue_type = "excessive-modules-complexity"
                    message = f"Module complexity violation: {issue_desc}"
                    severity = "high"
                elif "is too complex" in issue_desc and "'" in issue_desc:
                    issue_type = "excessive-absolute-complexity"
                    message = f"Function complexity violation: {issue_desc}"
                    severity = "high"
                elif "average complexity" in issue_desc:
                    issue_type = "excessive-average-complexity"
                    message = f"Average complexity violation: {issue_desc}"
                    severity = "medium"
                else:
                    issue_type = "complexity-threshold-violation"
                    message = f"Complexity threshold violation: {issue_desc}"
                    severity = "medium"

                # Create finding
                finding = {
                    'analyzer': 'xenon',
                    'characteristic': self.characteristic,
                    'rule_id': issue_type,
                    'cwe_id': 'CWE-1121',  # Excessive McCabe Cyclomatic Complexity
                    'severity': severity,
                    'file_path': file_path,
                    'line': line_no,
                    'message': message,
                    'raw_data': {
                        'xenon_output': line
                    }
                }

                self.findings.append(finding)
            elif "are too complex" in line or "average complexity" in line:
                # This is a summary line without a specific file path
                # We'll create a generic finding based on the issue description

                if "modules are too complex" in line:
                    issue_type = "excessive-modules-complexity"
                    message = f"Module complexity violation: {line}"
                    severity = "high"
                elif "average complexity" in line:
                    issue_type = "excessive-average-complexity"
                    message = f"Average complexity violation: {line}"
                    severity = "medium"
                else:
                    issue_type = "complexity-threshold-violation"
                    message = f"Complexity threshold violation: {line}"
                    severity = "medium"

                # Create generic finding for project-wide issues
                finding = {
                    'analyzer': 'xenon',
                    'characteristic': self.characteristic,
                    'rule_id': issue_type,
                    'cwe_id': 'CWE-1121',  # Excessive McCabe Cyclomatic Complexity
                    'severity': severity,
                    'file_path': str(self.project_path),
                    'line': 1,
                    'message': message,
                    'raw_data': {
                        'xenon_output': line
                    }
                }

                self.findings.append(finding)