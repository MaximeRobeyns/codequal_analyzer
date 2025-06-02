"""Radon analyzer for code complexity issues."""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

# Mapping of Radon complexity levels to CWE IDs
COMPLEXITY_TO_CWE = {
    "A": None,  # No CWE for low complexity
    "B": None,  # No CWE for low complexity
    "C": "CWE-1121",  # Moderate complexity -> Excessive McCabe Cyclomatic Complexity
    "D": "CWE-1121",  # High complexity -> Excessive McCabe Cyclomatic Complexity
    "E": "CWE-1121",  # Very high complexity -> Excessive McCabe Cyclomatic Complexity
    "F": "CWE-1121",  # Extremely high complexity -> Excessive McCabe Cyclomatic Complexity
}

# Severity mapping based on Radon complexity rank
COMPLEXITY_SEVERITY_MAP = {
    "A": "info",  # Low
    "B": "info",  # Low
    "C": "low",  # Moderate
    "D": "medium",  # High
    "E": "high",  # Very high
    "F": "critical",  # Extremely high
}


class RadonAnalyzer(BaseAnalyzer):
    """Analyzer for Radon code complexity metrics."""

    def __init__(
        self,
        project_path: Union[str, Path],
        verbose: bool = False,
        complexity_threshold: str = "C",
    ):
        """
        Initialize the Radon analyzer.

        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            complexity_threshold: Minimum complexity rank to report (A-F)
        """
        super().__init__(project_path, "maintainability", verbose)
        self.complexity_threshold = complexity_threshold

    def _check_availability(self) -> bool:
        """Check if Radon is installed."""
        return is_tool_installed("radon")

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Radon analysis for code complexity.

        Returns:
            List of findings
        """
        self.findings = []

        if not self.is_available:
            self.logger.warning("Radon is not installed. Skipping analysis.")
            return self.findings

        self.logger.info("Running Radon complexity analysis...")

        # Build command to get cyclomatic complexity in JSON format
        cmd = ["radon", "cc", "--json", str(self.project_path)]

        # Run Radon
        exit_code, stdout, stderr = run_command(cmd)

        # Check for errors
        if exit_code != 0:
            self.logger.error(f"Error running Radon: {stderr}")
            return self.findings

        # Parse JSON output
        try:
            if stdout.strip():
                complexity_data = json.loads(stdout)
                self._process_complexity_findings(complexity_data)
        except json.JSONDecodeError:
            self.logger.error(f"Error parsing Radon output: {stdout}")

        # Run raw metrics for additional maintainability metrics
        self._analyze_raw_metrics()

        self.logger.info(f"Found {len(self.findings)} complexity issues with Radon")
        return self.findings

    def _process_complexity_findings(self, data: Dict[str, Any]) -> None:
        """
        Process Radon complexity findings and map to CWE IDs.

        Args:
            data: Radon complexity data dictionary
        """
        for file_path, functions in data.items():
            for func_data in functions:
                # Extract data
                name = func_data.get("name")
                line = func_data.get("lineno", 0)
                complexity = func_data.get("complexity", 0)
                rank = self._complexity_rank(complexity)

                # Skip if below threshold
                if rank < self.complexity_threshold:
                    continue

                # Skip if no CWE mapping
                cwe_id = COMPLEXITY_TO_CWE.get(rank)
                if cwe_id is None:
                    continue

                # Get severity based on complexity rank
                severity = COMPLEXITY_SEVERITY_MAP.get(rank, "medium")

                # Create finding
                finding = {
                    "analyzer": "radon",
                    "characteristic": self.characteristic,
                    "rule_id": f"complexity-{rank}",
                    "cwe_id": cwe_id,
                    "severity": severity,
                    "file_path": file_path,
                    "line": line,
                    "message": f"Function '{name}' has cyclomatic complexity of {complexity} (rank {rank})",
                    "raw_data": func_data,
                }

                self.findings.append(finding)

    def _complexity_rank(self, complexity: int) -> str:
        """
        Convert raw complexity score to Radon ranking.

        Args:
            complexity: Cyclomatic complexity score

        Returns:
            Rank letter from A (best) to F (worst)
        """
        if complexity <= 5:
            return "A"
        elif complexity <= 10:
            return "B"
        elif complexity <= 20:
            return "C"
        elif complexity <= 30:
            return "D"
        elif complexity <= 40:
            return "E"
        else:
            return "F"

    def _analyze_raw_metrics(self) -> None:
        """Run Radon raw metrics analysis for additional maintainability metrics."""
        # Build command to get raw metrics in JSON format
        cmd = ["radon", "raw", "--json", str(self.project_path)]

        # Run Radon
        exit_code, stdout, stderr = run_command(cmd)

        # Check for errors
        if exit_code != 0:
            self.logger.error(f"Error running Radon raw metrics: {stderr}")
            return

        # Parse JSON output
        try:
            if stdout.strip():
                metrics_data = json.loads(stdout)
                self._process_raw_metrics(metrics_data)
        except json.JSONDecodeError:
            self.logger.error(f"Error parsing Radon raw metrics output: {stdout}")

    def _process_raw_metrics(self, data: Dict[str, Any]) -> None:
        """
        Process Radon raw metrics and identify issues like file size.

        Args:
            data: Radon raw metrics data dictionary
        """
        for file_path, metrics in data.items():
            # Check for excessively large files (CWE-1080)
            loc = metrics.get("loc", 0)
            if loc > 1000:  # Default threshold from CISQ doc
                finding = {
                    "analyzer": "radon",
                    "characteristic": self.characteristic,
                    "rule_id": "excessive-file-length",
                    "cwe_id": "CWE-1080",  # Source Code File with Excessive Number of Lines of Code
                    "severity": "medium",
                    "file_path": file_path,
                    "line": 1,
                    "message": f"File has {loc} lines of code (exceeds recommended limit of 1000)",
                    "raw_data": metrics,
                }
                self.findings.append(finding)
