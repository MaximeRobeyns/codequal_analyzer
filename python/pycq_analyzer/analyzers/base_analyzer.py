"""Base analyzer class for all PyCQ quality analyzers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Union

from ..utils import configure_logging


class BaseAnalyzer(ABC):
    """Base class for all analyzers."""

    def __init__(
        self, project_path: Union[str, Path], characteristic: str, verbose: bool = False
    ):
        """
        Initialize a base analyzer.

        Args:
            project_path: Path to the project to analyze
            characteristic: Quality characteristic this analyzer targets
            verbose: Whether to enable verbose logging
        """
        self.project_path = Path(project_path)
        self.characteristic = characteristic
        self.logger = configure_logging(verbose)

        self.findings = []
        self.is_available = self._check_availability()

    def _check_availability(self) -> bool:
        """
        Check if this analyzer is available (tools installed, etc.)

        Returns:
            True if the analyzer is available, False otherwise
        """
        # Default implementation assumes it's available
        # Subclasses should override this to check for required tools
        return True

    @abstractmethod
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run the analysis.

        Returns:
            List of findings, each as a dictionary
        """
        pass

    def get_finding_count(self) -> int:
        """Get the total number of findings."""
        return len(self.findings)

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.get("severity") == severity]

    def get_findings_by_rule(self, rule_id: str) -> List[Dict[str, Any]]:
        """Get findings filtered by rule ID."""
        return [f for f in self.findings if f.get("rule_id") == rule_id]

    def get_findings_by_cwe(self, cwe_id: str) -> List[Dict[str, Any]]:
        """Get findings filtered by CWE ID."""
        return [f for f in self.findings if f.get("cwe_id") == cwe_id]

    def log_availability(self) -> None:
        """Log whether the analyzer is available."""
        if self.is_available:
            self.logger.info(f"{self.__class__.__name__} is available")
        else:
            self.logger.warning(
                f"{self.__class__.__name__} is not available. "
                "Some required tools may not be installed."
            )
