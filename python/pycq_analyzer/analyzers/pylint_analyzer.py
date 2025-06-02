"""Pylint analyzer for maintainability issues."""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

# Mapping of Pylint message IDs to CWE IDs
PYLINT_TO_CWE = {
    'unused-import': 'CWE-561',  # Dead code
    'unused-variable': 'CWE-561',  # Dead code
    'unused-argument': 'CWE-561',  # Dead code
    'duplicate-code': 'CWE-1041',  # Copy-paste code
    'too-many-arguments': 'CWE-1064',  # Excessive parameters
    'too-many-instance-attributes': 'CWE-1074',  # Class with too many attributes
    'too-many-locals': 'CWE-1121',  # Excessive complexity
    'too-many-statements': 'CWE-1121',  # Excessive complexity
    'too-many-branches': 'CWE-1121',  # Excessive McCabe complexity
    'too-many-return-statements': 'CWE-1121',  # Excessive complexity
    'too-many-public-methods': 'CWE-1086',  # Class with excessive methods
    'too-few-public-methods': None,  # No corresponding CWE
    'missing-docstring': None,  # No corresponding CWE
    'bad-indentation': None,  # No corresponding CWE
    'line-too-long': None,  # No corresponding CWE
    'invalid-name': None,  # No corresponding CWE
    'wildcard-import': None,  # No corresponding CWE
    'wrong-import-order': None,  # No corresponding CWE
}

# Severity mapping
PYLINT_SEVERITY_MAP = {
    'C': 'low',       # Convention
    'R': 'low',       # Refactor
    'W': 'medium',    # Warning
    'E': 'high',      # Error
    'F': 'critical',  # Fatal
}

class PylintAnalyzer(BaseAnalyzer):
    """Analyzer for Pylint."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False,
        rcfile: Optional[Union[str, Path]] = None
    ):
        """
        Initialize the Pylint analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            rcfile: Optional path to Pylint configuration file
        """
        super().__init__(project_path, 'maintainability', verbose)
        self.rcfile = rcfile
    
    def _check_availability(self) -> bool:
        """Check if Pylint is installed."""
        return is_tool_installed('pylint')
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Pylint analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.is_available:
            self.logger.warning("Pylint is not installed. Skipping analysis.")
            return self.findings
        
        self.logger.info("Running Pylint analysis...")
        
        # Build command
        cmd = ["pylint", "--output-format=json"]
        
        if self.rcfile:
            cmd.append(f"--rcfile={self.rcfile}")
        
        cmd.append(str(self.project_path))
        
        # Run Pylint
        exit_code, stdout, stderr = run_command(cmd)
        
        # Non-zero exit code is expected from Pylint when it finds issues
        if exit_code < 0:
            self.logger.error(f"Error running Pylint: {stderr}")
            return self.findings
        
        # Parse JSON output
        try:
            if stdout.strip():
                pylint_issues = json.loads(stdout)
                self._process_pylint_findings(pylint_issues)
        except json.JSONDecodeError:
            self.logger.error(f"Error parsing Pylint output: {stdout}")
        
        self.logger.info(f"Found {len(self.findings)} issues with Pylint")
        return self.findings
    
    def _process_pylint_findings(self, issues: List[Dict[str, Any]]) -> None:
        """
        Process Pylint findings and map to CWE IDs.
        
        Args:
            issues: List of Pylint issues
        """
        for issue in issues:
            # Extract message ID (e.g., 'unused-import')
            message_id = issue.get('symbol')
            
            # Skip issues without a corresponding CWE
            if message_id not in PYLINT_TO_CWE or PYLINT_TO_CWE[message_id] is None:
                continue
            
            cwe_id = PYLINT_TO_CWE[message_id]
            
            # Get severity level
            severity_code = issue.get('type', 'W')[0].upper()  # Get first letter of type
            severity = PYLINT_SEVERITY_MAP.get(severity_code, 'medium')
            
            # Create finding
            finding = {
                'analyzer': 'pylint',
                'characteristic': self.characteristic,
                'rule_id': message_id,
                'cwe_id': cwe_id,
                'severity': severity,
                'file_path': issue.get('path'),
                'line': issue.get('line', 0),
                'message': issue.get('message', ''),
                'raw_data': issue
            }
            
            self.findings.append(finding)