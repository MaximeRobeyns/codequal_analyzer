"""Vulture analyzer for dead code detection."""
import json
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

class VultureAnalyzer(BaseAnalyzer):
    """Analyzer for Vulture, detecting unused code."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False,
        min_confidence: int = 60
    ):
        """
        Initialize the Vulture analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            min_confidence: Minimum confidence threshold for reporting unused code (0-100)
        """
        super().__init__(project_path, 'maintainability', verbose)
        self.min_confidence = min_confidence
    
    def _check_availability(self) -> bool:
        """Check if Vulture is installed."""
        return is_tool_installed('vulture')
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Vulture analysis for dead code.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.is_available:
            self.logger.warning("Vulture is not installed. Skipping analysis.")
            return self.findings
        
        self.logger.info("Running Vulture analysis for dead code detection...")
        
        # Build command to run Vulture
        cmd = [
            "vulture",
            str(self.project_path),
            "--min-confidence", str(self.min_confidence)
        ]

        # Run Vulture and capture its output
        exit_code, stdout, stderr = run_command(cmd)

        # Check for errors
        if exit_code != 0 and not stdout:  # Vulture may return non-zero if it finds issues
            self.logger.error(f"Error running Vulture: {stderr}")
            return self.findings

        # Parse the output
        findings = self._parse_vulture_output(stdout)
        self.findings.extend(findings)
        
        self.logger.info(f"Found {len(self.findings)} unused code issues with Vulture")
        return self.findings
    
    def _parse_vulture_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Vulture output and convert to findings.

        Args:
            output: Vulture output text

        Returns:
            List of findings
        """
        findings = []

        # Vulture outputs lines in the format:
        # path/to/file.py:line: unused function 'name' (confidence: confidence%)
        lines = output.strip().split('\n')

        for line in lines:
            if not line.strip():
                continue

            # Parse the line
            try:
                # Split file path and message
                parts = line.split(': ', 1)
                if len(parts) < 2:
                    continue

                file_line, message = parts

                # Extract file path and line number
                if ':' in file_line:
                    file_path, line_no_str = file_line.rsplit(':', 1)
                    try:
                        line_no = int(line_no_str)
                    except ValueError:
                        line_no = 0
                else:
                    file_path = file_line
                    line_no = 0

                # Parse unused item type (function, variable, etc.)
                item_type = "unknown"
                if "unused function" in message:
                    item_type = "function"
                elif "unused variable" in message:
                    item_type = "variable"
                elif "unused class" in message:
                    item_type = "class"
                elif "unused method" in message:
                    item_type = "method"
                elif "unused property" in message:
                    item_type = "property"
                elif "unused attribute" in message:
                    item_type = "attribute"
                elif "unused import" in message:
                    item_type = "import"

                # Extract confidence
                confidence = 100  # Default
                if "(confidence: " in message and "%)" in message:
                    confidence_str = message.split("(confidence: ", 1)[1].split("%)", 1)[0]
                    try:
                        confidence = int(confidence_str)
                    except ValueError:
                        pass

                # Extract name
                name = "unknown"
                if "'" in message:
                    name_parts = message.split("'")
                    if len(name_parts) >= 2:
                        name = name_parts[1]

                # Dead code maps to CWE-561 (Dead Code)
                finding = {
                    'analyzer': 'vulture',
                    'characteristic': self.characteristic,
                    'rule_id': f'unused-{item_type}',
                    'cwe_id': 'CWE-561',  # Dead Code
                    'severity': self._severity_from_confidence(confidence),
                    'file_path': file_path,
                    'line': line_no,
                    'message': f"Unused {item_type} '{name}' (confidence: {confidence}%)",
                    'raw_data': {
                        'item_type': item_type,
                        'name': name,
                        'confidence': confidence
                    }
                }

                findings.append(finding)
            except Exception as e:
                self.logger.warning(f"Error parsing Vulture output line '{line}': {e}")
                continue

        return findings
    
    def _severity_from_confidence(self, confidence: int) -> str:
        """
        Determine severity level from Vulture confidence level.
        
        Args:
            confidence: Vulture confidence level (0-100)
            
        Returns:
            Severity level (low, medium, high)
        """
        if confidence < 60:
            return "low"
        elif confidence < 90:
            return "medium"
        else:
            return "high"