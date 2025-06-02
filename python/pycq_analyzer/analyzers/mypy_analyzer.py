"""Mypy analyzer for type checking issues."""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

# Mapping of Mypy error codes to CWE IDs
MYPY_TO_CWE = {
    'assignment': 'CWE-704',          # Incorrect Type Conversion or Cast
    'attr-defined': 'CWE-456',        # Missing Initialization of Variable
    'arg-type': 'CWE-704',            # Incorrect Type Conversion or Cast
    'call-arg': 'CWE-628',            # Function Call with Incorrectly Specified Arguments
    'call-overload': 'CWE-628',       # Function Call with Incorrectly Specified Arguments  
    'dict-item': 'CWE-681',           # Incorrect Conversion between Numeric Types
    'index': 'CWE-125',               # Out-of-bounds Read
    'list-item': 'CWE-681',           # Incorrect Conversion between Numeric Types
    'misc': 'CWE-703',                # Improper Check or Handling of Exceptional Conditions
    'no-redef': 'CWE-675',            # Duplicate Operations on Resource
    'operator': 'CWE-480',            # Use of Incorrect Operator
    'override': 'CWE-695',            # Use of Low-Level Functionality
    'return-value': 'CWE-704',        # Incorrect Type Conversion or Cast
    'return': 'CWE-394',              # Unexpected Status Code or Return Value
    'syntax': 'CWE-703',              # Improper Check or Handling of Exceptional Conditions
    'type-arg': 'CWE-704',            # Incorrect Type Conversion or Cast
    'type-var': 'CWE-704',            # Incorrect Type Conversion or Cast
    'union-attr': 'CWE-456',          # Missing Initialization of Variable
    'union-return': 'CWE-704',        # Incorrect Type Conversion or Cast
    'valid-type': 'CWE-704',          # Incorrect Type Conversion or Cast
    'var-annotated': 'CWE-704',       # Incorrect Type Conversion or Cast
    'attr': 'CWE-456',                # Missing Initialization of Variable
    'name-defined': 'CWE-456',        # Missing Initialization of Variable
    'import': 'CWE-440',              # Expected Behavior Violation
    # Default for any other error codes
    'default': 'CWE-704'              # Incorrect Type Conversion or Cast
}

class MypyAnalyzer(BaseAnalyzer):
    """Analyzer for Mypy, detecting type checking issues."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False,
        config_file: Optional[Union[str, Path]] = None
    ):
        """
        Initialize the Mypy analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            config_file: Optional path to Mypy configuration file
        """
        super().__init__(project_path, 'reliability', verbose)
        self.config_file = config_file
    
    def _check_availability(self) -> bool:
        """Check if Mypy is installed."""
        return is_tool_installed('mypy')
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Mypy analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.is_available:
            self.logger.warning("Mypy is not installed. Skipping analysis.")
            return self.findings
        
        self.logger.info("Running Mypy analysis for type checking...")
        
        # Build command
        cmd = ["mypy", "--show-column-numbers"]
        
        if self.config_file:
            cmd.extend(["--config-file", str(self.config_file)])
        else:
            # Use some default options if no config file provided
            cmd.extend([
                "--ignore-missing-imports",  # Don't complain about missing stubs for imports
                "--disallow-untyped-defs",   # Disallow defining functions without type annotations
                "--disallow-incomplete-defs", # Disallow defining functions with incomplete type annotations
                "--check-untyped-defs",      # Check the bodies of functions with no type annotations
                "--disallow-untyped-calls",  # Disallow calling functions without type annotations
            ])
        
        # Add target
        cmd.append(str(self.project_path))
        
        # Run Mypy
        exit_code, stdout, stderr = run_command(cmd)
        
        # Mypy returns non-zero exit codes when it finds type errors,
        # so we can't use that to check for command failure
        if stderr and "error:" in stderr.lower() and not stdout:
            self.logger.error(f"Error running Mypy: {stderr}")
            return self.findings
        
        # Parse output
        findings = self._parse_mypy_output(stdout)
        self.findings.extend(findings)
        
        self.logger.info(f"Found {len(self.findings)} type checking issues with Mypy")
        return self.findings
    
    def _parse_mypy_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Mypy output and convert to findings.
        
        Args:
            output: Mypy output text
            
        Returns:
            List of findings
        """
        findings = []
        
        # Mypy outputs lines in the format:
        # file:line:column: error: message  [error_code]
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line.strip() or ': error:' not in line:
                continue
            
            # Parse the line
            try:
                # Extract file:line:column and message
                location, message = line.split(': error:', 1)
                message = message.strip()
                
                # Extract error code if present
                error_code = 'default'
                if '[' in message and ']' in message:
                    error_code_match = re.search(r'\[([a-zA-Z\-]+)\]', message)
                    if error_code_match:
                        error_code = error_code_match.group(1)
                
                # Extract file, line, column
                if ':' in location:
                    parts = location.split(':')
                    if len(parts) >= 2:
                        file_path = ':'.join(parts[:-1]) if len(parts) > 2 else parts[0]
                        line_no = int(parts[-1]) if len(parts) == 2 else int(parts[-2])
                        column = int(parts[-1]) if len(parts) > 2 else 0
                    else:
                        file_path = location
                        line_no = 0
                        column = 0
                else:
                    file_path = location
                    line_no = 0
                    column = 0
                
                # Map error code to CWE
                cwe_id = MYPY_TO_CWE.get(error_code, MYPY_TO_CWE['default'])
                
                # Determine severity (all type errors are considered medium by default)
                severity = "medium"
                
                # Create finding
                finding = {
                    'analyzer': 'mypy',
                    'characteristic': self.characteristic,
                    'rule_id': f'type-error-{error_code}',
                    'cwe_id': cwe_id,
                    'severity': severity,
                    'file_path': file_path,
                    'line': line_no,
                    'message': f"Type error: {message}",
                    'raw_data': {
                        'column': column,
                        'error_code': error_code
                    }
                }
                
                findings.append(finding)
                
            except Exception as e:
                self.logger.warning(f"Error parsing Mypy output line '{line}': {e}")
                continue
        
        return findings