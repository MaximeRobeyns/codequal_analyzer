"""Bandit analyzer for security issues."""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

# Mapping of Bandit test IDs to CWE IDs
BANDIT_TO_CWE = {
    'B101': 'CWE-703',  # Use of assert
    'B102': 'CWE-676',  # Use of exec
    'B103': 'CWE-78',   # Use of command shell in conjunction with a function with potentially dangerous input
    'B104': 'CWE-78',   # Use of eval
    'B105': 'CWE-798',  # Use of hard-coded password
    'B106': 'CWE-798',  # Use of hard-coded password with empty string
    'B107': 'CWE-327',  # Use of hard-coded password function argument
    'B108': 'CWE-916',  # Use of insecure cipher mode
    'B110': 'CWE-327',  # Use of insecure cipher mode of operation
    'B112': 'CWE-400',  # Slow operation that could lead to DoS
    'B201': 'CWE-78',   # Flask app without proper CSRF protection
    'B301': 'CWE-506',  # Use of pickle
    'B303': 'CWE-327',  # Use of insecure MD2/MD4/MD5
    'B304': 'CWE-327',  # Use of insecure cipher
    'B305': 'CWE-327',  # Use of insecure hash functions
    'B306': 'CWE-327',  # Use of insecure PRNG
    'B307': 'CWE-327',  # Use of insufficiently random values
    'B308': 'CWE-347',  # Use of weak hash functions
    'B309': 'CWE-377',  # Use of unsafe yaml.load
    'B310': 'CWE-22',   # Path injection
    'B311': 'CWE-330',  # Use of random module is not suitable for security/cryptographic purposes
    'B312': 'CWE-330',  # Use of telnetlib is not secure
    'B313': 'CWE-330',  # Use of insecure xml libraries 
    'B314': 'CWE-327',  # Use of insecure ciphers
    'B315': 'CWE-327',  # Use of insecure HMAC settings
    'B316': 'CWE-502',  # Deserialization with YAML
    'B317': 'CWE-94',   # Use of insecure templating 
    'B318': 'CWE-20',   # Use of insecure XML library
    'B319': 'CWE-78',   # Use of insecure Python functions
    'B320': 'CWE-312',  # Hard-coded credentials
    'B321': 'CWE-605',  # Use of insecure FTP
    'B322': 'CWE-676',  # Use of insecure input()
    'B323': 'CWE-676',  # Insecure use of unverified data
    'B324': 'CWE-798',  # Use of constant in hashlib
    'B501': 'CWE-22',   # Request without cert verification
    'B502': 'CWE-377',  # Use of unsafe eval
    'B503': 'CWE-259',  # Use of insecure SSL/TLS settings
    'B504': 'CWE-338',  # Use of insecure SSL/TLS version
    'B505': 'CWE-327',  # Use of weak cryptographic key
    'B506': 'CWE-79',   # Use of unsafe YAML load
    'B507': 'CWE-20',   # Host header attacks
    'B601': 'CWE-78',   # Possible shell injection
    'B602': 'CWE-78',   # os.popen with shell=True
    'B603': 'CWE-78',   # subprocess with shell=True
    'B604': 'CWE-78',   # Any function with shell=True using untrusted input
    'B605': 'CWE-78',   # Start process with shell=True
    'B606': 'CWE-95',   # Start process with function args
    'B607': 'CWE-88',   # Start process with partial path
    'B608': 'CWE-377',  # tempfile insecure use
    'B609': 'CWE-20',   # Wildcard injection
    'B610': 'CWE-20',   # SQL injection
    'B611': 'CWE-22',   # Path injection
    'B701': 'CWE-120',  # Ignore jinja2 autoescape
    'B702': 'CWE-287',  # Use of mako templates
    'B703': 'CWE-94',   # Django mark_safe use
}

# Severity mapping
BANDIT_SEVERITY_MAP = {
    'LOW': 'low',
    'MEDIUM': 'medium',
    'HIGH': 'high',
}

class BanditAnalyzer(BaseAnalyzer):
    """Analyzer for Bandit."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False,
        config_file: Optional[Union[str, Path]] = None
    ):
        """
        Initialize the Bandit analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose output
            config_file: Optional path to Bandit configuration file
        """
        super().__init__(project_path, 'security', verbose)
        self.config_file = config_file
    
    def _check_availability(self) -> bool:
        """Check if Bandit is installed."""
        return is_tool_installed('bandit')
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Bandit analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.is_available:
            self.logger.warning("Bandit is not installed. Skipping analysis.")
            return self.findings
        
        self.logger.info("Running Bandit analysis...")
        
        # Build command
        cmd = ["bandit", "-f", "json", "-r"]
        
        if self.config_file:
            cmd.extend(["-c", str(self.config_file)])
        
        cmd.append(str(self.project_path))
        
        # Run Bandit
        exit_code, stdout, stderr = run_command(cmd)
        
        # Bandit returns 1 when issues are found, so we can't check for non-zero exit code
        if exit_code < 0:
            self.logger.error(f"Error running Bandit: {stderr}")
            return self.findings
        
        # Parse JSON output
        try:
            if stdout.strip():
                bandit_results = json.loads(stdout)
                self._process_bandit_findings(bandit_results)
        except json.JSONDecodeError:
            self.logger.error(f"Error parsing Bandit output: {stdout}")
        
        self.logger.info(f"Found {len(self.findings)} issues with Bandit")
        return self.findings
    
    def _process_bandit_findings(self, results: Dict[str, Any]) -> None:
        """
        Process Bandit findings and map to CWE IDs.
        
        Args:
            results: Bandit results dictionary
        """
        if 'results' not in results:
            self.logger.warning("No results found in Bandit output")
            return
        
        for issue in results['results']:
            # Extract test ID (e.g., 'B101')
            test_id = issue.get('test_id')
            
            # Skip issues without a corresponding CWE
            if test_id not in BANDIT_TO_CWE:
                continue
            
            cwe_id = BANDIT_TO_CWE[test_id]
            
            # Get severity level
            severity = issue.get('issue_severity', 'MEDIUM')
            severity = BANDIT_SEVERITY_MAP.get(severity, 'medium')
            
            # Create finding
            finding = {
                'analyzer': 'bandit',
                'characteristic': self.characteristic,
                'rule_id': test_id,
                'cwe_id': cwe_id,
                'severity': severity,
                'file_path': issue.get('filename'),
                'line': issue.get('line_number', 0),
                'message': issue.get('issue_text', ''),
                'raw_data': issue
            }
            
            self.findings.append(finding)