"""Safety analyzer for security vulnerabilities in dependencies."""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer
from ..utils import run_command, is_tool_installed

class SafetyAnalyzer(BaseAnalyzer):
    """Analyzer for Safety, detecting security vulnerabilities in dependencies."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False,
        requirements_file: Optional[str] = None
    ):
        """
        Initialize the Safety analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            requirements_file: Optional path to requirements file (relative to project_path)
        """
        super().__init__(project_path, 'security', verbose)
        self.requirements_file = requirements_file
    
    def _check_availability(self) -> bool:
        """Check if Safety is installed."""
        return is_tool_installed('safety')
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run Safety analysis on dependencies.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        if not self.is_available:
            self.logger.warning("Safety is not installed. Skipping analysis.")
            return self.findings
        
        self.logger.info("Running Safety analysis for vulnerable dependencies...")
        
        # Find requirements files if not specified
        requirements_files = self._find_requirements_files() if not self.requirements_file else [self.requirements_file]
        
        if not requirements_files:
            self.logger.warning("No requirements files found. Skipping Safety analysis.")
            return self.findings
        
        # Analyze each requirements file
        for req_file in requirements_files:
            self._analyze_requirements(req_file)
        
        self.logger.info(f"Found {len(self.findings)} vulnerable dependencies with Safety")
        return self.findings
    
    def _find_requirements_files(self) -> List[str]:
        """Find requirements files in the project."""
        req_patterns = [
            "*requirements*.txt",
            "requirements/*.txt",
            "setup.py"
        ]
        
        found_files = []
        for pattern in req_patterns:
            cmd = ["find", str(self.project_path), "-name", pattern]
            exit_code, stdout, stderr = run_command(cmd)
            
            if exit_code == 0 and stdout.strip():
                found_files.extend(stdout.strip().split("\n"))
        
        return found_files
    
    def _analyze_requirements(self, req_file: str) -> None:
        """
        Analyze a single requirements file.

        Args:
            req_file: Path to requirements file
        """
        # Build command
        cmd = ["safety", "check", "--json", "-r", req_file]

        # Run Safety
        exit_code, stdout, stderr = run_command(cmd)

        # Safety returns non-zero exit code when it finds vulnerabilities, so we can't check for errors that way
        if stderr and "error" in stderr.lower():
            self.logger.error(f"Error running Safety on {req_file}: {stderr}")
            return

        # Check if output contains JSON data
        json_data = self._extract_json_from_output(stdout)
        if json_data:
            self._process_json_data(json_data, req_file)
    
    def _extract_json_from_output(self, output: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON data from Safety output which may contain banners and other text.

        Args:
            output: Safety command output

        Returns:
            Parsed JSON data or None if parsing failed
        """
        # Try to find JSON data between banners
        json_pattern = r'({[\s\S]*})'
        json_matches = re.findall(json_pattern, output)

        for json_str in json_matches:
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                continue

        return None

    def _process_json_data(self, data: Dict[str, Any], req_file: str) -> None:
        """
        Process JSON data from Safety output.

        Args:
            data: Parsed JSON data from Safety output
            req_file: Path to requirements file
        """
        # Check if this is the new Safety format with affected_packages
        if "affected_packages" in data:
            self._process_new_format(data, req_file)
        # Else, check if it's directly a list of vulnerabilities (old format)
        elif isinstance(data, list):
            self._process_old_format(data, req_file)
        # Lastly, check if it's the old format but wrapped in a dict
        elif "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            self._process_old_format(data["vulnerabilities"], req_file)

    def _process_new_format(self, data: Dict[str, Any], req_file: str) -> None:
        """
        Process Safety output in the new format (3.x).

        Args:
            data: Safety output data
            req_file: Path to requirements file
        """
        # Get vulnerabilities directly from affected_packages section
        for package_name, package_info in data.get("affected_packages", {}).items():
            # The package version
            version = package_info.get("version", "unknown")

            # For each vulnerability
            for vuln_id, vuln_info in data.get("vulnerabilities", {}).items():
                # Skip if this vulnerability doesn't apply to this package
                if vuln_info.get("package_name") != package_name:
                    continue

                # Extract information
                vulnerability_id = vuln_info.get("vulnerability_id", vuln_id)
                description = vuln_info.get("advisory", "No description available")
                vulnerable_spec = vuln_info.get("vulnerable_spec", [])
                if isinstance(vulnerable_spec, list):
                    vulnerable_spec = ", ".join(vulnerable_spec)

                # Create finding
                finding = {
                    'analyzer': 'safety',
                    'characteristic': self.characteristic,
                    'rule_id': f"vulnerable-dependency-{vulnerability_id}",
                    'cwe_id': "CWE-1104",  # Use of Unmaintained Third Party Components
                    'severity': "medium",   # Default
                    'file_path': req_file,
                    'line': 0,  # Safety doesn't provide line numbers
                    'message': f"Security vulnerability found in {package_name} {version}: {description}",
                    'raw_data': vuln_info
                }

                self.findings.append(finding)

    def _process_old_format(self, vulnerabilities: List[Dict[str, Any]], req_file: str) -> None:
        """
        Process Safety output in the old format.

        Args:
            vulnerabilities: List of vulnerability data
            req_file: Path to requirements file
        """
        for vuln in vulnerabilities:
            # Extract data
            package_name = vuln.get("package_name", "unknown")
            affected_version = vuln.get("vulnerable_spec", "")
            vulnerability_id = vuln.get("vulnerability_id", "")
            description = vuln.get("advisory", "No description available")

            # Determine severity based on CVSS score if available
            cvss_score = vuln.get("cvss_score")
            severity = self._severity_from_cvss(cvss_score)

            # Create finding
            finding = {
                'analyzer': 'safety',
                'characteristic': self.characteristic,
                'rule_id': f"vulnerable-dependency-{vulnerability_id}",
                'cwe_id': "CWE-1104",  # Use of Unmaintained Third Party Components
                'severity': severity,
                'file_path': req_file,
                'line': 0,  # Safety doesn't provide line numbers
                'message': f"Security vulnerability found in {package_name} {affected_version}: {description}",
                'raw_data': vuln
            }

            self.findings.append(finding)
    
    def _severity_from_cvss(self, cvss_score: Optional[float]) -> str:
        """
        Determine severity level from CVSS score.
        
        Args:
            cvss_score: CVSS score, if available
            
        Returns:
            Severity level (low, medium, high, critical)
        """
        if cvss_score is None:
            return "medium"  # Default if score not available
            
        if cvss_score < 4.0:
            return "low"
        elif cvss_score < 7.0:
            return "medium"
        elif cvss_score < 9.0:
            return "high"
        else:
            return "critical"