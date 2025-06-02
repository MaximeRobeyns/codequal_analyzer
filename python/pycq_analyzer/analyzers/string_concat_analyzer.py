"""String concatenation analyzer for performance issues."""
import ast
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .base_analyzer import BaseAnalyzer

# Python version compatibility
PY38_PLUS = sys.version_info >= (3, 8)

def is_string_constant(node):
    """Check if a node is a string constant, compatible across Python versions."""
    if node is None:
        return False
    
    # Python 3.8+ uses ast.Constant with string value
    if PY38_PLUS:
        return isinstance(node, ast.Constant) and isinstance(node.value, str)
    
    # Python 3.7 and earlier use ast.Str
    return hasattr(ast, 'Str') and isinstance(node, ast.Str)

class StringConcatVisitor(ast.NodeVisitor):
    """
    AST visitor to detect inefficient string concatenation patterns.
    
    This detects patterns where strings are concatenated in a loop
    using the + operator, which creates a new string object each time.
    """
    
    def __init__(self):
        """Initialize the visitor."""
        self.findings = []
        self.in_loop = False
        self.loop_depth = 0
        self.current_file = "unknown"
    
    def set_file(self, filename: str) -> None:
        """Set the current file being analyzed."""
        self.current_file = filename
    
    def visit_For(self, node):
        """Visit a for loop node."""
        old_in_loop = self.in_loop
        self.in_loop = True
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1
        self.in_loop = old_in_loop
    
    def visit_While(self, node):
        """Visit a while loop node."""
        old_in_loop = self.in_loop
        self.in_loop = True
        self.loop_depth += 1
        self.generic_visit(node)
        self.loop_depth -= 1
        self.in_loop = old_in_loop
    
    def visit_BinOp(self, node):
        """Visit a binary operation node."""
        # Check for string concatenation using + operator
        if self.in_loop and isinstance(node.op, ast.Add):
            # Check if both sides are strings or involve strings
            if (self._is_string_related(node.left) or self._is_string_related(node.right)):
                # Check if this is a string += string pattern
                if isinstance(node.left, ast.Name) and isinstance(node, ast.BinOp):
                    finding = {
                        'file': self.current_file,
                        'line': node.lineno,
                        'col': node.col_offset,
                        'message': "String concatenation in a loop using '+' operator can be inefficient",
                        'severity': 'medium',
                        'loop_depth': self.loop_depth
                    }
                    self.findings.append(finding)
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node):
        """Visit an augmented assignment node (e.g., x += y)."""
        # Check for string += ... pattern in loops
        if self.in_loop and isinstance(node.op, ast.Add):
            if hasattr(node, 'target') and self._is_string_related(node.target):
                finding = {
                    'file': self.current_file,
                    'line': node.lineno,
                    'col': node.col_offset,
                    'message': "String concatenation in a loop using '+=' operator can be inefficient",
                    'severity': 'medium' if self.loop_depth == 1 else 'high',
                    'loop_depth': self.loop_depth,
                    'operator': '+='
                }
                self.findings.append(finding)
            # Check if the value being added is a string
            elif hasattr(node, 'value') and self._is_string_related(node.value):
                finding = {
                    'file': self.current_file,
                    'line': node.lineno,
                    'col': node.col_offset,
                    'message': "String concatenation in a loop using '+=' operator can be inefficient",
                    'severity': 'medium' if self.loop_depth == 1 else 'high',
                    'loop_depth': self.loop_depth,
                    'operator': '+='
                }
                self.findings.append(finding)

        self.generic_visit(node)
    
    def _is_string_related(self, node):
        """Check if a node is likely to involve string operations."""
        # Handle None node
        if node is None:
            return False

        # Direct string literal
        if is_string_constant(node):
            return True
            
        # String conversion
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'str':
            return True
            
        # Check for common string methods
        if isinstance(node, ast.Attribute) and hasattr(node, 'value') and isinstance(node.value, ast.Name):
            if hasattr(node, 'attr') and node.attr in ['strip', 'join', 'format', 'replace', 'lower', 'upper', 'title']:
                return True

        # More complex cases involving f-strings, formatted strings, etc.
        # could be handled with more detailed analysis
        return False


class StringConcatenationAnalyzer(BaseAnalyzer):
    """Analyzer for inefficient string concatenation (CWE-1046)."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False
    ):
        """
        Initialize the string concatenation analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
        """
        super().__init__(project_path, 'performance', verbose)
    
    def _check_availability(self) -> bool:
        """Check if the analyzer is available."""
        # This analyzer uses Python's built-in ast module, so it's always available
        return True
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run string concatenation analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        self.logger.info("Running String Concatenation analysis for performance issues...")
        
        # Find all Python files in the project
        python_files = list(Path(self.project_path).glob("**/*.py"))
        
        # Analyze each file
        for file_path in python_files:
            self._analyze_file(file_path)
        
        self.logger.info(f"Found {len(self.findings)} string concatenation issues")
        return self.findings
    
    def _analyze_file(self, file_path: Path) -> None:
        """
        Analyze a single Python file.
        
        Args:
            file_path: Path to the file to analyze
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Parse the file into an AST
            tree = ast.parse(source_code, filename=str(file_path))
            
            # Visit the AST to find string concatenation issues
            visitor = StringConcatVisitor()
            visitor.set_file(str(file_path))
            visitor.visit(tree)
            
            # Convert visitor findings to analyzer findings
            for finding in visitor.findings:
                analyzer_finding = {
                    'analyzer': 'string_concatenation',
                    'characteristic': self.characteristic,
                    'rule_id': 'inefficient-string-concatenation',
                    'cwe_id': 'CWE-1046',  # Creation of Immutable Text Using String Concatenation
                    'severity': finding['severity'],
                    'file_path': finding['file'],
                    'line': finding['line'],
                    'message': finding['message'],
                    'raw_data': {
                        'col': finding['col'],
                        'loop_depth': finding['loop_depth'],
                        'operator': finding.get('operator', '+')
                    }
                }
                self.findings.append(analyzer_finding)
        
        except (SyntaxError, UnicodeDecodeError) as e:
            self.logger.warning(f"Error parsing {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")