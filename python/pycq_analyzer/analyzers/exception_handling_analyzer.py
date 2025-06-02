"""Exception handling analyzer for reliability issues."""
import ast
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set

from .base_analyzer import BaseAnalyzer

# Python version compatibility
PY38_PLUS = sys.version_info >= (3, 8)

def is_constant(node):
    """Check if a node is a constant, compatible across Python versions."""
    if PY38_PLUS:
        return isinstance(node, ast.Constant)
    else:
        # Check for old-style constants
        return isinstance(node, (ast.NameConstant, ast.Num, ast.Str, ast.Bytes, ast.Ellipsis))

def get_constant_value(node):
    """Extract the value from a constant node, compatible across Python versions."""
    if isinstance(node, ast.Constant):
        return node.value
    elif hasattr(node, 'value'):  # ast.NameConstant
        return node.value
    elif hasattr(node, 'n'):  # ast.Num
        return node.n
    elif hasattr(node, 's'):  # ast.Str
        return node.s
    elif hasattr(node, 'bytes'):  # ast.Bytes
        return node.bytes
    return None

class ExceptionHandlingVisitor(ast.NodeVisitor):
    """
    AST visitor to detect improper exception handling patterns.
    
    This looks for patterns like:
    - Bare except clauses
    - Catching too broad exceptions
    - Silencing exceptions (empty except blocks)
    - Missing finally blocks for resource cleanup
    - Re-raised exceptions losing context
    """
    
    def __init__(self):
        """Initialize the visitor."""
        self.findings = []
        self.current_file = "unknown"
        self.in_try_block = False
        self.has_finally = False
        self.resources_opened = []
        self.resources_closed = []
    
    def set_file(self, filename: str) -> None:
        """Set the current file being analyzed."""
        self.current_file = filename

    def visit_Try(self, node):
        """Visit a try block."""
        old_in_try = self.in_try_block
        old_has_finally = self.has_finally
        old_resources_opened = self.resources_opened.copy()
        old_resources_closed = self.resources_closed.copy()
        
        self.in_try_block = True
        self.has_finally = bool(node.finalbody)
        self.resources_opened = []
        self.resources_closed = []
        
        # First visit the try body to detect resource acquisitions
        for stmt in node.body:
            self.visit(stmt)
        
        # Check for bare except clauses or empty handlers
        has_bare_except = False
        has_empty_handler = False
        
        for handler in node.handlers:
            if handler.type is None:  # bare except:
                has_bare_except = True
                self._add_finding(
                    handler,
                    "Bare except clause catches all exceptions, including KeyboardInterrupt and SystemExit",
                    'high'
                )
            
            # Check for over-broad exception types (like 'Exception')
            elif isinstance(handler.type, ast.Name) and handler.type.id == "Exception":
                self._add_finding(
                    handler,
                    "Catching Exception is too broad, prefer catching specific exceptions",
                    'medium'
                )
            
            # Check for empty except blocks
            if len(handler.body) == 0 or (len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)):
                has_empty_handler = True
                self._add_finding(
                    handler,
                    "Empty except block silently ignores exceptions",
                    'high'
                )
        
        # Visit handlers after checking them
        for handler in node.handlers:
            self.visit(handler)
        
        # Visit orelse block
        for stmt in node.orelse:
            self.visit(stmt)
        
        # Check for missing finally when resources are opened
        if self.resources_opened and not self.has_finally:
            unclosed_resources = set(self.resources_opened) - set(self.resources_closed)
            if unclosed_resources:
                self._add_finding(
                    node,
                    f"Resources may not be properly closed without a finally block: {', '.join(unclosed_resources)}",
                    'medium'
                )
        
        # Visit finalbody
        for stmt in node.finalbody:
            self.visit(stmt)
        
        # Check if any exceptions can propagate without proper handling
        if not has_bare_except and len(node.handlers) == 0:
            self._add_finding(
                node,
                "No exception handlers defined, exceptions will propagate without being handled",
                'low'
            )
        
        # Restore state
        self.in_try_block = old_in_try
        self.has_finally = old_has_finally
        self.resources_opened = old_resources_opened
        self.resources_closed = old_resources_closed
    
    def visit_With(self, node):
        """Visit a with block (context manager)."""
        # Context managers are generally safe for resource management
        # but we should still check their contents
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Visit a function call node to track resource acquisition/release."""
        # Check for resource acquisition
        if self.in_try_block:
            if isinstance(node.func, ast.Name) and node.func.id == 'open':
                # Track file resources being opened
                if len(node.args) > 0:
                    self.resources_opened.append("file")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in ['connect', 'cursor', 'socket']:
                # Track database or network resources
                self.resources_opened.append(node.func.attr)
        
        # Check for resource closing in finally block
        if self.has_finally and isinstance(node.func, ast.Attribute):
            if node.func.attr in ['close', 'cleanup', 'release', '__exit__']:
                self.resources_closed.append("resource")
        
        self.generic_visit(node)
    
    def visit_Raise(self, node):
        """Visit a raise statement."""
        # Check for raising a new exception without context
        if self.in_try_block and node.exc is not None and node.cause is None:
            self._add_finding(
                node,
                "Raising a new exception inside except block loses original exception context",
                'medium'
            )
        self.generic_visit(node)
    
    def _add_finding(self, node, message, severity):
        """Add a finding to the results."""
        finding = {
            'file': self.current_file,
            'line': node.lineno if hasattr(node, 'lineno') else 0,
            'col': node.col_offset if hasattr(node, 'col_offset') else 0,
            'message': message,
            'severity': severity
        }
        self.findings.append(finding)


class ExceptionHandlingAnalyzer(BaseAnalyzer):
    """Analyzer for improper exception handling (CWE-703)."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False
    ):
        """
        Initialize the exception handling analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
        """
        super().__init__(project_path, 'reliability', verbose)
    
    def _check_availability(self) -> bool:
        """Check if the analyzer is available."""
        # This analyzer uses Python's built-in ast module, so it's always available
        return True
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run exception handling analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        self.logger.info("Running Exception Handling analysis for reliability issues...")
        
        # Find all Python files in the project
        python_files = list(Path(self.project_path).glob("**/*.py"))
        
        # Analyze each file
        for file_path in python_files:
            self._analyze_file(file_path)
        
        self.logger.info(f"Found {len(self.findings)} exception handling issues")
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
            
            # Visit the AST to find exception handling issues
            visitor = ExceptionHandlingVisitor()
            visitor.set_file(str(file_path))
            visitor.visit(tree)
            
            # Convert visitor findings to analyzer findings
            for finding in visitor.findings:
                analyzer_finding = {
                    'analyzer': 'exception_handling',
                    'characteristic': self.characteristic,
                    'rule_id': 'improper-exception-handling',
                    'cwe_id': 'CWE-703',  # Improper Check or Handling of Exceptional Conditions
                    'severity': finding['severity'],
                    'file_path': finding['file'],
                    'line': finding['line'],
                    'message': finding['message'],
                    'raw_data': {
                        'col': finding['col']
                    }
                }
                self.findings.append(analyzer_finding)
        
        except (SyntaxError, UnicodeDecodeError) as e:
            self.logger.warning(f"Error parsing {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")