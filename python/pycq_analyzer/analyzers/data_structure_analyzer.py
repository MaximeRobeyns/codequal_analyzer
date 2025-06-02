"""Data structure complexity analyzer for performance issues."""
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

class DataStructureVisitor(ast.NodeVisitor):
    """
    AST visitor to detect excessively complex data structures.
    
    This looks for patterns like:
    - Classes with many attributes
    - Deeply nested data structures
    - Complex object hierarchies
    """
    
    def __init__(self, max_attributes=10, max_nesting=5):
        """
        Initialize the visitor.
        
        Args:
            max_attributes: Maximum number of attributes allowed in a class
            max_nesting: Maximum nesting level allowed for data structures
        """
        self.findings = []
        self.current_file = "unknown"
        self.max_attributes = max_attributes
        self.max_nesting = max_nesting
        self.nesting_level = 0
    
    def set_file(self, filename: str) -> None:
        """Set the current file being analyzed."""
        self.current_file = filename
    
    def visit_ClassDef(self, node):
        """Visit a class definition node."""
        # Count class attributes
        attributes = self._count_class_attributes(node)
        
        if attributes > self.max_attributes:
            self._add_finding(
                node,
                f"Class '{node.name}' has {attributes} attributes, which exceeds the recommended maximum of {self.max_attributes}",
                'medium'
            )
        
        # Continue visiting children
        self.generic_visit(node)
    
    def _count_class_attributes(self, node):
        """Count the number of attributes in a class."""
        attributes = 0
        
        for item in node.body:
            # Count assignments to self.attr in __init__
            if isinstance(item, ast.FunctionDef) and item.name == '__init__':
                for stmt in item.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Attribute) and \
                               isinstance(target.value, ast.Name) and \
                               target.value.id == 'self':
                                attributes += 1
            
            # Count class variables defined directly
            elif isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        attributes += 1
        
        return attributes
    
    def visit_Dict(self, node):
        """Visit a dictionary literal node."""
        old_level = self.nesting_level
        self.nesting_level += 1
        
        # Check if this dictionary has nested complex structures
        if self.nesting_level > self.max_nesting:
            self._add_finding(
                node,
                f"Dictionary with excessive nesting level ({self.nesting_level} > {self.max_nesting})",
                'medium'
            )
        
        # Check for dictionaries with many key-value pairs
        if hasattr(node, 'keys') and len(node.keys) > self.max_attributes:
            self._add_finding(
                node,
                f"Dictionary with {len(node.keys)} key-value pairs exceeds recommended maximum of {self.max_attributes}",
                'low'
            )
            
            # Also check for constant keys in large dictionaries
            constant_keys = 0
            for key in node.keys:
                if is_constant(key):
                    constant_keys += 1
            
            if constant_keys > self.max_attributes:
                self._add_finding(
                    node,
                    f"Dictionary with {constant_keys} literal keys may be better represented as a named constant or enum",
                    'medium'
                )
        
        # Continue visiting children
        self.generic_visit(node)
        self.nesting_level = old_level
    
    def visit_List(self, node):
        """Visit a list literal node."""
        old_level = self.nesting_level
        self.nesting_level += 1
        
        # Check if this list has a lot of elements
        if hasattr(node, 'elts') and len(node.elts) > self.max_attributes*2:
            self._add_finding(
                node,
                f"List with {len(node.elts)} elements may be excessively large",
                'low'
            )
        
        # Check for excessive nesting
        if self.nesting_level > self.max_nesting:
            self._add_finding(
                node,
                f"List with excessive nesting level ({self.nesting_level} > {self.max_nesting})",
                'medium'
            )
        
        # Continue visiting children
        self.generic_visit(node)
        self.nesting_level = old_level
    
    def visit_Call(self, node):
        """Visit a function call node."""
        # Check for creation of complex objects
        if isinstance(node.func, ast.Name) and node.func.id[0].isupper():
            # This is likely a class constructor call
            if len(node.args) > self.max_attributes or len(node.keywords) > self.max_attributes:
                self._add_finding(
                    node,
                    f"Object creation with {len(node.args) + len(node.keywords)} arguments may be excessively complex",
                    'medium'
                )
        
        # Continue visiting children
        self.generic_visit(node)
    
    def _add_finding(self, node, message, severity):
        """Add a finding to the results."""
        finding = {
            'file': self.current_file,
            'line': node.lineno if hasattr(node, 'lineno') else 0,
            'col': node.col_offset if hasattr(node, 'col_offset') else 0,
            'message': message,
            'severity': severity,
            'nesting_level': self.nesting_level
        }
        self.findings.append(finding)


class DataStructureComplexityAnalyzer(BaseAnalyzer):
    """Analyzer for excessively complex data structures (CWE-1043)."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False,
        max_attributes: int = 10,
        max_nesting: int = 5
    ):
        """
        Initialize the data structure complexity analyzer.
        
        Args:
            project_path: Path to the project to analyze
            verbose: Whether to enable verbose logging
            max_attributes: Maximum number of attributes allowed in a class
            max_nesting: Maximum nesting level allowed for data structures
        """
        super().__init__(project_path, 'performance', verbose)
        self.max_attributes = max_attributes
        self.max_nesting = max_nesting
    
    def _check_availability(self) -> bool:
        """Check if the analyzer is available."""
        # This analyzer uses Python's built-in ast module, so it's always available
        return True
    
    def analyze(self) -> List[Dict[str, Any]]:
        """
        Run data structure complexity analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        self.logger.info("Running Data Structure Complexity analysis for performance issues...")
        
        # Find all Python files in the project
        python_files = list(Path(self.project_path).glob("**/*.py"))
        
        # Analyze each file
        for file_path in python_files:
            self._analyze_file(file_path)
        
        self.logger.info(f"Found {len(self.findings)} data structure complexity issues")
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
            
            # Visit the AST to find data structure complexity issues
            visitor = DataStructureVisitor(self.max_attributes, self.max_nesting)
            visitor.set_file(str(file_path))
            visitor.visit(tree)
            
            # Convert visitor findings to analyzer findings
            for finding in visitor.findings:
                analyzer_finding = {
                    'analyzer': 'data_structure_complexity',
                    'characteristic': self.characteristic,
                    'rule_id': 'excessive-data-structure-complexity',
                    'cwe_id': 'CWE-1043',  # Data Element Aggregating an Excessively Large Number of Non-Primitive Elements
                    'severity': finding['severity'],
                    'file_path': finding['file'],
                    'line': finding['line'],
                    'message': finding['message'],
                    'raw_data': {
                        'col': finding['col'],
                        'nesting_level': finding['nesting_level']
                    }
                }
                self.findings.append(analyzer_finding)
        
        except (SyntaxError, UnicodeDecodeError) as e:
            self.logger.warning(f"Error parsing {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")