"""Resource consumption analyzer for performance issues."""
import ast
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

class ResourceConsumptionVisitor(ast.NodeVisitor):
    """
    AST visitor to detect excessive resource consumption in loops.
    
    This looks for patterns like:
    - Growing data structures in loops
    - Blocking operations in loops
    - Network or file I/O in loops
    - Creating large objects in loops
    """
    
    def __init__(self):
        """Initialize the visitor."""
        self.findings = []
        self.in_loop = False
        self.loop_depth = 0
        self.current_file = "unknown"
        
        # Resource-intensive operations to look for
        self.resource_intensive_calls = {
            # File operations
            'open', 'read', 'write', 'readline', 'readlines', 
            # Network operations
            'connect', 'request', 'urlopen', 'get', 'post', 
            # Time/blocking operations
            'sleep', 'wait',
            # Database operations
            'execute', 'cursor', 'commit',
            # Process/system operations
            'subprocess', 'system', 'Popen', 'call'
        }
        
        # Libraries associated with resource-intensive operations
        self.resource_intensive_imports = {
            'time', 'socket', 'requests', 'urllib', 'http',
            'subprocess', 'multiprocessing', 'threading',
            'sqlite3', 'psycopg2', 'pymysql', 'sqlalchemy',
            'os', 'sys', 'io', 'aiohttp', 'asyncio'
        }
        
        # Track imports to identify resource-intensive modules
        self.imported_modules = set()
    
    def set_file(self, filename: str) -> None:
        """Set the current file being analyzed."""
        self.current_file = filename
    
    def visit_Import(self, node):
        """Visit an import statement."""
        for name in node.names:
            module_name = name.name.split('.')[0]  # Get top-level module
            self.imported_modules.add(module_name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Visit an import from statement."""
        if node.module:
            module_name = node.module.split('.')[0]  # Get top-level module
            self.imported_modules.add(module_name)
        self.generic_visit(node)
    
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
    
    def visit_Call(self, node):
        """Visit a function call node."""
        if not self.in_loop:
            self.generic_visit(node)
            return
        
        # Check for direct resource-intensive function calls
        if isinstance(node.func, ast.Name) and node.func.id in self.resource_intensive_calls:
            self._add_finding(
                node,
                f"Resource-intensive function '{node.func.id}' called within a loop",
                'high' if self.loop_depth > 1 else 'medium'
            )
        
        # Check for attribute calls that might be resource-intensive
        elif isinstance(node.func, ast.Attribute) and node.func.attr in self.resource_intensive_calls:
            # Check if the base object is from a resource-intensive module
            if isinstance(node.func.value, ast.Name):
                base_name = node.func.value.id
                if any(base_name.startswith(mod) for mod in self.imported_modules & self.resource_intensive_imports):
                    self._add_finding(
                        node,
                        f"Resource-intensive method '{node.func.attr}' called within a loop",
                        'high' if self.loop_depth > 1 else 'medium'
                    )
        
        # Check for object creation that might consume resources
        elif isinstance(node.func, ast.Name) and node.func.id[0].isupper():  # Likely a class constructor
            # Large object creation within a loop could be resource-intensive
            if len(node.args) > 2 or len(node.keywords) > 2:
                self._add_finding(
                    node,
                    f"Complex object '{node.func.id}' created within a loop",
                    'medium'
                )
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """Visit an assignment node."""
        if not self.in_loop:
            self.generic_visit(node)
            return
        
        # Check for growing data structures in loops
        if isinstance(node.value, ast.BinOp):
            # Look for patterns like result = result + something
            if isinstance(node.value.op, ast.Add) and isinstance(node.value.left, ast.Name):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == node.value.left.id:
                        self._add_finding(
                            node,
                            "Growing data structure within a loop",
                            'medium'
                        )
                        break
        
        # Check for list/dictionary/set comprehensions within loops
        elif isinstance(node.value, (ast.ListComp, ast.DictComp, ast.SetComp)):
            self._add_finding(
                node,
                f"Comprehension within a loop may lead to excessive memory consumption",
                'low'
            )
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node):
        """Visit an augmented assignment (e.g., x += y)."""
        if not self.in_loop:
            self.generic_visit(node)
            return
        
        # Growing a list or other data structure in a loop using +=
        if isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name):
            self._add_finding(
                node,
                f"Growing data structure '{node.target.id}' within a loop using '+='",
                'medium'
            )
        
        self.generic_visit(node)
    
    def _add_finding(self, node, message, severity):
        """Add a finding to the results."""
        finding = {
            'file': self.current_file,
            'line': node.lineno,
            'col': node.col_offset if hasattr(node, 'col_offset') else 0,
            'message': message,
            'severity': severity,
            'loop_depth': self.loop_depth
        }
        self.findings.append(finding)


class ResourceConsumptionAnalyzer(BaseAnalyzer):
    """Analyzer for excessive resource consumption (CWE-1050)."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False
    ):
        """
        Initialize the resource consumption analyzer.
        
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
        Run resource consumption analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        self.logger.info("Running Resource Consumption analysis for performance issues...")
        
        # Find all Python files in the project
        python_files = list(Path(self.project_path).glob("**/*.py"))
        
        # Analyze each file
        for file_path in python_files:
            self._analyze_file(file_path)
        
        self.logger.info(f"Found {len(self.findings)} resource consumption issues")
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
            
            # Visit the AST to find resource consumption issues
            visitor = ResourceConsumptionVisitor()
            visitor.set_file(str(file_path))
            visitor.visit(tree)
            
            # Convert visitor findings to analyzer findings
            for finding in visitor.findings:
                analyzer_finding = {
                    'analyzer': 'resource_consumption',
                    'characteristic': self.characteristic,
                    'rule_id': 'excessive-resource-consumption',
                    'cwe_id': 'CWE-1050',  # Excessive Platform Resource Consumption within a Loop
                    'severity': finding['severity'],
                    'file_path': finding['file'],
                    'line': finding['line'],
                    'message': finding['message'],
                    'raw_data': {
                        'col': finding['col'],
                        'loop_depth': finding['loop_depth']
                    }
                }
                self.findings.append(analyzer_finding)
        
        except (SyntaxError, UnicodeDecodeError) as e:
            self.logger.warning(f"Error parsing {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {e}")