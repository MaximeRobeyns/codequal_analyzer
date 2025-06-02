"""Deadlock detection analyzer for reliability issues."""
import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set, Tuple

from .base_analyzer import BaseAnalyzer

# Add imports and version check at the top after existing imports
import sys

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

class LockTracker:
    """Utility class to track lock acquisitions and potential deadlocks."""
    
    def __init__(self):
        """Initialize the lock tracker."""
        # Maps class names to methods and their lock sequences
        # class_name -> {method_name -> [(lock_name, position)]}
        self.class_lock_sequences = {}
        
        # Set of potential deadlock patterns
        self.potential_deadlocks = []
    
    def add_lock_acquisition(self, class_name: str, method_name: str, lock_name: str, position: int):
        """
        Add a lock acquisition to the tracker.
        
        Args:
            class_name: Name of the class containing the method
            method_name: Name of the method
            lock_name: Name of the lock variable
            position: Order of lock acquisition in the method
        """
        if class_name not in self.class_lock_sequences:
            self.class_lock_sequences[class_name] = {}
            
        if method_name not in self.class_lock_sequences[class_name]:
            self.class_lock_sequences[class_name][method_name] = []
            
        self.class_lock_sequences[class_name][method_name].append((lock_name, position))
    
    def check_deadlocks(self):
        """
        Check for potential deadlocks based on recorded lock sequences.
        
        Returns:
            List of (class, method1, method2, lock1, lock2) tuples representing potential deadlocks
        """
        self.potential_deadlocks = []
        
        # Check each class for potential deadlocks
        for class_name, methods in self.class_lock_sequences.items():
            method_names = list(methods.keys())
            
            # Compare each pair of methods within the class
            for i in range(len(method_names)):
                for j in range(i+1, len(method_names)):
                    method1 = method_names[i]
                    method2 = method_names[j]
                    
                    lock_seq1 = methods[method1]
                    lock_seq2 = methods[method2]
                    
                    # Extract lock names from both sequences
                    locks1 = [lock for lock, _ in lock_seq1]
                    locks2 = [lock for lock, _ in lock_seq2]
                    
                    # Find common locks
                    common_locks = set(locks1) & set(locks2)
                    
                    if len(common_locks) >= 2:  # Need at least 2 common locks for a deadlock
                        # Check if the order is different
                        for lock_a in common_locks:
                            for lock_b in common_locks:
                                if lock_a != lock_b:
                                    # Find positions in each method
                                    pos1_a = next((pos for lock, pos in lock_seq1 if lock == lock_a), -1)
                                    pos1_b = next((pos for lock, pos in lock_seq1 if lock == lock_b), -1)
                                    pos2_a = next((pos for lock, pos in lock_seq2 if lock == lock_a), -1)
                                    pos2_b = next((pos for lock, pos in lock_seq2 if lock == lock_b), -1)
                                    
                                    # Check if order is reversed
                                    if (pos1_a < pos1_b and pos2_a > pos2_b):
                                        self.potential_deadlocks.append(
                                            (class_name, method1, method2, lock_a, lock_b)
                                        )
        
        return self.potential_deadlocks


class DeadlockVisitor(ast.NodeVisitor):
    """
    AST visitor to detect potential deadlocks in Python code.
    
    This looks for patterns like:
    - Mutex/lock acquisitions in different orders across different functions
    - Missing lock releases
    - Nested lock acquisitions
    """
    
    def __init__(self):
        """Initialize the visitor."""
        self.findings = []
        self.current_file = "unknown"
        
        # Track classes, methods and lock operations
        self.current_class = None
        self.current_method = None
        self.lock_counter = 0
        
        # Track imported threading/multiprocessing modules
        self.thread_modules = {'threading', 'multiprocessing', 'asyncio'}
        self.imported_modules = set()
        
        # Track lock variables and their parent classes
        # class_name -> {var_name -> lock_type}
        self.class_locks = {}
        
        # Lock tracker to detect deadlocks
        self.lock_tracker = LockTracker()
        
        # Track unreleased locks in methods
        # (class, method) -> {acquired_locks}
        self.acquired_locks = {}
    
    def set_file(self, filename: str) -> None:
        """Set the current file being analyzed."""
        self.current_file = filename
    
    def visit_Import(self, node):
        """Visit an import statement."""
        for name in node.names:
            if name.name in self.thread_modules:
                self.imported_modules.add(name.name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Visit an import from statement."""
        if node.module in self.thread_modules:
            self.imported_modules.add(node.module)
        self.generic_visit(node)
    
    def visit_ClassDef(self, node):
        """Visit a class definition."""
        old_class = self.current_class
        self.current_class = node.name
        
        # Initialize class locks
        if self.current_class not in self.class_locks:
            self.class_locks[self.current_class] = {}
        
        # Process class attributes first to find locks
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == 'self':
                        # Found a self.attribute = something
                        if isinstance(item.value, ast.Call):
                            # Check if it's a lock creation
                            if self._is_lock_creation(item.value):
                                lock_name = target.attr
                                lock_type = self._get_lock_type(item.value)
                                self.class_locks[self.current_class][lock_name] = lock_type
        
        # Now process methods
        for item in node.body:
            if isinstance(item, ast.FunctionDef) and item.name == '__init__':
                # Process __init__ method first to find locks
                self._process_init_method(item)
                
        # Process the rest of the class body
        self.generic_visit(node)
        
        self.current_class = old_class
    
    def _process_init_method(self, node):
        """Process __init__ method to find locks."""
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == 'self':
                        # Found a self.attribute = something
                        if isinstance(stmt.value, ast.Call):
                            # Check if it's a lock creation
                            if self._is_lock_creation(stmt.value):
                                lock_name = target.attr
                                lock_type = self._get_lock_type(stmt.value)
                                self.class_locks[self.current_class][lock_name] = lock_type
    
    def visit_FunctionDef(self, node):
        """Visit a method definition."""
        old_method = self.current_method
        self.current_method = node.name
        old_lock_counter = self.lock_counter
        self.lock_counter = 0
        
        # Initialize acquired locks for this method
        if (self.current_class, self.current_method) not in self.acquired_locks:
            self.acquired_locks[(self.current_class, self.current_method)] = set()
        
        # Process the method body
        self.generic_visit(node)
        
        # Check for unreleased locks
        if self.acquired_locks.get((self.current_class, self.current_method)):
            locks = self.acquired_locks[(self.current_class, self.current_method)]
            if locks:
                self._add_finding(
                    node,
                    f"Method '{self.current_method}' may not release all acquired locks: {', '.join(locks)}",
                    'medium'
                )
        
        self.current_method = old_method
        self.lock_counter = old_lock_counter
    
    def visit_With(self, node):
        """Visit a with statement to detect lock acquisition."""
        if not self.current_class or not self.current_method:
            self.generic_visit(node)
            return
        
        for item in node.items:
            context_expr = item.context_expr
            
            # Check if it's a lock acquisition
            if self._is_lock_use(context_expr):
                lock_name = self._extract_lock_name(context_expr)
                if lock_name:
                    self.lock_counter += 1
                    
                    # Record this lock acquisition
                    self.lock_tracker.add_lock_acquisition(
                        self.current_class,
                        self.current_method,
                        lock_name,
                        self.lock_counter
                    )
                    
                    # With statement automatically releases locks
        
        # Process the body of the with statement
        for stmt in node.body:
            self.visit(stmt)
    
    def _is_lock_creation(self, node):
        """Check if a node represents lock creation."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ('Lock', 'RLock', 'Semaphore', 'Condition'):
                    return True
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id in self.thread_modules and node.func.attr in ('Lock', 'RLock', 'Semaphore', 'Condition'):
                    return True
        return False
    
    def _is_lock_use(self, node):
        """Check if a node represents lock usage."""
        if isinstance(node, ast.Name):
            # This won't work in our simple visitor, but check just in case
            return False
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # self.lock_name
            if node.value.id == 'self':
                # Check if it's a known lock in this class
                return self.current_class in self.class_locks and node.attr in self.class_locks[self.current_class]
        return False
    
    def _extract_lock_name(self, node):
        """Extract the name of a lock from a node."""
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'self':
            return node.attr
        return None
    
    def _get_lock_type(self, node):
        """Get the type of a lock from a creation node."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return "unknown"
    
    def finalize(self):
        """Check for deadlocks after the entire file is processed."""
        # Check for potential deadlocks
        deadlocks = self.lock_tracker.check_deadlocks()
        
        for class_name, method1, method2, lock1, lock2 in deadlocks:
            self._add_finding(
                None,
                f"Potential deadlock in class '{class_name}': methods '{method1}' and '{method2}' acquire locks '{lock1}' and '{lock2}' in different orders",
                'high'
            )
    
    def _add_finding(self, node, message, severity):
        """Add a finding to the results."""
        line = 0
        if node and hasattr(node, 'lineno'):
            line = node.lineno
        
        finding = {
            'file': self.current_file,
            'line': line,
            'col': node.col_offset if node and hasattr(node, 'col_offset') else 0,
            'message': message,
            'severity': severity
        }
        self.findings.append(finding)


class DeadlockAnalyzer(BaseAnalyzer):
    """Analyzer for deadlock detection (CWE-833)."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False
    ):
        """
        Initialize the deadlock analyzer.
        
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
        Run deadlock detection analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        self.logger.info("Running Deadlock Detection analysis for reliability issues...")
        
        # Find all Python files in the project
        python_files = list(Path(self.project_path).glob("**/*.py"))
        
        # Analyze each file
        for file_path in python_files:
            self._analyze_file(file_path)
        
        self.logger.info(f"Found {len(self.findings)} potential deadlock issues")
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
            
            # Visit the AST to find deadlock issues
            visitor = DeadlockVisitor()
            visitor.set_file(str(file_path))
            visitor.visit(tree)
            
            # Check for deadlocks after full analysis
            visitor.finalize()
            
            # Convert visitor findings to analyzer findings
            for finding in visitor.findings:
                analyzer_finding = {
                    'analyzer': 'deadlock_detection',
                    'characteristic': self.characteristic,
                    'rule_id': 'potential-deadlock',
                    'cwe_id': 'CWE-833',  # Deadlock
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