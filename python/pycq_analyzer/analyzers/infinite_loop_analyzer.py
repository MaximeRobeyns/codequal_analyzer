"""Infinite loop detection analyzer for reliability issues."""
import ast
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Set, Tuple

from .base_analyzer import BaseAnalyzer

# Python version compatibility
PY38_PLUS = sys.version_info >= (3, 8)

# Version-aware compatibility functions
def is_constant_true(node):
    """Check if a node represents a constant True value, compatible across Python versions."""
    if PY38_PLUS:
        # Python 3.8+ uses ast.Constant
        return isinstance(node, ast.Constant) and node.value is True
    else:
        # Python 3.7 and earlier use ast.NameConstant
        return hasattr(ast, 'NameConstant') and isinstance(node, ast.NameConstant) and node.value is True

def is_constant(node):
    """Check if a node is a constant, compatible across Python versions."""
    if PY38_PLUS:
        return isinstance(node, ast.Constant)
    else:
        # Check for old-style constants only if they exist
        types = []
        if hasattr(ast, 'NameConstant'):
            types.append(ast.NameConstant)
        if hasattr(ast, 'Num'):
            types.append(ast.Num) 
        if hasattr(ast, 'Str'):
            types.append(ast.Str)
        if hasattr(ast, 'Bytes'):
            types.append(ast.Bytes)
        if hasattr(ast, 'Ellipsis'):
            types.append(ast.Ellipsis)
        return types and isinstance(node, tuple(types))

def get_constant_value(node):
    """Extract the value from a constant node, compatible across Python versions."""
    if isinstance(node, ast.Constant):
        return node.value
    elif hasattr(node, 'value'):
        # Works for ast.NameConstant
        return node.value
    elif hasattr(node, 'n'):
        # Works for ast.Num
        return node.n
    elif hasattr(node, 's'):
        # Works for ast.Str
        return node.s
    elif hasattr(node, 'bytes'):
        # Works for ast.Bytes
        return node.bytes
    return None

class InfiniteLoopVisitor(ast.NodeVisitor):
    """
    AST visitor to detect potential infinite loops in Python code.
    
    This looks for patterns like:
    - Loops without break conditions
    - Loops with unreachable exit conditions
    - Loops with counter variables that might not change properly
    """
    
    def __init__(self):
        """Initialize the visitor."""
        self.findings = []
        self.current_file = "unknown"
        
        # Track variables whose values determine loop exit conditions
        self.loop_counter_vars = set()
        self.current_function = None
        
        # Keep track of loop control variables and exit conditions
        self.loop_control_vars = {}  # var_name -> {modified: bool, used_in_condition: bool}
        
        # Track loop nesting
        self.loop_depth = 0
        self.in_loop_body = False
        self.has_break_or_return = False
    
    def set_file(self, filename: str) -> None:
        """Set the current file being analyzed."""
        self.current_file = filename
    
    def visit_FunctionDef(self, node):
        """Visit a function definition."""
        old_function = self.current_function
        self.current_function = node.name
        
        # Process the function body
        self.generic_visit(node)
        
        # Restore context
        self.current_function = old_function
    
    def visit_For(self, node):
        """Visit a for loop to detect potential infinite loops."""
        self._analyze_loop(node, is_for=True)
    
    def visit_While(self, node):
        """Visit a while loop to detect potential infinite loops."""
        self._analyze_loop(node, is_for=False)
    
    def _analyze_loop(self, node, is_for=False):
        """
        Analyze a loop for potential infinite loop patterns.
        
        Args:
            node: The loop AST node
            is_for: Whether it's a for loop (True) or while loop (False)
        """
        # Track loop nesting
        self.loop_depth += 1
        
        # Reset loop-specific state
        old_in_loop_body = self.in_loop_body
        old_has_break_or_return = self.has_break_or_return
        self.in_loop_body = True
        self.has_break_or_return = False
        
        # Initialize control variables
        control_vars = set()
        
        # Check for potential infinite loop patterns
        if is_for:
            # For loops over constants are generally safe
            # But for x in iterator might be a problem if iterator doesn't change
            # There are still edge cases, but we're not as concerned with for loops
            pass
        else:  # while loop
            # Check for while loops with constant conditions
            if is_constant_true(node.test):
                # while True without break is infinite
                # We'll verify if there are breaks after processing the body
                pass
            elif isinstance(node.test, ast.Constant) and node.test.value is True:
                # Python 3.8+ syntax for constants
                # while True without break is infinite
                pass
            
            # Extract variables used in the condition
            condition_vars = self._extract_variables_from_condition(node.test)
            for var in condition_vars:
                control_vars.add(var)
        
        # Process the loop body
        for stmt in node.body:
            self.visit(stmt)
        
        # Check if control variables are modified within the loop
        if not is_for and is_constant_true(node.test):
            # while True loop without break/return is an infinite loop
            if not self.has_break_or_return:
                self._add_finding(
                    node,
                    "Infinite loop: 'while True' without break or return statement",
                    'high'
                )
        
        # If it's a potentially problematic while loop and no break/return was found
        if not is_for and control_vars and not self.has_break_or_return:
            # Check if loop variables are actually modified within the loop
            modified_vars = set()
            all_modified = True
            
            for stmt in node.body:
                if isinstance(stmt, (ast.Assign, ast.AugAssign)):
                    # Extract variables being assigned to
                    assigned_vars = []
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                assigned_vars.append(target.id)
                    elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                        assigned_vars.append(stmt.target.id)
                        
                    for var in control_vars:
                        if var in assigned_vars:
                            modified_vars.add(var)
            
            # Check if any control variables were not modified
            unmodified_vars = control_vars - modified_vars
            if unmodified_vars:
                self._add_finding(
                    node,
                    f"Potential infinite loop: control variables {', '.join(unmodified_vars)} may not be modified within the loop",
                    'medium'
                )
        
        # Check for loops that modify their iteration variables in a way that might prevent termination
        if is_for and isinstance(node.iter, ast.Name):
            # Check if the iteration variable is being modified in the loop body
            iter_var = node.iter.id
            target_var = node.target.id if isinstance(node.target, ast.Name) else None
            
            if target_var:
                # Check for patterns like:
                # for i in range(len(some_list)):
                #     some_list.append(i)
                # which can lead to infinite loops due to growing iterable
                for stmt in node.body:
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        if (isinstance(stmt.value.func, ast.Attribute) and 
                            isinstance(stmt.value.func.value, ast.Name) and 
                            stmt.value.func.value.id == iter_var and 
                            stmt.value.func.attr in ['append', 'insert', 'extend']):
                            self._add_finding(
                                node,
                                f"Potential infinite loop: modifying iteration variable '{iter_var}' within the loop",
                                'medium'
                            )
                
                # Check for decreasing the index in a for loop over a range
                if hasattr(node, 'iter') and hasattr(node.iter, 'value'):
                    # Handle both old and new AST patterns for 'range' calls
                    range_call = False
                    range_call_func_name = None
                    
                    if isinstance(node.iter.value, ast.Call) and isinstance(node.iter.value.func, ast.Name):
                        range_call = True
                        range_call_func_name = node.iter.value.func.id
                    
                    if range_call and range_call_func_name == 'range':
                        for stmt in node.body:
                            if (isinstance(stmt, ast.AugAssign) and 
                                isinstance(stmt.target, ast.Name) and 
                                stmt.target.id == target_var and 
                                isinstance(stmt.op, ast.Sub)):
                                self._add_finding(
                                    node,
                                    f"Potential infinite loop: decrementing loop variable '{target_var}' within a for loop",
                                    'high'
                                )
        
        # Look for while loops with conditions that might never become False
        if not is_for:
            # Check for while loops with equality comparisons but no breaks
            if isinstance(node.test, ast.Compare) and not self.has_break_or_return:
                # Extract the left and right sides of the comparison
                left = node.test.left
                op = node.test.ops[0]
                comparator = node.test.comparators[0]
                
                # Check for patterns like: while i != target_val
                # where i might skip over the target_val or never reach it
                if (isinstance(op, (ast.NotEq, ast.Eq)) and
                    isinstance(left, ast.Name) and
                    is_constant(comparator)):
                    
                    var_name = left.id
                    
                    # Check how the variable is modified in the loop
                    for stmt in node.body:
                        # Check for potentially problematic increments/decrements
                        if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == var_name:
                            if isinstance(stmt.op, (ast.Add, ast.Sub)):
                                # Look for augmented assignments that might skip the comparison value  
                                if is_constant(stmt.value):
                                    increment = get_constant_value(stmt.value)
                                    if increment and increment > 1:
                                        self._add_finding(
                                            node,
                                            f"Potential infinite loop: variable '{var_name}' is incremented by {increment} and might skip the termination value",
                                            'medium'
                                        )
        
        # Restore loop state
        self.loop_depth -= 1
        self.in_loop_body = old_in_loop_body
        self.has_break_or_return = old_has_break_or_return
    
    def visit_Break(self, node):
        """Visit a break statement."""
        if self.in_loop_body:
            self.has_break_or_return = True
        self.generic_visit(node)
    
    def visit_Return(self, node):
        """Visit a return statement."""
        if self.in_loop_body:
            self.has_break_or_return = True
        self.generic_visit(node)
    
    def visit_Raise(self, node):
        """Visit a raise statement."""
        if self.in_loop_body:
            self.has_break_or_return = True
        self.generic_visit(node)
    
    def _extract_variables_from_condition(self, node):
        """
        Extract variable names from a condition node.
        
        Args:
            node: AST node representing a condition
            
        Returns:
            Set of variable names used in the condition
        """
        variables = set()
        
        # Helper function to recursively extract variables
        def extract_vars(n):
            if isinstance(n, ast.Name):
                variables.add(n.id)
            elif isinstance(n, ast.Compare):
                extract_vars(n.left)
                for comparator in n.comparators:
                    extract_vars(comparator)
            elif isinstance(n, ast.BoolOp):
                for value in n.values:
                    extract_vars(value)
            elif isinstance(n, ast.UnaryOp):
                extract_vars(n.operand)
            elif isinstance(n, ast.BinOp):
                extract_vars(n.left)
                extract_vars(n.right)
            elif isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name):
                    for arg in n.args:
                        extract_vars(arg)
            # Add more cases as needed for other AST node types
        
        extract_vars(node)
        return variables
    

    
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


class InfiniteLoopAnalyzer(BaseAnalyzer):
    """Analyzer for potential infinite loops (CWE-835)."""
    
    def __init__(
        self, 
        project_path: Union[str, Path],
        verbose: bool = False
    ):
        """
        Initialize the infinite loop analyzer.
        
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
        Run infinite loop detection analysis.
        
        Returns:
            List of findings
        """
        self.findings = []
        
        self.logger.info("Running Infinite Loop Detection analysis for reliability issues...")
        
        # Find all Python files in the project
        python_files = list(Path(self.project_path).glob("**/*.py"))
        
        # Analyze each file
        for file_path in python_files:
            self._analyze_file(file_path)
        
        self.logger.info(f"Found {len(self.findings)} potential infinite loop issues")
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
            
            # Visit the AST to find infinite loop issues
            visitor = InfiniteLoopVisitor()
            visitor.set_file(str(file_path))
            visitor.visit(tree)
            
            # Convert visitor findings to analyzer findings
            for finding in visitor.findings:
                analyzer_finding = {
                    'analyzer': 'infinite_loop_detection',
                    'characteristic': self.characteristic,
                    'rule_id': 'potential-infinite-loop',
                    'cwe_id': 'CWE-835',  # Loop with Unreachable Exit Condition ('Infinite Loop')
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