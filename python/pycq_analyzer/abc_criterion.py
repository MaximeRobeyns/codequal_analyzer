"""
A very simple Assignment-Branch-Criterion proxy for software complexity
"""

import os
import ast
import math
import logging

from typing import Union, Tuple
from functools import singledispatch

logger = logging.getLogger()


# ABC implementation logic -----------------------------------------------------


class Vector:
    __slots__ = ("assignment", "branch", "condition", "lineno", "node")

    def __init__(
        self,
        assignment: int,
        branch: int,
        condition: int,
        lineno: int = 0,
        node: ast.AST | None = None,
    ):
        self.assignment = assignment
        self.branch = branch
        self.condition = condition
        self.lineno = lineno
        self.node = node

    def __add__(self, other: "Vector") -> "Vector":
        return Vector(
            self.assignment + other.assignment,
            self.branch + other.branch,
            self.condition + other.condition,
            self.lineno,
        )

    def __str__(self) -> str:
        return f"<{self.assignment}, {self.branch}, {self.condition}>"

    def get_magnitude_value(self) -> float:
        """Calculate the magnitude of the ABC vector."""
        return round(
            math.sqrt(
                sum(
                    (
                        self.assignment * self.assignment,
                        self.branch * self.branch,
                        self.condition * self.condition,
                    )
                )
            ),
            1,
        )

    @property
    def magnitude(self) -> str:
        """Return vector with magnitude."""
        return f"{str(self)} ({self.get_magnitude_value()})"


def empty(node_class: ast.AST, lineno=None) -> Vector:
    lineno = lineno if lineno else getattr(node_class, "lineno", 0)
    return Vector(0, 0, 0, lineno, node_class)


def assignment(node_class: ast.AST, lineno=None) -> Vector:
    lineno = lineno if lineno else node_class.lineno
    return Vector(1, 0, 0, lineno, node_class)


def branch(node_class: ast.AST, lineno=None) -> Vector:
    lineno = lineno if lineno else node_class.lineno
    return Vector(0, 1, 0, lineno, node_class)


def condition(node_class: ast.AST, lineno=None) -> Vector:
    lineno = lineno if lineno else node_class.lineno
    return Vector(0, 0, 1, lineno, node_class)


@singledispatch
def calculate_abc_for_node(node_class: ast.AST) -> list[Vector]:
    """Used by default"""
    return [empty(node_class)]


def handle_else(
    node_class: ast.For | ast.If | ast.IfExp | ast.Try | ast.While,
) -> Vector:
    """Handle else/elif branches."""
    if not getattr(node_class, "orelse", None):
        return empty(node_class)

    if isinstance(node_class.orelse, list):
        node = node_class.orelse[0]  # type: ast.AST
    else:
        node = node_class.orelse

    if not isinstance(node, ast.If):
        lineno = node.lineno - 1 if node.lineno != node_class.lineno else node.lineno
    else:
        lineno = node.lineno

    return condition(node, lineno)


# Node classes that do not contribute to count but may have components
@calculate_abc_for_node.register
def ast_for(node_class: ast.For):
    return [handle_else(node_class)]


@calculate_abc_for_node.register
def ast_while(node_class: ast.While):
    return [handle_else(node_class)]


# Syntax contributing to assignment count
@calculate_abc_for_node.register
def ast_assign(node_class: ast.Assign):
    vectors = []
    for target in node_class.targets:
        if isinstance(target, ast.Tuple):
            for elt in target.elts:
                vectors.append(assignment(elt))
        else:
            vectors.append(assignment(target))
    return vectors


@calculate_abc_for_node.register
def ast_annassign(node_class: ast.AnnAssign):
    return [assignment(node_class)]


@calculate_abc_for_node.register
def ast_augassign(node_class: ast.AugAssign):
    return [assignment(node_class)]


# Syntax contributing to branch count
@calculate_abc_for_node.register
def ast_call(node_class: ast.Call):
    return [branch(node_class)]


# Syntax contributing to condition count
@calculate_abc_for_node.register
def ast_boolop(node_class: ast.BoolOp):
    return [
        condition(v)
        for v in node_class.values
        if not isinstance(v, (ast.BoolOp, ast.Compare))
    ] or [empty(node_class)]


@calculate_abc_for_node.register
def ast_compare(node_class: ast.Compare):
    return [condition(node_class)]


@calculate_abc_for_node.register
def ast_excepthandler(node_class: ast.ExceptHandler):
    return [condition(node_class)]


@calculate_abc_for_node.register
def ast_if(node_class: ast.If):
    if not isinstance(node_class.test, (ast.BoolOp, ast.Compare, ast.Constant)):
        return [condition(node_class.test), handle_else(node_class)]
    else:
        return [handle_else(node_class)]


@calculate_abc_for_node.register
def ast_ifexp(node_class: ast.IfExp):
    if not isinstance(node_class.test, (ast.BoolOp, ast.Compare, ast.Constant)):
        return [condition(node_class.test), handle_else(node_class)]
    else:
        return [handle_else(node_class)]


@calculate_abc_for_node.register
def ast_try(node_class: ast.Try):
    return [handle_else(node_class)]


@calculate_abc_for_node.register
def ast_assert(node_class: ast.Assert):
    if isinstance(node_class.test, ast.Name):
        return [condition(node_class.test)]
    else:
        return [empty(node_class)]


def calculate_abc(source: str) -> Vector:
    """Calculate ABC metric for Python source code."""
    final_vector = Vector(0, 0, 0)

    tree = ast.parse(source)

    for node in ast.walk(tree):
        temp_vectors = calculate_abc_for_node(node)

        for v in temp_vectors:
            if getattr(v, "lineno", 0):
                final_vector += v

    return final_vector


def _normalize_score(magnitude: float, root: float = 3.0) -> float:
    """Convert ABC magnitude to quality score using reciprocal root normalization."""
    if magnitude == 0:
        return 1.0
    return min(1.0, 1.0 / (magnitude ** (1 / root)))


def calculate(
    code: str, root: float = 3.0, verbose: bool = False
) -> Union[float, Tuple[float, dict]]:
    """
    Calculate ABC quality score for Python code.

    Args:
        code: Python source code as a string
        root: Root parameter for normalization (default 3.0)
        verbose: If True, return additional metrics

    Returns:
        If verbose is False: Quality score (float) between 0 and 1
        If verbose is True: Tuple of (score, metrics_dict)
    """
    # Calculate ABC metrics
    vector = calculate_abc(code)
    magnitude = vector.get_magnitude_value()
    score = _normalize_score(magnitude, root)

    if verbose:
        metrics = {
            "assignments": vector.assignment,
            "branches": vector.branch,
            "conditions": vector.condition,
            "abc_vector": str(vector),
            "magnitude": magnitude,
            "root": root,
        }
        return score, metrics

    return score


def calculate_file(
    filepath: Union[str, os.PathLike], root: float = 3.0, verbose: bool = False
) -> Union[float, Tuple[float, dict]]:
    """
    Calculate ABC quality score for a Python file.

    Args:
        filepath: Path to Python file
        root: Root parameter for normalization (default 3.0)
        verbose: If True, return additional metrics

    Returns:
        If verbose is False: Quality score (float) between 0 and 1
        If verbose is True: Tuple of (score, metrics_dict)

    Raises:
        FileNotFoundError: If the file doesn't exist
        SyntaxError: If the file contains invalid Python syntax
    """
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()

    return calculate(code, root=root, verbose=verbose)


def calculate_dir(
    dirpath: Union[str, os.PathLike],
    root: float = 3.0,
    verbose: bool = False,
    recursive: bool = True,
    ignore_patterns: list[str] = None,
) -> Union[float, Tuple[float, dict]]:
    """
    Calculate ABC quality score for all Python files in a directory.

    Args:
        dirpath: Path to directory containing Python files
        root: Root parameter for normalization (default 3.0)
        verbose: If True, return additional metrics
        recursive: If True, process subdirectories recursively
        ignore_patterns: List of glob patterns to ignore (e.g. ["*test*.py", "setup.py"])

    Returns:
        If verbose is False: Average quality score (float) between 0 and 1
        If verbose is True: Tuple of (average_score, aggregated_metrics_dict)

    Raises:
        FileNotFoundError: If the directory doesn't exist
        ValueError: If no Python files are found in the directory
    """
    import os
    import fnmatch
    from pathlib import Path

    # Convert to Path object for consistent handling
    dirpath = Path(dirpath)

    if not dirpath.exists() or not dirpath.is_dir():
        raise FileNotFoundError(f"Directory not found: {dirpath}")

    # Initialize default ignore patterns if None
    if ignore_patterns is None:
        ignore_patterns = []

    # Initialize aggregate metrics
    total_files = 0
    total_score = 0.0
    aggregated_metrics = {
        "assignments": 0,
        "branches": 0,
        "conditions": 0,
        "magnitude": 0,
        "files": {},
        "root": root,
    }

    # Get all Python files
    python_files = []

    if recursive:
        for root_dir, _, files in os.walk(dirpath):
            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root_dir) / file
                    # Check if file should be ignored
                    should_ignore = any(
                        fnmatch.fnmatch(file_path.name, pattern)
                        for pattern in ignore_patterns
                    )
                    if not should_ignore:
                        python_files.append(file_path)
    else:
        for file in dirpath.glob("*.py"):
            # Check if file should be ignored
            should_ignore = any(
                fnmatch.fnmatch(file.name, pattern) for pattern in ignore_patterns
            )
            if not should_ignore:
                python_files.append(file)

    if not python_files:
        raise ValueError(f"No Python files found in directory: {dirpath}")

    # Process each file
    for file_path in python_files:
        try:
            relative_path = file_path.relative_to(dirpath)

            # Calculate metrics for this file
            if verbose:
                file_score, file_metrics = calculate_file(
                    file_path, root=root, verbose=True
                )

                # Add to aggregated metrics
                aggregated_metrics["assignments"] += file_metrics["assignments"]
                aggregated_metrics["branches"] += file_metrics["branches"]
                aggregated_metrics["conditions"] += file_metrics["conditions"]
                aggregated_metrics["magnitude"] += file_metrics["magnitude"]

                # Store file-specific metrics
                aggregated_metrics["files"][str(relative_path)] = {
                    "score": file_score,
                    "metrics": file_metrics,
                }
            else:
                file_score = calculate_file(file_path, root=root, verbose=False)

            total_score += file_score
            total_files += 1

        except (SyntaxError, UnicodeDecodeError) as e:
            # Log but continue processing other files
            logger.warning(f"Error processing {file_path}: {e}")

    # Calculate average score
    if total_files > 0:
        average_score = total_score / total_files
    else:
        average_score = 0.0

    # Include aggregate ABC vector
    if verbose and total_files > 0:
        a = aggregated_metrics["assignments"]
        b = aggregated_metrics["branches"]
        c = aggregated_metrics["conditions"]
        aggregated_metrics["abc_vector"] = f"<{a}, {b}, {c}>"

        # Add average magnitude
        aggregated_metrics["average_magnitude"] = (
            aggregated_metrics["magnitude"] / total_files
        )

        # Add file count
        aggregated_metrics["file_count"] = total_files

        return average_score, aggregated_metrics

    return average_score
