"""
PyCQ Analyzer Quick Assessment Example.

This script demonstrates how to use the PyCQ Analyzer's API to:
1. Analyze a Python project
2. Analyze a single Python file
3. Analyze Python code from a string
"""

from pathlib import Path

# Import from the main package
from pycq_analyzer import get_quality_score, assess_code_string, analyze_file


def demo_project_analysis():
    """Demonstrate analyzing an entire project."""
    print("\n=== Project Analysis ===")

    # Get the path to the sample project
    current_dir = Path(__file__).parent.parent
    project_path = current_dir / "sample_project"

    print(f"Analyzing project: {project_path}")

    # Get the quality score with default settings (quick=True)
    score = get_quality_score(project_path, verbose=True)
    print(f"\nProject Quality Score: {score:.2f}/100")

    # You can also use all analyzers for a more comprehensive assessment
    comprehensive_score = get_quality_score(project_path, verbose=False, quick=False)
    print(f"\nComprehensive Project Quality Score: {comprehensive_score:.2f}/100")


def demo_file_analysis():
    """Demonstrate analyzing a single file."""
    print("\n=== Single File Analysis ===")

    # Get the path to a file in the sample project
    current_dir = Path(__file__).parent.parent
    file_path = current_dir / "sample_project" / "security_issues.py"

    print(f"Analyzing file: {file_path}")

    # Analyze the file
    score = analyze_file(file_path, verbose=True)
    print(f"\nFile Quality Score: {score:.2f}/100")


def demo_string_analysis():
    """Demonstrate analyzing code from a string."""
    print("\n=== String Analysis ===")

    # Some Python code to analyze
    code = """
def calculate_sum(numbers):
    # A function with good practices
    total = 0
    for num in numbers:
        total += num
    return total

if __name__ == "__main__":
    result = calculate_sum([1, 2, 3, 4, 5])
    print(f"The sum is {result}")
"""

    print("Analyzing code string:")
    print(code)

    # Analyze the code string
    score = assess_code_string(code, verbose=True)
    print(f"\nCode Quality Score: {score:.2f}/100")


def main():
    """Run all the demonstrations."""
    print("PyCQ Analyzer Quick Assessment Examples")
    print("======================================")

    demo_project_analysis()
    demo_file_analysis()
    demo_string_analysis()


if __name__ == "__main__":
    main()
