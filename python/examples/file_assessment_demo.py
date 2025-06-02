"""
File Assessment Demo - Demonstrating how to check quality of a specific Python file.

This script shows how to use the quick_quality_check module to analyze:
1. A specific Python file on disk
2. Multiple Python files from a project
3. Python code provided as a string
"""

import os
from pathlib import Path
from pprint import pprint

from quick_quality_check import get_quality_score, assess_code_string


def analyze_specific_file(filepath):
    """Analyze a specific Python file and print the quality score."""
    print(f"\nAnalyzing file: {filepath}")

    # First approach: Create a temporary directory with just this file
    # This is useful if you want to analyze a file in isolation
    from tempfile import mkdtemp
    import shutil

    temp_dir = mkdtemp(prefix="file_analysis_")
    try:
        # Copy the file to the temporary directory
        basename = os.path.basename(filepath)
        temp_file = os.path.join(temp_dir, basename)
        shutil.copy(filepath, temp_file)

        # Analyze the temporary directory
        score = get_quality_score(temp_dir, verbose=True)
        print(f"\nQuality Score for {basename}: {score:.2f}/100")
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

    # Second approach: Read the file content and use assess_code_string
    # This is useful when you have the code as a string already
    print(f"\nAlternative approach using assess_code_string:")
    with open(filepath, "r") as f:
        file_content = f.read()

    score = assess_code_string(
        file_content, filename=os.path.basename(filepath), verbose=True
    )
    print(f"\nQuality Score for {filepath} (using assess_code_string): {score:.2f}/100")


def main():
    """Main entry point for demonstration."""
    # Analyze a specific file from the sample project
    sample_file = Path(__file__).parent / "sample_project" / "security_issues.py"
    analyze_specific_file(sample_file)

    # You can also analyze a whole project in one go
    project_path = Path(__file__).parent / "sample_project"
    print(f"\n\nAnalyzing entire project: {project_path}")
    score = get_quality_score(
        project_path, verbose=False
    )  # Set verbose=False to reduce output
    print(f"\nOverall Project Quality Score: {score:.2f}/100")

    # Create and analyze a string with Python code
    print("\n\nAnalyzing Python code string:")
    code_string = """
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
    score = assess_code_string(code_string, verbose=True)
    print(f"\nQuality Score for good code example: {score:.2f}/100")


if __name__ == "__main__":
    main()
