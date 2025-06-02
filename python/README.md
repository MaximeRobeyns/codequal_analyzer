# PyCQ Quality Analyzer

A Python tool for measuring software quality based on the CISQ (Consortium for IT Software Quality) [standards](https://www.it-cisq.org/cisq-files/pdf/cisq-weaknesses-in-ascqm.pdf). The analyzer detects weaknesses in source code across four key quality characteristics:

- **Maintainability**: How easy the software is to modify and enhance
- **Security**: How well protected the software is against vulnerabilities
- **Performance Efficiency**: How well the software uses resources
- **Reliability**: How well the software functions under stated conditions

## Features

- Automated analysis of Python code for quality issues
- Parallel execution of analyzers with configurable concurrency limit
- Integration with multiple open-source analysis tools
- Mapping of found issues to CWE (Common Weakness Enumeration) IDs
- Calculation of quality scores across CISQ dimensions
- Support for both static and dynamic analysis
- **Quick assessment API** for getting single quality scores
- **In-memory code analysis** for assessing code strings

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Basic Installation (Static Analysis Only)

```bash
# Clone the repository
git clone https://github.com/maximerobeyns/codequal_analyzer.git
cd pycq_analyzer

# Install the package in development mode
pip install -e .
```

### Full Installation (Including Runtime Analysis)

```bash
# Install all dependencies including runtime analysis tools
pip install -r requirements/full.txt

# Install the package in development mode
pip install -e .
```

## Usage

### Command-line Usage

```bash
# Analyze a Python project
pycq-analyzer /path/to/python/project

# Enable verbose output
pycq-analyzer /path/to/python/project --verbose

# Specify an output directory for reports
pycq-analyzer /path/to/python/project --output-dir ./reports

# Run analyzers in parallel with a specific number of concurrent jobs
pycq-analyzer /path/to/python/project -j 4
```

### Python API Usage

You can also use PyCQ Analyzer directly as a library in your Python code:

```python
# Import the API functions
from pycq_analyzer import get_quality_score, analyze_file, assess_code_string

# Analyze a project
score = get_quality_score('/path/to/project', verbose=True)
print(f"Project Quality: {score:.2f}/100")

# Analyze a single file
file_score = analyze_file('/path/to/file.py')
print(f"File Quality: {file_score:.2f}/100")

# Analyze code from a string
code = """
def hello_world():
    print("Hello, World!")
"""
code_score = assess_code_string(code, filename="hello.py")
print(f"Code Quality: {code_score:.2f}/100")
```

#### Quick vs. Comprehensive Analysis

By default, the API uses a selected set of analyzers for quick assessment. For comprehensive analysis:

```python
# Quick analysis (default)
quick_score = get_quality_score('/path/to/project')

# Comprehensive analysis with all available analyzers
comprehensive_score = get_quality_score('/path/to/project', quick=False)
```

Check the `examples` folder for more detailed usage examples.

### Analysis Options

- `--static-only`: Run only static analyzers (no execution required)
- `--verbose`, `-v`: Enable verbose logging
- `--output-dir`: Directory to store analysis reports (default: ./pycq_reports)
- `-j`, `--jobs`: Maximum number of analyzers to run in parallel (default: 4)
- `--complexity-threshold`: Minimum code complexity threshold to report (A-F, default: C)
- `--requirements-file`: Path to requirements file for dependency analysis

## Currently Implemented Analyzers

### Maintainability
- **Pylint**: Detects various maintainability issues including dead code, duplicate code, and complexity
- **Radon**: Detects code complexity issues and excessive file length
- **Vulture**: Detects unused code

### Security
- **Bandit**: Detects common security issues such as use of insecure functions, hard-coded credentials, and shell injection
- **Safety**: Detects known security vulnerabilities in Python dependencies

### Performance Efficiency
- **String Concatenation Analyzer**: Detects inefficient string operations
- **Resource Consumption Analyzer**: Identifies potential resource usage issues
- **Data Structure Complexity Analyzer**: Detects overly complex data structures

### Reliability
- **Exception Handling Analyzer**: Detects improper exception handling
- **Deadlock Analyzer**: Identifies potential thread deadlocks
- **Mypy**: Provides static type checking

## Understanding the Scores

Quality scores are calculated on a 0-100 scale (higher is better):

- 90-100: Excellent
- 70-89: Good
- 50-69: Fair
- 0-49: Poor

The overall score is calculated as an average of all four CISQ characteristics.

## Parallel Execution

The PyCQ Quality Analyzer runs multiple analyzers in parallel for better performance. You can control the maximum number of concurrent analyzers using the `-j` or `--jobs` parameter:

```bash
# Run with up to 8 concurrent analyzers
pycq-analyzer /path/to/python/project -j 8
```

This can significantly speed up analysis of large projects.

## Extending the Analyzer

The analyzer is designed to be modular and extensible. To add a new analyzer:

1. Create a new class that inherits from `BaseAnalyzer`
2. Implement the `analyze()` method to detect issues
3. Map detected issues to CWE IDs
4. Add your analyzer to the `run_analyzers()` function in `main.py`

## License

This project is licensed under the MIT License - see the LICENSE file for details.
