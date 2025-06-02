"""PyCQ Analyzer - A tool for measuring python software quality."""

from .api import (
    get_quality_score,
    assess_code_string,
    analyze_file,
    assess_code_with_feedback,
    assess_dir_with_feedback,
    get_rich_insights,
)

__version__ = "0.1.0"
