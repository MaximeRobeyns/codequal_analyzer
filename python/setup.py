"""Setup script for PyCQ Quality Analyzer."""

from setuptools import setup, find_packages

setup(
    name="pycq_analyzer",
    version="0.1.0",
    description="Python Code Quality Analyzer for Python projects",
    author="Maxime Robeyns",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "qa=pycq_analyzer.main:main",
        ],
    },
    python_requires=">=3.7",
)
