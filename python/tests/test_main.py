"""Tests for the main CLI entrypoint."""

import unittest
from pathlib import Path

from pycq_analyzer.main import run_analyzers, calculate_scores


class TestMainCLI(unittest.TestCase):
    """Test cases for the main CLI entrypoint."""

    def setUp(self):
        """Set up test fixture."""
        self.project_path = Path(__file__).parent.parent / "sample_project"

    def test_run_analyzers(self):
        """Test running all analyzers."""
        findings = run_analyzers(self.project_path, static_only=True, verbose=True)

        # Check that we have findings for maintainability
        self.assertIn("maintainability", findings)
        self.assertGreater(len(findings["maintainability"]), 0)

        # Print summary of findings
        total_findings = sum(len(f) for f in findings.values())
        print(f"\nFound {total_findings} issues across all analyzers:")

        for characteristic, characteristic_findings in findings.items():
            print(f"  {characteristic}: {len(characteristic_findings)}")

    def test_calculate_scores(self):
        """Test score calculation."""
        # Create sample findings
        findings = {
            "maintainability": [{"severity": "high"}, {"severity": "medium"}],
            "security": [{"severity": "high"}],
            "performance": [],
            "reliability": [
                {"severity": "low"},
                {"severity": "low"},
                {"severity": "medium"},
            ],
        }

        # Calculate scores
        scores = calculate_scores(findings)

        # Check that we have scores for all characteristics
        for characteristic in findings.keys():
            self.assertIn(characteristic, scores)

        # Check overall score
        self.assertIn("overall", scores)

        # Print scores
        print("\nQuality scores:")
        for characteristic, score in scores.items():
            print(f"  {characteristic}: {score:.2f}")

        # Verify score calculation logic
        self.assertEqual(scores["maintainability"], 90.0)  # 100 - (2 * 5)
        self.assertEqual(scores["security"], 95.0)  # 100 - (1 * 5)
        self.assertEqual(scores["performance"], 100.0)  # 100 - (0 * 5)
        self.assertEqual(scores["reliability"], 85.0)  # 100 - (3 * 5)

        # Overall is average of all scores
        expected_overall = (90.0 + 95.0 + 100.0 + 85.0) / 4
        self.assertEqual(scores["overall"], expected_overall)


if __name__ == "__main__":
    unittest.main()
