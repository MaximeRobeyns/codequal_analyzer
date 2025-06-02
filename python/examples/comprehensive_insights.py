from pycq_analyzer import get_rich_insights


def main():
    print("=== PyCQ RICH INSIGHTS COMPREHENSIVE DEMO ===")
    print("Analyzing sample project with rich insights...\n")

    # Get rich insights with all features enabled
    insights = get_rich_insights(
        "sample_project", verbose=False, include_rates=True, include_distributions=True
    )

    # Overall project summary
    print("1. PROJECT OVERVIEW")
    print("=" * 50)
    overall = insights["overall_metrics"]
    print(f"• Overall Quality Score: {overall['quality_score']:.2f}/100")
    print(f"• Total Files Analyzed: {overall['total_files']}")
    print(
        f"• Lines of Code: {overall['total_lines']:,} (Code: {overall['code_lines']:,})"
    )
    print(f"• Functions: {overall['total_functions']}")
    print(f"• Classes: {overall['total_classes']}")

    # Detailed characteristics breakdown
    print("\n2. QUALITY CHARACTERISTICS BREAKDOWN")
    print("=" * 50)
    for char_name, char_data in insights["characteristics"].items():
        score = char_data["score"]
        total_issues = char_data["total_issues"]

        # Color coding for score (simulate with symbols)
        score_symbol = "🟢" if score >= 70 else "🟡" if score >= 50 else "🔴"

        print(f"\n{char_name.upper()} {score_symbol}")
        print(f"  Score: {score:.2f}/100 | Issues: {total_issues}")

        # Show detailed metrics
        if "metrics" in char_data:
            for metric_name, metric_data in char_data["metrics"].items():
                if isinstance(metric_data, dict) and "count" in metric_data:
                    count = metric_data["count"]
                    rate = metric_data.get("rate", "N/A")
                    print(f"    {metric_name.replace('_', ' ').title()}:")
                    print(f"      Issues: {count}, Rate: {rate}")

                    # Show breakdown if available
                    if "breakdown" in metric_data:
                        breakdown = metric_data["breakdown"]
                        for item, item_count in breakdown.items():
                            if item_count > 0:
                                print(
                                    f"        - {item.replace('_', ' ').title()}: {item_count}"
                                )

                    # Show distribution if available
                    if "distribution" in metric_data:
                        dist = metric_data["distribution"]
                        print(f"        Distribution: {dist}")

    # File-level hotspots
    print("\n3. FILE HOTSPOTS (Top 10 Issues)")
    print("=" * 50)
    file_insights = insights["file_level_insights"][:10]

    if file_insights:
        for i, file_insight in enumerate(file_insights, 1):
            file_path = file_insight["file_path"]
            total_issues = file_insight["total_issues"]
            metrics = file_insight["metrics"]

            print(f"\n{i}. {file_path} ({total_issues} issues)")
            for issue_type, count in metrics.items():
                if count > 0:
                    print(f"   • {issue_type.replace('_', ' ').title()}: {count}")
    else:
        print("No major file-specific issues found!")

    # Summary insights and recommendations
    print("\n4. KEY INSIGHTS & RECOMMENDATIONS")
    print("=" * 50)

    # Dead code analysis
    maint_metrics = insights["characteristics"]["maintainability"]["metrics"]
    if "dead_code" in maint_metrics and maint_metrics["dead_code"]["count"] > 0:
        dead_code = maint_metrics["dead_code"]
        print(
            f"• Clean up {dead_code['count']} dead code items ({dead_code['rate']:.2%} of your codebase)"
        )
        breakdown = dead_code["breakdown"]
        if breakdown["unused_functions"] > 0:
            print(f"  - Remove {breakdown['unused_functions']} unused functions")
        if breakdown["unused_variables"] > 0:
            print(f"  - Remove {breakdown['unused_variables']} unused variables")

    # Security analysis
    security_metrics = insights["characteristics"]["security"]["metrics"]
    if (
        "security_antipatterns" in security_metrics
        and security_metrics["security_antipatterns"]["count"] > 0
    ):
        security = security_metrics["security_antipatterns"]
        print(f"• Fix {security['count']} security vulnerabilities")
        breakdown = security["breakdown"]
        for vuln_type, count in breakdown.items():
            if count > 0:
                print(f"  - Address {count} {vuln_type.replace('_', ' ')} issues")

    # Performance analysis
    perf_metrics = insights["characteristics"]["performance"]["metrics"]
    total_perf_issues = sum(
        metric.get("count", 0)
        for metric in perf_metrics.values()
        if isinstance(metric, dict)
    )
    if total_perf_issues > 0:
        print(f"• Optimize {total_perf_issues} performance bottlenecks")
        for metric_name, metric_data in perf_metrics.items():
            if isinstance(metric_data, dict) and metric_data.get("count", 0) > 0:
                print(
                    f"  - Fix {metric_data['count']} {metric_name.replace('_', ' ')} issues"
                )

    print("\n5. RATE COMPARISON (Issues per unit)")
    print("=" * 50)
    print(
        "Dead Code Rate:",
        f"{maint_metrics.get('dead_code', {}).get('rate', 0):.3f} per code structure",
    )
    print(
        "Security Issues Rate:",
        f"{security_metrics.get('security_antipatterns', {}).get('rate', 0):.3f} per 1000 lines",
    )
    print(
        "Performance Issues Rate:",
        f"{sum(m.get('rate', 0) for m in perf_metrics.values() if isinstance(m, dict)):.3f} per loop",
    )

    # Test with different configurations
    print("\n6. CONFIGURATION COMPARISON")
    print("=" * 50)

    # Test without rates
    insights_no_rates = get_rich_insights(
        "sample_project", include_rates=False, include_distributions=False
    )
    print("✓ Analysis without rates and distributions completed")

    # Test with different parameters
    insights_rates_only = get_rich_insights(
        "sample_project", include_rates=True, include_distributions=False
    )
    print("✓ Analysis with rates only completed")

    print("\n=== DEMO COMPLETED SUCCESSFULLY ===")
    print(f"Total characteristics analyzed: {len(insights['characteristics'])}")
    print(f"Total files assessed: {len(insights['file_level_insights'])}")
    print("Rich insights provide actionable feedback for code quality improvement!")


if __name__ == "__main__":
    main()
