from pycq_analyzer import get_rich_insights

# Test the rich insights function
print("Testing get_rich_insights...")
insights = get_rich_insights("sample_project", verbose=False)

print("\n=== RICH INSIGHTS RESULTS ===")
print(f"Overall quality score: {insights['overall_metrics']['quality_score']:.2f}")
print(f"Total files: {insights['overall_metrics']['total_files']}")
print(f"Total functions: {insights['overall_metrics']['total_functions']}")
print(f"Total classes: {insights['overall_metrics']['total_classes']}")

print("\n=== ISSUES BY CHARACTERISTIC ===")
for char, data in insights["characteristics"].items():
    print(
        f"{char.capitalize()}: {data['total_issues']} issues (Score: {data['score']:.2f})"
    )
    if "metrics" in data:
        for metric_name, metric_data in data["metrics"].items():
            if isinstance(metric_data, dict) and "count" in metric_data:
                count = metric_data["count"]
                rate = metric_data.get("rate", "N/A")
                print(f"  - {metric_name}: {count} issues (Rate: {rate})")

print(f"\n=== FILE HOTSPOTS ===")
print("Files with highest issue counts:")
for file_insight in insights["file_level_insights"][:5]:  # Top 5
    print(f"  {file_insight['file_path']}: {file_insight['total_issues']} total issues")
    for issue_type, count in file_insight["metrics"].items():
        if count > 0:
            print(f"    - {issue_type}: {count}")

print("\n=== DETAILED BREAKDOWN EXAMPLE ===")
if "maintainability" in insights["characteristics"]:
    maint = insights["characteristics"]["maintainability"]["metrics"]
    if "dead_code" in maint:
        dead_code = maint["dead_code"]
        print(f"Dead code breakdown: {dead_code['breakdown']}")
    if "complexity" in maint and "distribution" in maint["complexity"]:
        complexity_dist = maint["complexity"]["distribution"]
        print(f"Complexity distribution: {complexity_dist}")

print("\nTest completed successfully!")
