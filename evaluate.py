import os
import json
from typing import Dict, Any
from prompts.core_prompt import *
from utils.model_utils import *

def evaluate_reports():
    """Evaluate the reports in the report directory and generate statistics."""
    report_dir = "report"
    
    # Initialize counters
    stats = {
        "total_reports": 0,
        "malicious": 0,
        "benign": 0,
        "anomalous": 0,
        "parse_errors": 0,
        "unknown_categories": 0
    }
    
    # Get all report files
    if not os.path.exists(report_dir):
        print(f"Report directory '{report_dir}' not found")
        return stats
    
    report_files = [f for f in os.listdir(report_dir) if f.endswith('.json')]
    stats["total_reports"] = len(report_files)
    
    # Process each report file
    for report_file in report_files:
        try:
            with open(os.path.join(report_dir, report_file), 'r', encoding='utf-8') as f:
                try:
                    report_content = json.load(f)
                    category = report_content.get("category", "unknown")
                    
                    # Count the category
                    if category in stats:
                        stats[category] += 1
                    else:
                        stats["unknown_categories"] += 1
                except json.JSONDecodeError:
                    stats["parse_errors"] += 1
                    print(f"Error parsing JSON in file: {report_file}")
                except Exception as e:
                    stats["parse_errors"] += 1
                    print(f"Error processing file {report_file}: {str(e)}")
        except IOError as e:
            stats["parse_errors"] += 1
            print(f"Error reading file {report_file}: {str(e)}")
    
    # Print statistics
    print("\nReport Statistics:")
    print(f"Total reports: {stats['total_reports']}")
    print(f"Malicious: {stats['malicious']} ({(stats['malicious']/stats['total_reports']*100):.1f}%)")
    print(f"Benign: {stats['benign']} ({(stats['benign']/stats['total_reports']*100):.1f}%)")
    print(f"Anomalous: {stats['anomalous']} ({(stats['anomalous']/stats['total_reports']*100):.1f}%)")
    print(f"Unknown categories: {stats['unknown_categories']}")
    print(f"Parse errors: {stats['parse_errors']}")
    
    return stats

def test_prompt():
    reportResult_tmp = [{"result": "anomalous", "position": "body_params.modo[0]", "statement": "registro", "cause": "Unexpected value 'registro' found in mode parameter. Expected values are 'editar', 'alta', and 'baja'."}]
    prompt_report_audit = report_audit_prompt_v1.replace("{reportResult}", str(reportResult_tmp))
    print(prompt_report_audit)
    response_report_audit = model.invoke(prompt_report_audit)
    print("report_audit response:")
    print(response_report_audit)
if __name__ == "__main__":
    test_prompt()
