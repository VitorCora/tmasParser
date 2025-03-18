import json
import argparse

def parse_json(file_path):
    # Load JSON data from the file
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    # Extract vulnerabilities information
    vulnerabilities = data.get('vulnerabilities', {})
    total_vuln_count = vulnerabilities.get('totalVulnCount', 0)
    critical_count = vulnerabilities.get('criticalCount', 0)
    high_count = vulnerabilities.get('highCount', 0)
    medium_count = vulnerabilities.get('mediumCount', 0)
    low_count = vulnerabilities.get('lowCount', 0)
    negligible_count = vulnerabilities.get('negligibleCount', 0)
    unknown_count = vulnerabilities.get('unknownCount', 0)
    overridden_count = vulnerabilities.get('overriddenCount', 0)
    
    # Initialize fix counts
    critical_no_fix = critical_fixable = 0
    high_no_fix = high_fixable = 0
    medium_no_fix = medium_fixable = 0
    low_no_fix = low_fixable = 0
    
    # Count fixable and no-fix vulnerabilities
    findings = vulnerabilities.get('findings', {})
    for severity, findings_list in findings.items():
        for finding in findings_list:
            fix = finding.get('fix', 'not-fixed')
            if severity == "Critical":
                if fix == "not-fixed":
                    critical_no_fix += 1
                else:
                    critical_fixable += 1
            elif severity == "High":
                if fix == "not-fixed":
                    high_no_fix += 1
                else:
                    high_fixable += 1
            elif severity == "Medium":
                if fix == "not-fixed":
                    medium_no_fix += 1
                else:
                    medium_fixable += 1
            elif severity == "Low":
                if fix == "not-fixed":
                    low_no_fix += 1
                else:
                    low_fixable += 1
    
    # Extract malware information
    malware = data.get('malware', {})
    malware_scan_result = malware.get('scanResult', 0)
    
    # Extract secrets information
    secrets = data.get('secrets', {})
    unmitigated_findings_count = secrets.get('unmitigatedFindingsCount', 0)
    
    # Generate the output
    output = {
        "vulnerabilities": {
            "totalVulnCount": total_vuln_count,
            "criticalCount": critical_count,
            "critical-no-fix": critical_no_fix,
            "critical-fixable": critical_fixable,
            "highCount": high_count,
            "high-no-fix": high_no_fix,
            "high-fixable": high_fixable,
            "mediumCount": medium_count,
            "medium-no-fix": medium_no_fix,
            "medium-fixable": medium_fixable,
            "lowCount": low_count,
            "low-no-fix": low_no_fix,
            "low-fixable": low_fixable,
            "negligibleCount": negligible_count,
            "unknownCount": unknown_count,
            "overriddenCount": overridden_count
        },
        "malware": malware_scan_result,
        "secrets": unmitigated_findings_count
    }
    
    # Write the output to a JSON file
    with open('tmasParser_output.json', 'w') as outfile:
        json.dump(output, outfile, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse security-related JSON data.')
    parser.add_argument('-tmas', metavar='file', type=str, required=True, help='Path to the JSON file')
    args = parser.parse_args()

    parse_json(args.tmas)
