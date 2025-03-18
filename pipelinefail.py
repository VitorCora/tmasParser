import argparse
import json
import sys

def load_json(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: The file '{filename}' is not a valid JSON file.")
        sys.exit(1)

def check_thresholds(data, args):
    findings = []
    thresholds_met = False

    if args.critical and data['vulnerabilities']['criticalCount'] > 0:
        findings.append('Critical vulnerabilities found')
        thresholds_met = True
    if args.critical_unmitigated and data['vulnerabilities']['critical-no-fix'] > 0:
        findings.append('Unmitigated critical vulnerabilities found')
        thresholds_met = True
    if args.high and data['vulnerabilities']['highCount'] > 0:
        findings.append('High vulnerabilities found')
        thresholds_met = True
    if args.high_unmitigated and data['vulnerabilities']['high-no-fix'] > 0:
        findings.append('Unmitigated high vulnerabilities found')
        thresholds_met = True
    if args.medium and data['vulnerabilities']['mediumCount'] > 0:
        findings.append('Medium vulnerabilities found')
        thresholds_met = True
    if args.medium_unmitigated and data['vulnerabilities']['medium-no-fix'] > 0:
        findings.append('Unmitigated medium vulnerabilities found')
        thresholds_met = True
    if args.low and data['vulnerabilities']['lowCount'] > 0:
        findings.append('Low vulnerabilities found')
        thresholds_met = True
    if args.low_unmitigated and data['vulnerabilities']['low-no-fix'] > 0:
        findings.append('Unmitigated low vulnerabilities found')
        thresholds_met = True
    if args.malware and data['malware'] > 0:
        findings.append('Malware detected')
        thresholds_met = True
    if args.secrets and data['secrets'] > 0:
        findings.append('Unmitigated secrets found')
        thresholds_met = True

    return findings, thresholds_met

def main():
    parser = argparse.ArgumentParser(description='Pipeline fail script based on security findings.')
    parser.add_argument('--critical', type=bool, default=False, help='Fail on critical vulnerabilities')
    parser.add_argument('--critical-unmitigated', type=bool, default=False, help='Fail on unmitigated critical vulnerabilities')
    parser.add_argument('--high', type=bool, default=False, help='Fail on high vulnerabilities')
    parser.add_argument('--high-unmitigated', type=bool, default=False, help='Fail on unmitigated high vulnerabilities')
    parser.add_argument('--medium', type=bool, default=False, help='Fail on medium vulnerabilities')
    parser.add_argument('--medium-unmitigated', type=bool, default=False, help='Fail on unmitigated medium vulnerabilities')
    parser.add_argument('--low', type=bool, default=False, help='Fail on low vulnerabilities')
    parser.add_argument('--low-unmitigated', type=bool, default=False, help='Fail on unmitigated low vulnerabilities')
    parser.add_argument('--malware', type=bool, default=False, help='Fail on malware detection')
    parser.add_argument('--secrets', type=bool, default=False, help='Fail on unmitigated secrets')
    parser.add_argument('--input', type=str, required=True, help='Input JSON file')

    args = parser.parse_args()

    data = load_json(args.input)
    findings, thresholds_met = check_thresholds(data, args)

    if not any([args.critical, args.critical_unmitigated, args.high, args.high_unmitigated, args.medium, args.medium_unmitigated, args.low, args.low_unmitigated, args.malware, args.secrets]):
        print("Findings:")
        print(json.dumps(data, indent=4))
        print("No thresholds provided. Running pipeline.")
        sys.exit(0)

    if thresholds_met:
        print("Thresholds met:")
        for finding in findings:
            print(f"- {finding}")
        print("Failing the pipeline.")
        sys.exit(1)
    else:
        print("No thresholds met. Running pipeline.")
        sys.exit(0)

if __name__ == "__main__":
    main()
