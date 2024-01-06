import csv
import yaml
import os
import argparse
import json

# Function to parse command line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='Process YAML rules and log entries.')
    parser.add_argument('--nuclei', type=str, help='Directory containing YAML files')
    parser.add_argument('--output', type=str, help='Output file for scoring')
    parser.add_argument('--custom', type=str, help='Custom YAML directory')
    parser.add_argument('--yara', type=str, help='Directory containing converted YAML files')
    return parser.parse_args()

# Function to load YAML files recursively from a directory
def load_yaml_rules(directory):
    yaml_rules = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.yaml') or file.endswith('.yml'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as yaml_file:
                        rule = yaml.safe_load(yaml_file)
                        yaml_rules.append(rule)
                except Exception as e:
                    print(f"Error loading YAML file '{file_path}': {e}")
    return yaml_rules

# Function to compare logs with YAML rules
def compare_logs_with_rules(logs, rules):
    matched_rules = []
    for log in logs:
        for rule in rules:
            print(json.dumps(rule, indent=4))
            print(saxsux)
            matchers = []
            score = 0
            try:
                if log['http_method'] == rule['http'][0]['method']:
                    score += 1
                    matchers.append({"type":"HTTP Method",
                                     "log":log['http_method'],
                                     "rule":rule['http'][0]['method']})
            except:
                pass
            
            # Compare resource path
            try:
                for path in rule['http'][0]['path']:
                    path = path.lower().replace(r"{{baseurl}}")
                    if log['resource_path'].lower() == path:
                        score += 1
                        matchers.append({"type":"Resource Path",
                                     "log":log['resource_path'],
                                     "rule":path})
            except:
                pass        
            
            # Compare HTTP version
            try:
                if log['http_version'] == 'HTTP/' + rule['http'][0].get('version', ''):
                    score += 1
                    matchers.append({"type":"HTTP Version",
                                     "log":log['http_version'],
                                     "rule":'HTTP/' + rule['http'][0].get('version', '')})

            except:
                pass

            # Compare status
            try:
                for status in rule['http'][0]['matchers']:
                    if int(log['status_code']) in status['status']:
                        score += 1
                        matchers.append({"type":"HTTP Status",
                                     "log":int(log['status_code']),
                                     "rule":status['status']})

            except:
                pass

            if score>=3:
                print(f"\nLog Entry: {log['resource_path']}\nRule ID: {rule.get('id')} | Score: {score}/4\n")

                matched_rule_entry = {
                    "Log Entry": log['resource_path'],
                    "Rule ID": rule.get('id'),
                    "Score": f"{score}/4"
                }
                matched_rules.append(matched_rule_entry)

    return matched_rules

# Main function
def main():
    args = parse_arguments()

    if args.nuclei and args.output and args.custom and args.yara:
        # Load YAML rules from the specified directories
        yaml_rules = load_yaml_rules(args.nuclei)
        custom_yaml_rules = load_yaml_rules(args.custom)
        yara_yaml_rules = load_yaml_rules(args.yara)

        # Combining all loaded rules into one list
        all_rules = yaml_rules + custom_yaml_rules + yara_yaml_rules

        # Load log entries
        log_entries = []
        with open('server_logs.csv', 'r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                log_entries.append(row)

        # Compare logs with all loaded YAML rules
        compare_logs_with_rules(log_entries, all_rules)

        # Output the scoring results to the specified file (args.output)
        with open(args.output, 'w', newline='', encoding='utf-8') as output_file:
            fieldnames = ["Log Entry", "Rule ID", "Score"]
            writer = csv.DictWriter(output_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(matched_rules_list)

    else:
        print("Please provide all necessary arguments.")

if __name__ == "__main__":
    main()
