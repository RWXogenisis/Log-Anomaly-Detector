import os
import re
import yaml
import argparse

def convert2YAML(filename: str):
    # Load the YARA rules from the file
    with open(filename, 'r') as file:
        yara_rules = file.read()

    # Extracting YARA rules using regex
    rules = re.findall(r'rule\s+(\w+)\s*{([^}]*)}', yara_rules, re.MULTILINE | re.DOTALL)

    # Mapping of YARA rule fields to YAML structure
    yaml_rules = []
    for rule_name, rule_content in rules:
        rule_data = {'id': rule_name, 'info': {}}
        lines = rule_content.strip().split('\n')
        meta_info = {}
        strings_section = False
        for line in lines:
            line = line.strip()
            if line.startswith(('meta:', 'condition:', 'strings:')):
                if line.startswith('strings:'):
                    strings_section = True
                else:
                    strings_section = False
                continue
            if '=' in line and not strings_section:
                key, value = map(str.strip, line.split('=', 1))
                meta_info[key] = value.strip('" ')

        rule_data['info']['name'] = meta_info.get('description', '')
        rule_data['info']['author'] = meta_info.get('author', '')
        rule_data['info']['severity'] = meta_info.get('severity', '')
        rule_data['info']['description'] = meta_info.get('description', '')
        rule_data['info']['reference'] = [meta_info.get('reference', '')]
        rule_data['info']['metadata'] = {
            'cvss_score': meta_info.get('cvss_score', ''),
            'mitre_att': meta_info.get('mitre_att', '')
        }

        # Create a directory if it doesn't exist
        directory = 'converted-yaml'
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Write each rule into a separate YAML file
        yaml_file_path = os.path.join(directory, f"{rule_name}.yaml")
        with open(yaml_file_path, 'w') as yaml_file:
            yaml.dump([rule_data], yaml_file, default_flow_style=False)

    return directory

def main():
    parser = argparse.ArgumentParser(description='Convert YARA rules to YAML')
    parser.add_argument('--filename', type=str, help='Input file containing YARA rules', required=False)
    args = parser.parse_args()

    if args.filename:
        converted_directory = convert2YAML(args.filename)
        print(f"YARA rules converted to YAML and stored in directory: {converted_directory}")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
