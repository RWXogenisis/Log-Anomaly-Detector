import os
import json
import yaml
from fuzzywuzzy import fuzz
import argparse

# Load the MITRE CAPEC data
with open('capec_data.json', 'r', encoding="UTF-8") as json_file:
    mitre_data = json.load(json_file)


# Define security-related keywords to look for
security_keywords = [
    "XSS", "cross-site", "scripting", "SQL", "injection", "vulnerability", "exploit", "attack", "malware", "threat",
    "firewall", "encryption", "authentication", "authorization", "cybersecurity", "phishing", "ransomware", "payload",
    "zero-day", "backdoor", "payload", "botnet", "DDoS", "Trojan", "hacker", "pentesting", "cyberattack", "exploitation",
    "intrusion", "keylogger", "sandbox", "security", "privacy", "breach", "compromise", "hash", "reconnaissance",
    "mitigation", "virus", "worm", "sniffing", "spoofing", "fingerprinting", "network", "endpoint", "hijacking",
    "patching", "cybercrime", "cyberthreat", "cyberdefense", "cyberwarfare", "cyberincident", "exploitable", "SSL",
    "TLS", "two-factor", "access control", "security policy", "threat intelligence", "forensics", "payload", "sandboxing",
    "man-in-the-middle", "security posture", "web application firewall", "secure coding", "risk assessment", "secure socket",
    "security patch", "vulnerability scanner", "security architecture", "security analyst", "security operations",
    "information security", "data breach", "identity theft", "secure communication", "secure network", "intrusion detection",
    "incident response", "data protection", "cybersecurity hygiene", "security awareness", "cloud security", "endpoint security",
    "data security", "threat detection", "security audit", "firewall rule", "malicious code", "security incident",
    "secure configuration", "security assessment", "security measure", "security control", "threat modeling", "security risk",
    "security framework", "security standard", "network security", "application security", "password security",
    "secure software development"
]

# Function to find the MITRE CAPEC tactic based on security-related keywords
def find_mitre_tactic(title, description, mitre_data, security_keywords):
    # Tokenize YAML description and filter for security-related keywords
    description_lower = description.lower()
    yaml_description_tokens = [word for word in description_lower.replace('.', ' ').split() if word in security_keywords]

    max_similarity = 0
    tactic_found = None

    for tactic in mitre_data:
        tactic_title = tactic.get('Attack Name', '').lower()  # Get the title of the tactic
        tactic_description = tactic.get('Description', '').lower()  # Get the description of the tactic

        title_similarity = fuzz.token_sort_ratio(title.lower(), tactic_title)
        desc_similarity = fuzz.token_sort_ratio(description_lower, tactic_description)

        overall_similarity = (title_similarity + desc_similarity) / 2

        if overall_similarity > max_similarity and overall_similarity > 80:
            max_similarity = overall_similarity
            tactic_found = tactic

        tactic_description_tokens = [word for word in tactic_description.replace('.', ' ').split() if word in security_keywords]

        for word in yaml_description_tokens:
            if word in tactic_description_tokens:
                return {"tactic": tactic, "similarity": title_similarity}

    return tactic_found

def find_tactic(title: str, desc: str, mitre_data, security_keywords):
    matched_tactic = find_mitre_tactic(title, desc, mitre_data, security_keywords)

    if matched_tactic:
        print(f"The YAML rule matches the MITRE CAPEC tactic:")
        print(f"Title: {matched_tactic.get('Attack Name')}")
        print(f"Description: {matched_tactic.get('Description')}")
        return matched_tactic
    else:
        print("No matching MITRE CAPEC tactic found for the YAML rule based on security-related keywords.")
        return None

def main(directories: list):
    # Load the MITRE CAPEC data
    with open('capec_data.json', 'r', encoding="UTF-8") as json_file:
        mitre_data = json.load(json_file)

    yaml_rules = []

    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.yaml') or file.endswith('.yml'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as yaml_file:
                            rule = yaml.safe_load(yaml_file)
                            if rule:
                                yaml_rules.append(rule)
                            else:
                                print(f"Error loading YAML file '{file_path}': Empty or invalid YAML content")
                    except Exception as e:
                        print(f"Error loading YAML file '{file_path}': {e}")

    for rule in yaml_rules:
        http_title = rule.get('info', {}).get('name', '')
        http_description = rule.get('info', {}).get('description', '')

        matched_tactic = find_tactic(http_title, http_description, mitre_data, security_keywords)
        if matched_tactic:
            rule.update({"CAPEC Tactic": matched_tactic.get("Attack ID"), "CWEs": matched_tactic.get("Related Weaknesses")})

    with open("capecMap.json", "w") as f:
        json.dump(yaml_rules, f, indent=4)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process directories containing YAML files')
    parser.add_argument('directories', metavar='dir', type=str, nargs='+',
                        help='Directories containing YAML files')
    args = parser.parse_args()

    main(args.directories)