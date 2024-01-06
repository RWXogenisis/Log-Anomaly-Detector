# CYBRANA: Cyber YARA/YAML-Based Resilience Applied with Next-Gen A.I 
## A comprehensive Firewall Solution.

Welcome to CYBRANA! This repository contains a powerful toolkit designed to analyze log files comprehensively and generate an insightful HTML-based dashboard report. Below is an in-depth breakdown of the repository's components:

## Files Overview

### `cybrana.sh` / `cybrana.bat`

The `cybrana.sh` script (for Unix-based systems) or `cybrana.bat` script (for Windows systems) serves as the central orchestrator for log analysis, modeling, rule matching, vulnerability assessment, and report generation.

### Python Scripts

1. **`rfModelCreate.py`**: This script facilitates the creation of a RandomForest model based on historical log data. The model generated serves as a predictive tool for log analysis.

2. **`rfPredict.py`**: Utilizing the previously generated RandomForest model, this script predicts log data, enabling the identification of potential anomalies or irregularities.

3. **`YARA2YAML.py`**: Converts YARA rules to YAML format, facilitating better rule organization and consolidation for efficient matching.

4. **`capecMapper.py`**: Performs MITRE CAPEC (Common Attack Pattern Enumeration and Classification) mapping, linking potential attack patterns to identified vulnerabilities.

5. **`yaraMatch.py`**: Matches YAML-formatted rules with log data, enhancing the accuracy of threat identification and classification.

6. **`capec2CWE.py`**: Maps identified CAPEC entries to CWE (Common Weakness Enumeration), providing a broader context to vulnerabilities.

7. **`CWE2CVE.py`**: Establishes mappings from CWE entries to CVE (Common Vulnerabilities and Exposures), aiding in specific vulnerability identification.

8. **`CVE2CVSS.py`**: Calculates CVSS (Common Vulnerability Scoring System) scores based on CVE entries, quantifying their severity and impact.

9. **`mapCVSS.py`**: Maps and processes calculated CVSS scores, enabling efficient classification and prioritization of vulnerabilities.

10. **`dashGen.py`**: Employs the processed data to generate a comprehensive HTML-based dashboard, visually presenting the identified threats, vulnerabilities, and their respective scores.

11. **`log_predictor.joblib`**: A model file utilized specifically for log prediction purposes within the CYBRANA framework.

## Usage

### Running the Analysis

1. **Python 3 Requirement**: Ensure Python 3 is installed on your system to execute the CYBRANA toolkit.

2. **Execution Instructions**:
   
   Execute the `cybrana.sh` script (for Unix) or `cybrana.bat` script (for Windows) using the following command structure:
   
   ```bash
   ./cybrana.sh <custom_yaml_dir>
   ```
   
   Replace `<custom_yaml_dir>` with the directory path containing any custom YAML files. If not using custom YAML files, simply omit `<custom_yaml_dir>` from the command.

### Generating the Dashboard Report

Upon successful execution of the script, the CYBRANA toolkit progresses through the following steps:

- Processing and analysis of log data.
- Execution of predictive models for log data prediction.
- Conversion and consolidation of YARA rules to YAML format.
- Matching YAML rules with log data.
- MITRE CAPEC mapping for identified vulnerabilities.
- Mapping of CAPEC entries to CWE and CWE to CVE for comprehensive vulnerability identification.
- Calculation and processing of CVSS scores.
- Generation of an informative and visually appealing HTML-based dashboard report (`dashboard.html`).

## To-Do List

- Stateful Inspection
- Dashboard + SIEM
- Update AI Accuracy with better Datasets
- Polishing Work
- Self-Feedback Mechanism: Induction with Experimentation
- LLM to generate reports using "xAI and NLP"
