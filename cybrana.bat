@echo off
set "custom_yaml_dir=%1"

python rfModelCreate.py
python rfPredict.py log_predictor.joblib

set "YARACONV=false"

for /r %%I in (*.yar) do (
    echo .YAR file found at %%I
    python YARA2YAML.py --filename "%%I"
    set "YARACONV=true"
)

git clone https://github.com/projectdiscovery/nuclei-templates.git
cd nuclei-templates || exit
ren http yaml-templates
for /d %%D in (*) do if not "%%D"=="yaml-templates" rd /s /q "%%D"
move yaml-templates ..
cd ..
rd /s /q nuclei-templates

if "%YARACONV%"=="true" (
    if not "%custom_yaml_dir%"=="" (
        python capecMapper.py --nuclei "yaml-templates" --custom "%custom_yaml_dir%" --yara "converted-yaml"
        python yaraMatch.py --nuclei "yaml-templates" --output "forScoring.csv" --custom "%custom_yaml_dir%" --yara "converted-yaml"
    ) else (
        python capecMapper.py --nuclei "yaml-templates" --yara "converted-yaml"
        python yaraMatch.py --nuclei "yaml-templates" --output "forScoring.csv" --yara "converted-yaml"
    )
) else (
    if not "%custom_yaml_dir%"=="" (
        python capecMapper.py --nuclei "yaml-templates" --custom "%custom_yaml_dir%"
        python yaraMatch.py --nuclei "yaml-templates" --output "forScoring.csv" --custom "%custom_yaml_dir%"
    ) else (
        python capecMapper.py --nuclei "yaml-templates"
        python yaraMatch.py --nuclei "yaml-templates" --output "forScoring.csv"
    )
)

python capec2CWE.py --capec "capec_data.json" --file "capec_table.csv"
python CWE2CVE.py --cwe "cwe_data.json" --file "capec_table.csv"
python CVE2CVSS.py --file "capec_table.csv"
python mapCVSS.py --input "forScoring.csv" --mitre "capec_table.csv"
python dashGen.py --filename "cvssScored.csv"

del cvssScored.csv forScoring.csv capec_table.csv
rmdir /s /q "converted-yaml"
