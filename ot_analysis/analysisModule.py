import pandas as pd
from tqdm import tqdm

# Step 1: Parse the CSV file into a DataFrame
csv_path = 'combined_data.csv'
print("Reading CSV...")
df = pd.read_csv(csv_path, delimiter=',', low_memory=False)

# Assuming your actual column names have spaces
df.columns = df.columns.str.strip()

# Display column names after stripping
print("Updated Column Names:")
print(df.columns)

# Display a sample of data from the DataFrame
sample_data = df.head()
print("Sample Data from DataFrame:")
print(sample_data)

# Step 2: Enumerate network actors (unique IPs) as nodes
print("Enumerate network actors (unique IPs) as nodes")
all_ips = set(df['Source IP']).union(set(df['Destination IP']))

# Sample list of known IPs (replace it with your actual list)
known_ips = set(['185.175.0.3', '185.175.0.4'])

# Classify IPs into trusted and untrusted
print("Classify IPs into trusted and untrusted")
df['Node Type'] = df['Source IP'].apply(lambda x: 'trusted' if x in known_ips else 'untrusted')

# Step 3: Shortlist packets sent to or received from untrusted nodes
print("Shortlist packets sent to or received from untrusted nodes")
untrusted_packets = df[df['Node Type'] == 'untrusted']

'''
FIX EVERYTHING BELOW!!
'''
# Step 4: Identify attack scenarios based on the defined criteria
# print("Identify attack scenarios based on the defined criteria")
# attack_scenarios = {
#     'Write Attack': (untrusted_packets['v'] == 1) & (untrusted_packets['Modbus Function'] == 'q'),
#     'Query Flooding': ((untrusted_packets['Unit ID'] == 'm') | (untrusted_packets['Unit ID'] == 's')) 
#                         & ((untrusted_packets['Modbus Function'] == 'Q') | (untrusted_packets['Modbus Function'] == 'R')),
#     'Malicious Packet Crafting': untrusted_packets['v'] == 1,
#     'Baseline Replay Attack': (untrusted_packets['v'] == 1) & (untrusted_packets['Modbus Function'] == 'q') 
#                                 & (untrusted_packets['Timestamp'].duplicated(keep=False)),
#     'Reconnaissance': (untrusted_packets['v'] == 0) & (untrusted_packets['Modbus Function'] == 'q')
# }

# Create a new column 'Attack Type' based on the identified attack scenarios
for attack_type, condition in tqdm(attack_scenarios.items(), desc="Identifying Attack Scenarios", unit="scenario"):
    untrusted_packets.loc[condition, 'Attack Type'] = attack_type

# Step 5: Identify all the attack log lines and store the data into an output CSV file
print("Identify all the attack log lines and store the data into an output CSV file")
attack_log_lines = untrusted_packets[untrusted_packets['Attack Type'].notna()]

# Save to CSV
output_csv_path = 'output_attack_log.csv'
print("Save to CSV")
attack_log_lines.to_csv(output_csv_path, index=False)

# Display completion message
print("Analysis complete. Results saved to", output_csv_path)
