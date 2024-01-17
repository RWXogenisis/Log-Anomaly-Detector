import pandas as pd
from tqdm import tqdm
from datetime import datetime
import statistics

# Step 1: Parse the CSV file into a DataFrame
csv_path = 'combined_data_short.csv'
print("Reading CSV...")
df = pd.read_csv(csv_path, delimiter=',', low_memory=True)

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
print("Identify attack scenarios based on the defined criteria")

iterated_unknown_IPs= []
# Group by and get counts
attack_scenarios = {
    "Write Attack":[],
    "Query Flooding":[],
    "Malicious Packet Crafting":[],
    "Baseline Replay Attack":[],
    "Reconnaissance":[]
}
# v=1 if 'Modbus Function' in 1,3,5,6
for index, row in df.iterrows():
    try:    
        if row['Modbus Function'] in [1,3,5,6]:
            attack_scenarios["Write Attack"].append(row)
            # print(row)
        elif row["Source IP"] not in known_ips and row["Source IP"] not in iterated_unknown_IPs:
            iterated_unknown_IPs.append(row["Source IP"])
            filtered_rows = df[(df["Source IP"] == row["Source IP"]) & (df["Destination IP"] == row["Destination IP"])]
            filtered_rows['Timestamp'] = pd.to_datetime(filtered_rows['Timestamp'], format='%d/%m/%Y %H:%M:%S.%f')
            time_difference = []
            for i in range(1, len(filtered_rows)):
                time_diff = filtered_rows.iloc[i]["Timestamp"] - filtered_rows.iloc[i-1]["Timestamp"]
                time_difference.append(time_diff)        

            # Check if the mode is less than 1 second
            if statistics.mode(time_difference).total_seconds() < 1:
                attack_scenarios["Query Flooding"].append(row)
        elif row["Source IP"] not in known_ips and row["Modbus Function"] == 1:
            attack_scenarios["Malicious Packet Crafting"].append(row)

        elif len(df["Source IP"]==row["Source IP"]) > 1 and row["Source IP"] not in known_ips and row["Source IP"] not in iterated_unknown_IPs:
            iterated_unknown_IPs.append(row["Source IP"])
            filtered_rows = df[(df["Source IP"] == row["Source IP"])]
            unique_destination_ips = set(filtered_rows['Destination IP'].unique())
            set_known_ips = set(known_ips)
            if len(set_known_ips.intersection(unique_destination_ips)) == len(known_ips):
                attack_scenarios["Reconnaissance"].append(row)
        else:
            # Group by and get counts, then transform to add the count column to each row
            df['Count'] = df.groupby(['Flags', 'Unit ID', 'Modbus Function'])['Flags'].transform('size')

            # Your condition for "Baseline Replay Attack"
            condition_replay_attack = (df['Count'] > 1) & ((df["Destination IP"].isin(known_ips)) | (df["Source IP"].isin(known_ips)))

            # Filter rows based on the condition
            filtered_rows_replay_attack = df[condition_replay_attack]

            # Append rows to the "Baseline Replay Attack" key in the attack_scenarios dictionary
            if not filtered_rows_replay_attack.empty:
                attack_scenarios["Baseline Replay Attack"].extend(filtered_rows_replay_attack.to_dict(orient='records'))
    except Exception as e:
        print(e)

    finally:
        if "filtered_rows" in locals():
            del filtered_rows
            print("Clearing filtered_rows")
        if "filtered_rows_replay_attack" in locals():
            del filtered_rows_replay_attack
            print("Clearing filtered_rows_replay_attack")
        if "time_difference" in locals():
            del time_difference
            print("Clearing time_difference")
        if "time_diff" in locals():
            del time_diff
            print("Clearing time_diff")
        if "condition_replay_attack" in locals():
            del condition_replay_attack
            print("Clearing condition_replay_attack")

        df = pd.DataFrame()
        df = pd.read_csv(csv_path, delimiter=',', low_memory=True)
        print("Resetting df")

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
