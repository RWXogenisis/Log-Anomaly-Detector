import csv
import json
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd

# JSON to CSV conversion
action_mapping = {
    '\"timeout\"': 1,
    '\"roll-log\"': 2,
    '\"dropped\"': 3,
    '\"ip-conn\"': 4,
    '\"dns\"': 5,
    '\"deny\"': 6,
    '\"accept\"': 7,
    '\"server-rst\"': 8,
    '\"alert-email\"': 9,
    '\"client-rst\"': 10,
    '\"perf-stats\"': 11,
    '\"close\"': 12
}

with open('intersection.txt', 'r') as headers_file:
    headers = headers_file.read().strip().split(',')

with open('output.json', 'r') as json_file:
    data = json.load(json_file)

def process_timestamp(timestamp):
    datetime_obj = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    new_time_obj = datetime_obj + timedelta(hours=5, minutes=30)  # Adjusting for the UTC+5 timezone
    formatted_datetime = new_time_obj.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Remove milliseconds
    return formatted_datetime

with open('output.csv', 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    updated_headers = [header if header != 'datetimestamp' else 'datetime' for header in headers]
    csv_writer.writerow(updated_headers)

    for item in data:
        if 'datetimestamp' in item:
            new_time_string = process_timestamp(item['datetimestamp'])
            item['datetime'] = new_time_string
        row = [str(item.get(header, 0)).rstrip('\"').lstrip('\"') for header in updated_headers]
        action_value = item.get('action', '')
        mapped_action = action_mapping.get(action_value, action_value)
        row[updated_headers.index('action')] = mapped_action
        csv_writer.writerow(row)

# Traffic Profiling
def traffic_profile(csv_file_path, output_file_path):
    df = pd.read_csv(csv_file_path)
    df['datetime'] = pd.to_datetime(df['datetime'])
    df.set_index('datetime', inplace=True)
    logs_per_minute = df.resample('T').size()
    mean_count = logs_per_minute.mean()
    with open(output_file_path, 'w') as file:
        file.write(f"Mean logs count per minute: {mean_count}\n\n")

        file.write("Logs Count per Minute:\n")
        file.write(logs_per_minute.to_string())

traffic_profile('output.csv', 'traffic_profile.txt')

# DDoS Attacks
csv_file_path = 'output.csv'
ip_request_count = defaultdict(int)
threshold = 20
time_window = 0.0001
ddos_ports = {'1433', '1434', '3306'}

def check_ddos_attack(fields):
    src_ip = fields.get('srcip')
    src_port = fields.get('srcport')
    dst_port = fields.get('dstport')

    datetime_str = f"{fields['datetime']}"
    current_time = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S.%f')
    
    with open('DDos.txt', 'a') as file:
        if src_ip in ip_request_count:
            last_time = ip_request_count[src_ip]
            if (current_time - last_time) < timedelta(seconds=time_window):
                file.write(f"Potential DDoS attack detected from {src_ip} at {current_time}\n")
        else:
            ip_request_count[src_ip] = current_time
    
        if src_port in ddos_ports or dst_port in ddos_ports:
            file.write(f"Potential DDoS attack detected with port {src_port}/{dst_port} at {current_time}\n")

        for ip, last_time in list(ip_request_count.items()):
            if (current_time - last_time) > timedelta(seconds=time_window):
                del ip_request_count[ip]

with open(csv_file_path, 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    header = next(csv_reader)
    for row in csv_reader:
        log_entry = dict(zip(header, row))
        check_ddos_attack(log_entry)

# Anomaly Detection
def anomaly_detection():
    df = pd.read_csv('output.csv')
    df['datetime'] = pd.to_datetime(df['datetime'])
    not_india_activity = df[(df['datetime'].dt.hour >= 0) & (df['datetime'].dt.hour < 6) & (df['srccountry'] != 'India')]
    request_counts = not_india_activity['srcip'].value_counts()
    abnormal_spikes = request_counts[request_counts > request_counts.mean() + 2 * request_counts.std()]
    response_changes = df[df['action'].diff() != 0]
    hostile_countries = ['Pakistan', 'China']
    hostile_activity = df[df['dstcountry'].isin(hostile_countries)]

    with open('anomaly.txt', 'a') as file:
        file.write("Abnormal Spikes in Requests:\n")
        file.write(str(abnormal_spikes) + '\n\n')

        file.write("Unusual High-level Activity from Hostile Countries:\n")
        file.write(str(hostile_activity) + '\n')


anomaly_detection()

# APT Detection
def check_apt_signs(fields):
    with open('apt.txt', 'a') as file:
        # Unusual user behavior
        if fields.get('action') == '1' and fields.get('datetime').split(' ')[1].split(':')[0] in ['18', '19', '20', '21', '22', '23', '00', '01', '02', '03', '04', '05']:
            file.write(f"Unusual user behavior detected from {fields['srcip']} at {fields['datetime']}\n")

        # Sizable movement of data
        if fields.get('action') in ['4', '5', '6', '7', '8'] and int(fields.get('sentbyte')) > 1000000:
            file.write(f"Sizable movement of data detected from {fields['srcip']} to {fields['dstip']} at {fields['datetime']}\n")

        # Backdoor trojans
        if fields.get('action') == '3':
            file.write(f"Backdoor Trojan detected from {fields['srcip']} to {fields['dstip']} at {fields['datetime']}\n")

        # Unusual data files
        if fields.get('action') in ['4', '5', '6', '7', '8'] and int(fields.get('sentbyte')) > 500000 and fields.get('duration') == '0':
            file.write(f"Unusual data files detected from {fields['srcip']} to {fields['dstip']} at {fields['datetime']}\n")

# Iterate through the CSV data and check for APT signs
with open(csv_file_path, 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    header = next(csv_reader)
    for row in csv_reader:
        log_entry = dict(zip(header, row))
        check_apt_signs(log_entry)

