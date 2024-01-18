import psycopg2
import csv
from datetime import datetime, timedelta
from collections import defaultdict
from ip2geotools.databases.noncommercial import DbIpCity

# Establishing the connection
conn = psycopg2.connect(
    database="cybrana", user='postgres', password='inr_db', host='intellx.in', port='5432'
)
# Setting auto commit to true
conn.autocommit = True

# Creating a cursor object using the cursor() method
cursor = conn.cursor()

# DDoS Attacks
csv_file_path = 'output.csv'
ip_request_count = defaultdict(int)
threshold = 20
time_window = 0.0001
ddos_ports = {'1433', '1434', '3306'}

sql_query = '''
    INSERT INTO ngfw(latitude, longitude, srcip, timestamp, requests, apt_type, type) 
    VALUES (%s, %s, %s, %s, %s, %s, %s)
'''

def check_ddos_attack(fields):
    src_ip = fields.get('srcip')

    datetime_str = f"{fields['datetime']}"
    current_time = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S.%f')
    
    if src_ip in ip_request_count:
        last_time = ip_request_count[src_ip]
        if (current_time - last_time) < timedelta(seconds=time_window):
            res = DbIpCity.get(src_ip, api_key="free")
            latitude = res.latitude
            longitude = res.longitude
            print(last_time)
            cursor.execute(sql_query, (latitude, longitude, src_ip, current_time, 0, None, 'DDos'))
    else:
        ip_request_count[src_ip] = current_time

    for ip, last_time in list(ip_request_count.items()):
        if (current_time - last_time) > timedelta(seconds=time_window):
            del ip_request_count[ip]

# Open CSV file and read rows
with open(csv_file_path, 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    header = next(csv_reader)
    for row in csv_reader:
        log_entry = dict(zip(header, row))
        check_ddos_attack(log_entry)

# Closing the connection
conn.close()
