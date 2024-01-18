import psycopg2
import pandas as pd
import csv
from datetime import datetime, timedelta
from collections import defaultdict
from ip2geotools.databases.noncommercial import DbIpCity
import requests
import json

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

# NGFW Insert Query
sql_query = '''
    INSERT INTO ngfw(latitude, longitude, srcip, timestamp, requests, apt_type, type) 
    VALUES (%s, %s, %s, %s, %s, %s, %s)
'''

def check_apt_signs(fields):
    # Extracting date from datetime
    datetime_str = f"{fields['datetime'].split(' ')[0]}"
    res = DbIpCity.get(fields['srcip'], api_key="free")
    latitude = res.latitude
    longitude = res.longitude
    
    # Unusual user behavior
    if fields.get('action') == '1' and datetime_str.split('-')[1] in ['18', '19', '20', '21', '22', '23', '00', '01', '02', '03', '04', '05']:
        apt_type = 'Unusual User Behavior'
        anomaly_type = 'Anomaly'
        cursor.execute(sql_query, (latitude, longitude, fields['srcip'], datetime_str, 0, apt_type, anomaly_type))

    # Sizable movement of data
    if fields.get('action') in ['4', '5', '6', '7', '8'] and int(fields.get('sentbyte')) > 1000000:
        apt_type = 'Sizeable Movement of Data'
        anomaly_type = 'Anomaly'
        cursor.execute(sql_query, (latitude, longitude, fields['srcip'], datetime_str, 0, apt_type, anomaly_type))
    
    # Backdoor trojans
    if fields.get('action') == '3':
        # res = DbIpCity.get(fields['srcip'], api_key="free")
        apt_type = 'Backdoor Torjan'
        anomaly_type = 'Anomaly'
        cursor.execute(sql_query, (latitude, longitude, fields['srcip'], datetime_str, 0, apt_type, anomaly_type))

    # Unusual data files
    if fields.get('action') in ['4', '5', '6', '7', '8'] and int(fields.get('sentbyte')) > 500000 and fields.get('duration') == '0':
        # res = DbIpCity.get(fields['srcip'], api_key="free")
        apt_type = 'Unusual data files'
        anomaly_type = 'Anomaly'
        cursor.execute(sql_query, (latitude, longitude, fields['srcip'], datetime_str, 0, apt_type, anomaly_type))

# Iterate through the CSV data and check for APT signs
with open(csv_file_path, 'r') as csv_file:
    csv_reader = csv.reader(csv_file)
    header = next(csv_reader)
    for row in csv_reader:
        log_entry = dict(zip(header, row))
        check_apt_signs(log_entry)

# Closing the connection
conn.close()
