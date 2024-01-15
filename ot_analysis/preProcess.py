import os
import pandas as pd
import dpkt
from tqdm import tqdm
from more_itertools import chunked
from datetime import datetime

MODBUS_PORT = 502
CHUNK_SIZE = 1000000

class ModBusTCP(dpkt.Packet):
    __hdr__ = (('id', 'H', 0),
               ('proto', 'H', 0),
               ('len', 'H', 0),
               ('ui', 'B', 0),
               ('fc', 'B', 0))

def process_packets(packet_batch):
    packet_infos = []

    for ts, buf in packet_batch:
        eth = dpkt.ethernet.Ethernet(buf)

        # Check if the packet has an IP layer
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data

            # Check if the IP packet is TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                protocol = ip.get_proto(ip.p).__name__

                # Extracting common fields
                packet_info = {
                    "Source IP": dpkt.utils.inet_to_str(ip.src),
                    "Source Port": tcp.sport,
                    "Destination IP": dpkt.utils.inet_to_str(ip.dst),
                    "Destination Port": tcp.dport,
                    "Protocol": protocol.upper(),  # Assuming it's TCP for now
                    "Timestamp": datetime.utcfromtimestamp(ts).strftime('%d/%m/%Y %H:%M:%S.%f')[:-3],
                    "Flags": tcp.flags
                }

                # Extracting TCP-specific fields
                packet_info["Source Port"] = tcp.sport
                packet_info["Destination Port"] = tcp.dport
                packet_info["Flags"] = tcp.flags

                # Check if it's a MODBUS packet
                if tcp.sport == MODBUS_PORT or tcp.dport == MODBUS_PORT:
                    # Assuming MODBUS port for now, replace with actual MODBUS port
                    modbus_data = tcp.data

                if tcp.data:
                    # Check if it's a MODBUS packet
                    if packet_info["Source Port"] == MODBUS_PORT or packet_info["Destination Port"] == MODBUS_PORT:
                        modtcp = ModBusTCP(tcp.data)
                        if modtcp.fc < 255 and modtcp.proto == 0:
                            packet_info['Unit ID'] = modtcp.ui
                            packet_info['Modbus Function'] = modtcp.fc

                packet_infos.append(packet_info)

    return packet_infos

def process_pcap(file_path):
    data = []

    # Process packets in batches
    batch_size = 1000
    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        total_packets = sum(1 for _ in pcap)

    with tqdm(total=total_packets, desc=os.path.basename(file_path), unit="packets") as pbar:
        with open(file_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            packet_batches = [list(batch) for batch in chunked(pcap, batch_size)]

        for packet_batch in packet_batches:
            result = process_packets(packet_batch)
            data.extend(result)
            pbar.update(len(data))

    return data

def combine_pcaps(directory):
    df_list = []
    files_list = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".pcap"):
                file_path = os.path.join(root, file)
                files_list.append(file_path)

    with tqdm(total=len(files_list), desc="Total Progress", unit="files") as pbar:
        for file_path in files_list:
            data = process_pcap(file_path)
            if data:
                df_list.extend(data)  # Accumulate the data
            pbar.update(1)

    if df_list:
        combined_df = pd.DataFrame(df_list)
        pbar.close()
        return combined_df
    else:
        print("No PCAP files found in the specified directory.")
        return None

if __name__ == "__main__":
    pcap_directory = r"input_pcap\attack\compromised-ied\ied1a\ied1a-network-captures"  # Change this to your directory path
    combined_dataframe = combine_pcaps(pcap_directory)

    if combined_dataframe is not None:
        print("Sample Data:")
        print(combined_dataframe.sample(20))  # Print a sample of 20 rows

        # Export the combined DataFrame to a single CSV file
        output_path = os.path.join(pcap_directory, "combined_data.csv")
        combined_dataframe.to_csv(output_path, index=False)

        print(f"Combined DataFrame exported to {output_path}")
    else:
        print("No PCAP files found in the specified directory.")
