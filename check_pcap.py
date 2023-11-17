from scapy.all import rdpcap, IP

def get_ips_facing_variable(pcap_file, ip_variable):
    """
    Returns a list of unique IP addresses that communicated with ip_variable.
    """
    packets = rdpcap(pcap_file)
    ips_facing_variable = set()

    for pkt in packets:
        if IP in pkt:
            if ip_variable == pkt[IP].src:
                ips_facing_variable.add(pkt[IP].dst)
            elif ip_variable == pkt[IP].dst:
                ips_facing_variable.add(pkt[IP].src)

    return list(ips_facing_variable)

def get_targets_of_variable(pcap_file, ip_variable):
    """
    Returns a list of unique IP addresses where ip_variable was the source.
    """
    packets = rdpcap(pcap_file)
    targets_of_variable = set()

    for pkt in packets:
        if IP in pkt and ip_variable == pkt[IP].src:
            targets_of_variable.add(pkt[IP].dst)

    return list(targets_of_variable)

# Example usage:
pcap_file = "C2Detective/traffic_20231116_200144.pcap"  # Replace with your PCAP file name
IP_variable = "192.168.1.196"  # Replace with your IP variable

# Get the IP lists
ips_facing_variable = get_ips_facing_variable(pcap_file, IP_variable)
targets_of_variable = get_targets_of_variable(pcap_file, IP_variable)

# Output results
print("IPs that communicated with {}: {}".format(IP_variable, ips_facing_variable))
print("Targets of {}: {}".format(IP_variable, targets_of_variable))





"""from scapy.all import sniff, wrpcap, rdpcap, IP
import threading
import time
import datetime
import decimal
import re
from proxy_config import interface_name
every_sec = 10



c2_patterns = [
    r'Mozilla\/5\.0 \(Windows NT 10\.0; Win64; x64\)',
    r'curl\/7\.[0-9]+\.[0-9]+',
    r'/wp-admin/admin-ajax\.php\?action=',
    r'/login\.php\?username=[^&]+&password=[^&]+',
    r'/heartbeat\.php\?id=[0-9a-f]{32}',
    r'/checkin\?machine=[^&]+&status=[0-9]+',
    r'a-zA-Z0-9+/={2,}=',
    r'/update\.php\?data=[a-zA-Z0-9+/=]+',
    r'X-Custom-Command: [A-Z]+',
    r'Authorization: Bearer [a-zA-Z0-9\._-]+',
    r'[a-z0-9-]{16,}\.example\.com',
    r'[a-f0-9]{32}\.dyndns\.org',
    r'/connect\.php\?ip=([0-9]{1,3}\.){3}[0-9]{1,3}',
    r'http://[0-9]+.[0-9]+.[0-9]+.[0-9]+/[a-z]+',
    r'/keepalive\.php\?session=[0-9a-f]+',
    r'/poll\.php\?last=[0-9]+',
    r'/system32/config\.dat',
    r'/bin/bash -c [a-zA-Z0-9]+',
    r'/exec\.php\?cmd=[a-zA-Z0-9]+',
    r'/run\.asp\?command=[^&]+',
]

def  extract_requests_by_time(pcap_file, time_variable):
    # Read the pcap file
    packets = rdpcap(pcap_file)
    # Filter packets based on the provided time variable
    filtered_packets = [packet for packet in packets if packet_has_time(packet, time_variable)]
    return filtered_packets


def packet_has_time(packet, time_variable):
    try:
        packet_time = datetime.datetime.fromtimestamp(packet.time)
        specified_time = datetime.datetime.strptime(time_variable, '%Y-%m-%d %H:%M:%S')
        print(packet_time)
        return packet_time == specified_time
    except:
        return False


def gogogo(telem_file, pcap_file):
    array_list = []
    with open(telem_file, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                array = eval(line)  # Try to evaluate the line as a Python expression
                if isinstance(array, list):
                    array_list.append(array)
            except (SyntaxError, NameError):
                pass  # Ignore lines that cannot be evaluated as lists
    for array in array_list:
        print(array[0], array[1])
        print(extract_requests_by_time(pcap_file, array[0]))
        print("===============")



gogogo("Filter/telemetry_marks.prx", "Pcaps/traffic_20231116_202440.pcap")"""