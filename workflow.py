import threading
import time
import os
import asyncio
from scapy.all import sniff, PcapWriter, IP

# Replace with the IP you are interested in
IP_variable = "192.168.1.1"
# Proxy port
proxy_port = 8080
# PCAP file to save the traffic
pcap_file = "traffic.pcap"
# Network interface
network_interface = "ens33"

write_or_append_to_file("Filter/sus.pxt", "\n", mode='w')


async def start_subprocess(program, *args):
    """
    Start a subprocess asynchronously.
    :param program: The program to run.
    :param args: Arguments to pass to the program.
    """
    process = await asyncio.create_subprocess_exec(
        program,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # Wait for the subprocess to finish
    stdout, stderr = await process.communicate()

    if stdout:
        #return True
        return print(f"[STDOUT]\n{stdout.decode()}")
    if stderr:
        return False
        #print(f"[STDERR]\n{stderr.decode()}")

    print(f"'{program}' exited with {process.returncode}")

async def mainpr(mode, argument, target):
    if mode == 1:
        #sudo python3 c2detective.py  -ucd -ujr  -w -i traffic_20231116_200144.pcap
        asd = await start_subprocess('python3', 'C2Detective/c2detective.py', '-ucd', '-ujr', "-w", "-i", argument)  # Replace 'ls' and '-la' with your program and its arguments
        print(asd)
    elif mode == 2:
        #python3 sliver_pcap_parser.py --pcap {file} --filter http --domain_name {target}
        asd = await start_subprocess('python3', 'SliverC2-Forensics/sliver_pcap_parser.py', '--pcap', argument, "--filter", "http", "--domain_name", target)  # Replace 'ls' and '-la' with your program and its arguments
        print(asd)

def capture_traffic():
    """
    Capture traffic on port 8080 from the ens33 interface and overwrite the PCAP file every 10 seconds.
    """
    while True:
        # Capture packets for 10 seconds from the specified interface
        packets = sniff(filter=f"port {proxy_port}", iface=network_interface, timeout=10)

        # Explicitly set the link-layer type when writing to the PCAP file
        with PcapWriter(pcap_file, linktype=1, append=True) as pcap_writer:
            for packet in packets:
                pcap_writer.write(packet)

            asyncio.run(mainpr(1))


def write_or_append_to_file(file_name, text, mode='a'):
    """
    Writes or appends text to a file.

    :param file_name: Name of the file to write to or append.
    :param text: Text to write or append.
    :param mode: 'w' for write (overwrite) mode, 'a' for append mode. Defaults to 'a'.
    """
    with open(file_name, mode) as file:
        file.write(text + "\n")


def monitor_traffic():
    """
    Monitor the PCAP file and print packets with the specific IP.
    """
    while True:
        if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
            try:
                packets = sniff(offline=pcap_file, count=10)
                for packet in packets:
                    print(packet[IP].src)
                    print(packet)
                    if packet[IP].src == IP_variable:
                        print(packet[IP].dst)
                        add_to_file("Filter/to_ip.pxt")
                    elif packet[IP].dst == IP_variable:
                        print(packet[IP].src)
                        add_to_file("Filter/from_ip.pxt")   


                    #if IP in packet and (packet[IP].src == IP_variable or packet[IP].dst == IP_variable):
                    #    print(packet.show())
            except Exception as e:
                print(f"Error reading PCAP file: {e}")
                time.sleep(1)
        else:
            # Wait if the file is empty or does not exist yet
            time.sleep(1)

# Start capturing traffic
capture_thread = threading.Thread(target=capture_traffic)
capture_thread.start()

# Start monitoring traffic
monitor_thread = threading.Thread(target=monitor_traffic)
monitor_thread.start()
