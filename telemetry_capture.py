import socket
import re

def parse_data(data):
    if "no statistics gathered." in data:
        return None
    else:
        data = data.split(" ")
        return data
	

def add_to_file(filename, data):
    with open(filename, 'a') as file:
        file.write(data + '\n')


def start_server(ip, port):
    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen()

        print(f"Server listening on {ip}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode()
                if data == None or data == ["None"]:
                    pass
                else:
                    parsed_data = parse_data(data)
                    print(parsed_data)
                    add_to_file("Filter/telemetry_marks.prx", f"{parsed_data}\n")

if __name__ == "__main__":
    server_ip = "0.0.0.0"  # Change to your server's IP address
    server_port = 6666
    start_server(server_ip, server_port)
