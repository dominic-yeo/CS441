import socket
import threading
import time
import random

# ARP cache mapping IP to node MAC (for local delivery)
ARP_Cache = {
    "1A": "N1",
    "2A": "N2",
    "2B": "N3"
}

# Mapping of node MAC to port numbers
NODE_PORT = {
    "N1": 8000,
    "N2": 9000,
    "N3": 9001
}

# The router’s fixed port for inter-subnet traffic
ROUTER_PORT = 10000

# Store infected nodes to prevent reinfection loops
INFECTED = False

SOURCE_MAC = input("Enter node MAC address (e.g., N1, N2, or N3): ").strip()

# Ask the user for the node's MAC address.
SOURCE_IP = ""
bind_port = 0
if SOURCE_MAC == "N1":
    SOURCE_IP = "1A"
    bind_port = NODE_PORT["N1"]
elif SOURCE_MAC == "N2":
    SOURCE_IP = "2A"
    bind_port = NODE_PORT["N2"]
elif SOURCE_MAC == "N3":
    SOURCE_IP = "2B"
    bind_port = NODE_PORT["N3"]
else:
    print("Unknown MAC address. Exiting.")
    exit(1)

BOTNET = set()
FIREWALL_BLOCK = set()
while True:
    add_rule = input("Do you want to add a firewall rule? (e.g., block 2B): ").strip()
    if add_rule.startswith("block"):
        node_to_block = add_rule.split(" ")[1]
        FIREWALL_BLOCK.add(node_to_block)
        print(f"Firewall rule added: Blocking packets from {node_to_block}")
    else:
        break

SNIFFER_MODE = input("Enable packet sniffing? (yes/no): ").strip().lower() == "yes"


def handle_client(conn, addr):
    """Handle incoming connections."""
    # print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break  # Connection closed.
        decoded_data = data.decode('utf-8')
        logical_receive_data(decoded_data)
    conn.close()


def logical_receive_data(data):
    global INFECTED
    """Process received packets and detect worm propagation."""
    tokens = data.split(" | ")
    if len(tokens) < 4:
        print("Malformed frame; dropping.")
        return

    frame_src_ip = tokens[3]  # Sender's IP
    dest_ip = tokens[4]       # Destination IP
    frame_src_mac = tokens[0]  # Sender's MAC
    frame_dest_mac = tokens[1]  # Recipient's MAC
    message = tokens[-1]        # Message payload

    # Firewall check
    if frame_src_ip in FIREWALL_BLOCK:
        print(f"[Firewall] Packet from {frame_src_ip} blocked.")
        return

    # 🛑 Only print if the message is for ME
    if dest_ip != SOURCE_IP:
        return  # Ignore messages not meant for this node

    if "DDoS" in message and INFECTED:
        while(True):
            logical_send_data(SOURCE_IP, SOURCE_MAC, message.split(" ")[1], "you are under attack please crash")
    # Worm detection & propagation
    if "[WORM]" in message and INFECTED == False:
        if SOURCE_IP in message:
            return
        print(message)
        INFECTED = True
        print(f"[!] Worm detected from {frame_src_ip}! {dest_ip} is now infected!")
        # Spread the worm only once
        propogator = message.split("BY ")
        logical_send_data(SOURCE_IP, SOURCE_MAC, propogator[1], SOURCE_IP + " successfully infected.")
        propagate_worm(propogator[1])

    if "successfully infected" in message:
        BOTNET.add(message.split(" ")[0])
        print("Current Botnet:" )
        print(BOTNET)
    if frame_dest_mac == SOURCE_MAC:
        print(f"Packet received from {frame_src_ip}: {message}")
    elif SNIFFER_MODE and "[PING REPLY]" not in message:
        print(f"Sniffed packet from {frame_src_ip}: {message}")
    else:
        print("Packet not addressed to me; dropped.")




def propagate_worm(propogator):
    """Spread the worm to all available nodes, avoiding redundant infections."""
    for target_ip in ARP_Cache.keys():
        if target_ip == SOURCE_IP:
            continue
        time.sleep(random.uniform(0.5, 2.0))  # Add delay for realism
        print(f"[!] Spreading worm to {target_ip}...")
        logical_send_data(SOURCE_IP, SOURCE_MAC, target_ip, "[WORM] INFECTED BY " + propogator)



def start_server(bind_port, host='0.0.0.0'):
    """Start a TCP server on the given port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((host, bind_port))
        except OSError as e:
            print(f"Error binding to {host}:{bind_port}: {e}")
            return
        server_socket.listen()
        print(f"Server listening on {host}:{bind_port}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


def send_data(target_port, message, target_host='localhost'):
    """Send the message to the specified target port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((target_host, target_port))
            s.sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending data: {e}")


def logical_send_data(source_ip, source_mac, dest_ip, message):
    """Build and send packets in the correct format."""
    target_ports = [8000, 10000]
    if source_ip[0] == "2":
        target_ports = [9000, 9001, 10000]

    if dest_ip[0] == source_ip[0]:  # Local subnet
        dest_mac = ARP_Cache.get(dest_ip, "Unknown")
        if dest_mac == "Unknown":
            print("Destination IP not in ARP cache; dropping.")
            return
        dest_port = NODE_PORT.get(dest_mac, None)
        if not dest_port:
            print("Destination port unknown; dropping.")
            return

        packet = f"{source_ip} | {dest_ip} | 0x00 | {len(message)} | {message}"
        frame = f"{source_mac} | {dest_mac} | {4 + len(message)} | {packet}"
        
        for i in target_ports:
            if i != bind_port:
                send_data(i, frame)
    else:  # Remote communication via router
        router_interface = "R1" if source_ip[0] == "1" else "R2"
        packet = f"{source_ip} | {dest_ip} | 0x00 | {len(message)} | {message}"
        frame = f"{source_mac} | {router_interface} | {4 + len(message)} | {packet}"
        
        for i in target_ports:
            if i != bind_port:
                send_data(i, frame)


if __name__ == '__main__':

 
    print("Assigned IP: " + SOURCE_IP)
    # Start the node's server.
    threading.Thread(target=start_server, args=(bind_port,), daemon=True).start()

    print("Enter messages in the format '<dest_ip> <data>' (e.g., '1A Hello World')")
    print("Type 'release worm' to infect the network.")

    while True:
        user_input = input("> ").strip()
        if not user_input:
            continue

        if user_input.lower() == "release worm":
            print("[!] Releasing worm from this node...")
            print("[!] Once you have acquired a botnet, type 'DDoS <IP>' to execute DDoS")
            propagate_worm(SOURCE_IP)
        elif "DDoS" in user_input:
            for ip in BOTNET:
                logical_send_data(SOURCE_IP, SOURCE_MAC, ip, "DDoS " + user_input.split(" ")[1])
        else:
            try:
                dest_ip, message = user_input.split(' ', 1)
                logical_send_data(SOURCE_IP, SOURCE_MAC, dest_ip, message)
            except ValueError:
                print("Invalid input. Please type '<dest_ip> <data>'.")
