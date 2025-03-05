import socket
import threading


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

SOURCE_MAC = input("Enter node MAC address (e.g., N1, N2, or N3): ").strip()

FIREWALL_BLOCK = set()
while(True):

    add_rule = input("Do you want to add a firewall rule? (e.g. block 2B): ").strip()
    firewall_tokens = add_rule.split(" ")
    if firewall_tokens[0] == "block":
        # In our simulation, Node2's MAC is N2.
        FIREWALL_BLOCK.add(firewall_tokens[1])
        print("Firewall rule added: Blocking packets from "+ firewall_tokens[1])
    else:
        break

SNIFFER_MODE = input("Enable packet sniffing? (yes/no): ").strip().lower() == "yes"

def handle_client(conn, addr):
    """Handle incoming connections."""
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        if not data:
            break  # Connection closed.
        decoded_data = data.decode('utf-8')
        # print(f"[LOG]: Received: {decoded_data}")
        logical_receive_data(decoded_data)
    conn.close()
def logical_receive_data(data):
    # Packet format: source_ip | dest_ip | 0x00 | <msg_length> | <message>
    # Frame format: source_mac | dest_mac | <packet_length> | <packet>
    tokens = data.split("|")
    if len(tokens) < 4:
        print("Malformed frame; dropping.")
        return
    
    packet_tokens = tokens[3:]
    frame_src_ip = packet_tokens[0]  # Extract sender's IP
    dest_ip = packet_tokens[1]        # Destination IP
    
    if len(packet_tokens) < 4:
        print("Malformed packet; dropping.")
        return
    
    frame_src_mac = tokens[0]  # Extract sender's MAC
    frame_dest_mac = tokens[1] # Extract recipient's MAC
    message = packet_tokens[-1]        # Extract message

    # Firewall check
    if frame_src_ip in FIREWALL_BLOCK:
        print(f"[Firewall] Packet from {frame_src_ip} blocked.")
        return

    if frame_dest_mac == SOURCE_MAC:
        print(f"Packet received from {frame_src_ip}: {message}")
        
        # **Avoid Infinite Loop - Do not reply to a reply**
        if "[PING REPLY]" not in message:
            reply_message = f"[PING REPLY] {message}"
            logical_send_data(dest_ip, SOURCE_MAC, frame_src_ip, reply_message)
    elif SNIFFER_MODE:
        print(f"Sniffed packet from {frame_src_ip}: {message}")
    else:
        print("Packet not addressed to me; dropped.")



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
            # print(f"[LOG]: Sent: '{message}' to {target_host}:{target_port}")
        except Exception as e:
            print(f"Error sending data: {e}")

def logical_send_data(source_ip, source_mac, dest_ip, message):
    target_ports = [8000, 10000] 
    if source_ip[0] == "2":
        target_ports = [9000 ,9001, 10000]
    """
    Build the packet and send it.
    If the destination is local (same subnet), send directly to the node's port.
    Otherwise, send the packet to the router's port.
    """
    # Determine if destination is local based on first character of IP.
    if dest_ip[0] == source_ip[0]:
        # Local communication: look up destination node's MAC and port.
        dest_mac = ARP_Cache.get(dest_ip, "Unknown")
        if dest_mac == "Unknown":
            print("Destination IP not in ARP cache; dropping.")
            return
        dest_port = NODE_PORT.get(dest_mac, None)
        if not dest_port:
            print("Destination port unknown; dropping.")
            return
        # Construct the frame and packet.
        #if spoofed packet
        spoofed = message.split("-s")
        if len(spoofed) == 2:
            spoof_data = spoofed[1].split(" ")
            # frame = spoof_data[0] + " | " + dest_mac + " | " + str(len(spoofed[0])) + " | " + spoofed[0]
            # packet = spoof_data[1] + " | " + dest_ip + " | 0x00 | " + str(len(frame)) + " | " + frame
            packet = spoof_data[1] + "|" + dest_ip + "|0x00|" + str(len(spoofed[0])) + "|" + spoofed[0]
            frame =  spoof_data[0] + "|" + dest_mac + "|" + str(4 + len(spoofed[0])) + "|" + packet 
        else: 
            # frame = source_mac + " | " + dest_mac + " | " + str(len(message)) + " | " + message
            # packet = source_ip + " | " + dest_ip + " | 0x00 | " + str(len(frame)) + " | " + frame
            packet = source_ip + "|" +  dest_ip + "|0x00|" + str(len(message)) + "|" + message
            frame = source_mac + "|" + dest_mac + "|" + str(4 + len(message))  + "|" + packet         
        for i in target_ports:
            if i != bind_port:
                send_data(i, frame)
    else:
        # Remote communication: send via router.
        # Choose router's interface MAC based on our subnet:
        # For nodes in subnet1, router interface is R1; for subnet2, it is R2.
        router_interface = "R1" if source_ip[0] == "1" else "R2"
        # The destination MAC in the frame will be set to the router's interface.
        spoofed = message.split("-s")
        if len(spoofed) == 2:
            spoof_data = spoofed[1].split(" ")
            # frame = spoof_data[0] + " | " + router_interface + " | " + str(len(spoofed[0])) + " | " + spoofed[0]
            # packet = spoof_data[1] + " | " + dest_ip + " | 0x00 | " + str(len(frame)) + " | " + frame
            packet = spoof_data[1] + "|" + dest_ip + " |0x00| " + str(len(spoofed[0])) + "|" + spoofed[0]
            frame =  spoof_data[0] + "|" + dest_mac + "|" + str(4 + len(spoofed[0])) + "|" + packet
        else: 
            # frame = source_mac + " | " + router_interface + " | " + str(len(message)) + " | " + message
            # packet = source_ip + " | " + dest_ip + " | 0x00 | " + str(len(frame)) + " | " + frame
            packet = source_ip + "|" +  dest_ip + "|0x00|" + str(len(message)) + "|" + message
            frame = source_mac + "|" + router_interface + "|" + str(4 + len(message))  + "|" + packet      
        for i in target_ports:
            if i != bind_port:
                send_data(i, frame)

if __name__ == '__main__':
    # Ask the user for the node's MAC address.
    ip = ""
    bind_port = 0
    if SOURCE_MAC == "N1":
        ip = "1A"
        bind_port = NODE_PORT["N1"]
    elif SOURCE_MAC == "N2":
        ip = "2A"
        bind_port = NODE_PORT["N2"]
    elif SOURCE_MAC == "N3":
        ip = "2B"
        bind_port = NODE_PORT["N3"]
    else:
        print("Unknown MAC address. Exiting.")
        exit(1)

    print("Assigned IP: " + ip)
    # Start the node's server.
    threading.Thread(target=start_server, args=(bind_port,), daemon=True).start()

    print("Enter messages in the format '<dest_ip> <data>' (e.g., '1A Hello World')")
    while True:
        user_input = input("> ").strip()
        if not user_input:
            continue
        try:
            dest_ip, message = user_input.split(' ', 1)
            logical_send_data(ip, SOURCE_MAC, dest_ip, message)
        except ValueError:
            print("Invalid input. Please type '<dest_ip> <data>'.")
