import socket
import threading

# ARP cache mapping destination IP to node MAC.
ARP_Cache = {
    "1A": "N1",
    "2A": "N2",
    "2B": "N3"
}

# Lists of node ports for each subnet.
SUBNET_1_NODES = [8000]        # e.g., nodes with IP starting with "1"
SUBNET_2_NODES = [9000, 9001]    # e.g., nodes with IP starting with "2"

# The router’s single listening port.
ROUTER_PORT = 10000

# Logical interface MAC addresses.
ROUTER_MAC_R1 = "R1"  # for subnet1
ROUTER_MAC_R2 = "R2"  # for subnet2

def send_data(target_port, message, target_host='localhost'):
    """Send the message to the specified target port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((target_host, target_port))
            s.sendall(message.encode('utf-8'))
            print(f"[Router] Sent to port {target_port}: {message}")
        except Exception as e:
            print(f"[Router] Error sending to port {target_port}: {e}")

def router_forward(packet):
    """
    Process a packet received on the router.
    Packet format: source_ip | dest_ip | 0x00 | <frame_length> | <frame>
    Frame format: source_mac | dest_mac | <msg_length> | <message>
    """
    tokens = packet.split(" | ")
    if len(tokens) < 5:
        print("[Router] Malformed packet; dropping.")
        return

    source_ip, dest_ip, protocol, frame_length = tokens[0:4]
    frame_tokens = tokens[4:]
    if len(frame_tokens) < 4:
        print("[Router] Malformed frame; dropping.")
        return

    frame_src_mac, frame_dest_mac, msg_length, message = frame_tokens[0:4]
    # Determine on which logical interface this packet arrived by checking the frame destination.
    if frame_dest_mac not in (ROUTER_MAC_R1, ROUTER_MAC_R2):
        print(f"[Router] Packet not addressed to router interfaces; dropping.")
        return

    incoming_interface = frame_dest_mac

    # Decide on the outgoing interface based on destination IP.
    if dest_ip[0] == "1":
        out_interface = ROUTER_MAC_R1
        target_nodes = SUBNET_1_NODES
    elif dest_ip[0] == "2":
        out_interface = ROUTER_MAC_R2
        target_nodes = SUBNET_2_NODES
    else:
        print("[Router] Unknown destination subnet; dropping.")
        return
    
    # Look up the final destination node's MAC address.
    dest_node_mac = ARP_Cache.get(dest_ip, None)
    if not dest_node_mac:
        print(f"[Router] Destination IP {dest_ip} not in ARP cache; dropping packet.")
        return

    # Update the frame: set source MAC to the router's outgoing interface and destination to the node's MAC.
    new_frame = out_interface + " | " + dest_node_mac + " | " + str(len(message)) + " | " + message
    new_packet = source_ip + " | " + dest_ip + " | " + protocol + " | " + str(len(new_frame)) + " | " + new_frame

    print(f"[Router] Forwarding packet from interface {incoming_interface} to {out_interface}")
    # Flood the updated packet to all nodes in the target subnet.
    for port in target_nodes:
        send_data(port, new_packet)

def handle_router_client(conn, addr):
    """Handle incoming connections on the router."""
    print(f"[Router] Connection from {addr}")
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            decoded_data = data.decode('utf-8')
            print(f"[Router] Received: {decoded_data}")
            router_forward(decoded_data)
    print(f"[Router] Connection closed from {addr}")

def start_router_server(host='0.0.0.0'):
    """Start the router's single server on ROUTER_PORT."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((host, ROUTER_PORT))
        except OSError as e:
            print(f"[Router] Error binding to {host}:{ROUTER_PORT}: {e}")
            return
        server_socket.listen()
        server_socket.settimeout(1)  # Set a 1-second timeout
        print(f"[Router] Listening on {host}:{ROUTER_PORT}")
        try:
            while True:
                try:
                    conn, addr = server_socket.accept()
                    threading.Thread(target=handle_router_client, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    # Timeout reached; continue the loop and check for KeyboardInterrupt.
                    continue
        except KeyboardInterrupt:
            print("\n[Router] Shutting down gracefully.")

if __name__ == '__main__':
    print("[Router] Starting router on a single port for both interfaces.")
    print(f"[Router] Interfaces: {ROUTER_MAC_R1} (Subnet 1) and {ROUTER_MAC_R2} (Subnet 2)")
    start_router_server()
