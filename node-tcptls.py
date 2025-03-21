import socket
import threading
import time
import random
import hashlib
import base64
import json
import ssl
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

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

# TCP flags
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_SYN_ACK = TCP_SYN | TCP_ACK  # 0x12
TCP_FIN = 0x01
TCP_RST = 0x04

# TCP connection states
TCP_STATE_CLOSED = 0
TCP_STATE_LISTEN = 1 
TCP_STATE_SYN_SENT = 2
TCP_STATE_SYN_RECEIVED = 3
TCP_STATE_ESTABLISHED = 4
TCP_STATE_FIN_WAIT_1 = 5
TCP_STATE_FIN_WAIT_2 = 6
TCP_STATE_CLOSING = 7
TCP_STATE_TIME_WAIT = 8
TCP_STATE_CLOSE_WAIT = 9
TCP_STATE_LAST_ACK = 10

# Add these constants after your TCP constants
# TLS Constants
TLS_CLIENT_HELLO = 1
TLS_SERVER_HELLO = 2
TLS_CERTIFICATE = 3
TLS_CLIENT_KEY_EXCHANGE = 4
TLS_CLIENT_FINISHED = 5
TLS_SERVER_FINISHED = 6
TLS_ESTABLISHED = 7
# TCP connection table: {(source_ip, source_port, dest_ip, dest_port): state}
tcp_connections = {}
tls_connections = {}
tls_sessions = {}

# TCP sequence numbers
tcp_seq_num = {}
tcp_ack_num = {}

# Create simple mock certificate for simulation
SERVER_CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIIDETCCAfkCFCOkcQJ0z0cxMTmi61ADfCETPA5MMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwNDAxMDAwMDAwWhcNMjQwNDAxMDAw
MDAwWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE
CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAvimM6qYnAcNmTR3gAoyPjQcUBrzA8YFpKm9MW88oCprQlBkM
G2LQ4MbOcg2CDXnFGZM5qixAQKn2aNuJKLgLYdyKQWNVgpQHw9p9lQzHEZXwkWb8
W5LZZsZ+7zRPGZISj8au77ZYZpBMxuaSe5msimJDYMebrCxnCfap2EHcYt3FzJJk
0fuB2SyKZeD3XV6OM+4GfkUnwH6zGvbWOGgGfjeOsJRIxPO93DE/NZQm2R5Vx3Sx
JLnCOgdCrQB9UyZ0MuKRpwcnZ/TAPLYohOUZXqG7xQnIITLQMxkQRCFHMEYPUOqM
BmZO4BiNgN0U8nP9wkzkFXAMA6KY4SQ1cQIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQAXTkr5FLJOcFKAFRmtTz5EZN6adsipnIYgY44h9W8EbY1X7gUQwCo++ZcICCU3
9y5eQJbKzCJZ9/NxdXnL3rUQHxL7sPGKnhbGFHJR8yaTPqPJOYPBZQx1xhQREVgL
oKQl+SqTKPCOGEDGrO1kgPEHtkFcA7mDq7TodmJRkPX1cy1PJiSKG+nkG3BF+BLI
JdGQNy7ZyKC7mAoRbN3QMdvf9+eDJHHSbdRG8NKY0Gtv7OKXLlOT9KYSzOYmRF1x
O8NeqpjgCOXUNSeuU0AqFjxzJwwCEYMdy9Tms0R4kMQPApu6hMXxXuDnLHhJwkJP
hVa7Lm8HfqBKmGCgR1eq+GE5
-----END CERTIFICATE-----
"""
# Store infected nodes to prevent reinfection loops
INFECTED = False

#store fragmented message 
# frag_message = []
memory = []
fmessage = ""
SOURCE_MAC = input("Enter node MAC address (e.g., N1, N2, or N3): ").strip()


if SOURCE_MAC == "N2":
    print("[TCP] Node is in TCP LISTEN state")
    is_tcp_server = True
    tcp_listen_port = 80  # Standard HTTP port
else:
    is_tcp_server = False

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

WAF_ENABLED = input("Enable Web Application Firewall? (yes/no): ").strip().lower() == "yes"

def waf_filter(message):
    """
    A simple WAF filter that detects worm payloads.
    If a worm signature ("[WORM]") is found, the function returns True to indicate that
    the packet should be blocked.
    """
    if "[WORM]" in message:
        print("[WAF] Worm signature detected; blocking packet.")
        return True
    return False


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
    global fmessage
    global memory
    
    """
    Process received packets and detect worm propagation.
    Also check for ARP spoofing messages
    Packet format (frame): source_mac | dest_mac | <frame_length> | source_ip | dest_ip | 0x00 | <msg_length> | <message>
    """
    tokens = data.split(" | ")
    if len(tokens) < 4:
        print("Malformed frame; dropping.")
        return

    # Extract fields from frame
    frame_src_ip = tokens[3]  # Sender's IP
    dest_ip = tokens[4]       # Destination IP
    frame_src_mac = tokens[0]  # Sender's MAC
    frame_dest_mac = tokens[1]  # Recipient's MAC
    message = tokens[-1]        # Message payload
    tcp_message = tokens[7:]
  
    

    # Firewall check
    if frame_src_ip in FIREWALL_BLOCK:
        print(f"[Firewall] Packet from {frame_src_ip} blocked.")
        return
    
    # WAF check
    if WAF_ENABLED and waf_filter(message):
        if waf_filter(message):
            return
    
    if "[TLS]" in data:
        tls_data = data.split("[TLS] ")[1].split(" | ", 1)
        if len(tls_data) >= 2:
            handle_tls_packet(frame_src_ip, frame_src_mac, dest_ip, tls_data)
        return

    elif "[TCP]" in tcp_message[0]:
        handle_tcp_packet(frame_src_ip, frame_src_mac, dest_ip, tcp_message)
        return

    
    if len(tokens) == 10:
        flag = tokens[-3]
        offset = int(tokens[-2])

        # Store and reassemble fragmented messages
        if frame_dest_mac == SOURCE_MAC:
            memory.append((offset, message))
            memory.sort()  # Ensure packets are in order

            # If flag = 0, this is the last fragment
            if flag == "0":
                fmessage = "".join(m[1] for m in memory)  # Reassemble message
                memory.clear()
                print(f"[Reassembled] Complete message received: {fmessage}")

                # Pass reassembled message for processing
                logical_receive_data(fmessage)

            else: 
                print(f"Offset = {offset}, unable to reassemble with previous fragment")
                memory.append(message)
            
            if flag == "0": 
                if len(memory) > 0:
                    print(f"Node crashing")
                    # raise KeyboardInterrupt
                    fmessage = ""
                    memory.clear()
                else:  
                    print(f"Packet received from {frame_src_ip}: {fmessage}")
                
        else:
            print("Packet not addressed to me; dropped.")
        return     

    # Process ARP spoofing messages regardless of destination to simulate a realistic ARP poisoning attack where malicious ARP replies are brodcasted
    if message.startswith("[ARP SPOOF]"):
        # Expected format: "[ARP SPOOF] <IP> <MAC>"
        tokens_spoof = message.split(" ")
        if len(tokens_spoof) >= 4:
            spoof_target_ip = tokens_spoof[2]
            spoof_fake_mac = tokens_spoof[3]
            # Do not update ARP cache if it is our own entry
            if spoof_target_ip == SOURCE_IP:
                print(f"[ARP SPOOF] Received spoof message for my own IP ({SOURCE_IP}); ignoring.")
            else:
                ARP_Cache[spoof_target_ip] = spoof_fake_mac
                print(f"[ARP SPOOF] ARP cache updated: {spoof_target_ip} now maps to {spoof_fake_mac}")
        return
            

    # 🛑 Only print if the message is for ME
    if not SNIFFER_MODE and frame_dest_mac != SOURCE_MAC:
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
        # **Avoid Infinite Loop - Do not reply to a reply**
        if "[PING REPLY]" not in message:
            reply_message = f"[PING REPLY] {message}"
            logical_send_data(dest_ip, SOURCE_MAC, frame_src_ip, reply_message)
        
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
    """Build and send packets in the correct format, handling ARP spoof messages specially."""
    # Determine local broadcast ports based on the sender's subnet.
    if source_ip[0] == "1":
        local_ports = [8000, 10000]
    else:
        local_ports = [9000, 9001, 10000]

    #Max Transmission Unit (MTU) =  256
    MTU = 256 
    #Fragmentation 
    if (len(message) + 6 > MTU or "[TEARDROP]" in message):
        offSet = (256 - 6)//8 #31
        dest_mac = ARP_Cache.get(dest_ip, "Unknown") if dest_ip[0] == source_ip[0] else ("R1" if source_ip.startswith("1") else "R2")
        attack = False 
        if "[TEARDROP]" in message:
            message = "a"*2000
            attack = True 
        curPos = 0
        while (curPos < len(message)):
            payload = message[curPos: curPos + (offSet*8)]
            flag = 0 if curPos + (offSet*8) > len(message) else 1
            os = curPos//8
            if attack and (curPos == offSet*8):
                print(f"Original offset value: {offSet}")
                os = curPos//8 - 1
                print(f"Adjusted offset value: {os}")
            #IP packet: source IP | dest IP | protocol | dataLength | flag | offset | payload 
            packet = f"{source_ip} | {dest_ip} | 0x00 | {len(payload)} | {flag} | {os} | {payload}"
            frame = f"{source_mac} | {dest_mac} | {6 + len(payload)} | {packet}"
            
            for port in local_ports:
                if port != bind_port:
                    send_data(port, frame)
            curPos += offSet*8
        return 

    
    # Special handling for ARP spoof messages.
    if message.startswith("[ARP SPOOF]"):
        protocol_field = "ARP"
        packet = f"{source_ip} | {dest_ip} | {protocol_field} | {len(message)} | {message}"
        if dest_ip[0] == source_ip[0]:
            dest_mac = ARP_Cache.get(dest_ip, "Unknown")
            if dest_mac == "Unknown":
                print("Destination IP not in ARP cache; dropping.")
                return
            frame = f"{source_mac} | {dest_mac} | {4 + len(message)} | {packet}"
        else:
            router_interface = "R1" if source_ip[0] == "1" else "R2"
            frame = f"{source_mac} | {router_interface} | {4 + len(message)} | {packet}"
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
        return
    
    # IP Spoofing check
    if "-ip" in message:
        parts = message.split(" -ip ")
        actual_message = parts[0].strip()
        # Expect the fake IP to be the first token after -ip
        fake_ip = parts[1].strip().split()[0]
        spoof_source_ip = fake_ip
        if dest_ip[0] == source_ip[0]:
            dest_mac = ARP_Cache.get(dest_ip, "Unknown")
            if dest_mac == "Unknown":
                print("Destination IP not in ARP cache; dropping.")
                return
            dest_port = NODE_PORT.get(dest_mac, None)
            if not dest_port:
                print("Destination port unknown; dropping.")
                return
            packet = f"{spoof_source_ip} | {dest_ip} | 0x00 | {len(actual_message)} | {actual_message}"
            frame = f"{source_mac} | {dest_mac} | {4 + len(actual_message)} | {packet}"
        else:
            router_interface = "R1" if source_ip[0] == "1" else "R2"
            packet = f"{spoof_source_ip} | {dest_ip} | 0x00 | {len(actual_message)} | {actual_message}"
            frame = f"{source_mac} | {router_interface} | {4 + len(actual_message)} | {packet}"
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
        return


    # Normal processing for non-ARP spoof messages.
    if dest_ip[0] == source_ip[0]:  # Local communication.
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
        
        # Check if the destination port (from ARP cache) is within our local broadcast ports.
        # If not, ARP spoofing has redirected the destination, so send directly.
        if dest_port not in local_ports:
            print(f"Directly sending to port {dest_port} (spoofed destination).")
            send_data(dest_port, frame)
        else:
            # Otherwise, broadcast to the local subnet (excluding our own port).
            for port in local_ports:
                if port != bind_port:
                    send_data(port, frame)
                    
    else:  # Remote communication via router.
        router_interface = "R1" if source_ip[0] == "1" else "R2"
        packet = f"{source_ip} | {dest_ip} | 0x00 | {len(message)} | {message}"
        frame = f"{source_mac} | {router_interface} | {4 + len(message)} | {packet}"
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)

def tcp_send(source_ip, source_mac, dest_ip, source_port, dest_port, flags, seq_num=0, ack_num=0, data=""):
    """Send a TCP packet with the specified flags and data."""
    # Create TCP header
    tcp_header = f"{source_port} | {dest_port} | {seq_num} | {ack_num} | {flags}"
    
    # Create the complete message with TCP header and data
    tcp_message = f"[TCP] {tcp_header} | {data}"
    
    # Use the existing logical_send_data function to send the TCP message
    logical_send_data(source_ip, source_mac, dest_ip, tcp_message)
    
    # Print debug information
    flag_names = []
    if flags & TCP_SYN:
        flag_names.append("SYN")
    if flags & TCP_ACK:
        flag_names.append("ACK")
    if flags & TCP_FIN:
        flag_names.append("FIN")
    if flags & TCP_RST:
        flag_names.append("RST")
    
    flag_str = " + ".join(flag_names) if flag_names else "None"
    print(f"[TCP] Sent: {source_ip}:{source_port} -> {dest_ip}:{dest_port} [Flags: {flag_str}] [SEQ: {seq_num}] [ACK: {ack_num}]")
    
def tcp_handshake_client(dest_ip, dest_port=80):
    """Initiate a TCP handshake as a client."""
    if SOURCE_MAC != "N1":
        print("[TCP] Only N1 can act as TCP client in this simulation")
        return
    
    # Generate initial sequence number (in a real TCP stack this would be random)
    init_seq = random.randint(1000, 9999)
    source_port = random.randint(10000, 65535)  # Ephemeral port
    
    # Store connection info
    conn_id = (SOURCE_IP, source_port, dest_ip, dest_port)
    tcp_connections[conn_id] = TCP_STATE_SYN_SENT
    tcp_seq_num[conn_id] = init_seq
    
    print(f"[TCP] Initiating handshake with {dest_ip}:{dest_port} from port {source_port}")
    
    # Send SYN packet (Step 1 of handshake)
    tcp_send(SOURCE_IP, SOURCE_MAC, dest_ip, source_port, dest_port, TCP_SYN, init_seq, 0)

def handle_tcp_packet(src_ip, src_mac, dest_ip, tcp_data):
    # Your existing TCP handling code
    source_port = int(tcp_data[0].replace("[TCP]", ""))
    dest_port = int(tcp_data[1])
    seq_num = int(tcp_data[2])
    ack_num = int(tcp_data[3])
    flags = int(tcp_data[4])
    data = tcp_data[5] if len(tcp_data) > 5 else ""
    
    # Print received TCP packet info
    flag_names = []
    if flags & TCP_SYN:
        flag_names.append("SYN")
    if flags & TCP_ACK:
        flag_names.append("ACK")
    if flags & TCP_FIN:
        flag_names.append("FIN")
    if flags & TCP_RST:
        flag_names.append("RST")
    
    flag_str = " + ".join(flag_names) if flag_names else "None"
    if SOURCE_MAC == "N2" or SOURCE_MAC == "N1":
        print(f"[TCP] Received: {src_ip}:{source_port} -> {dest_ip}:{dest_port} [Flags: {flag_str}] [SEQ: {seq_num}] [ACK: {ack_num}]")
    
    # Check if this is a TLS message
    if "[TLS]" in data:
        # Extract TLS data
        tls_parts = data.split("[TLS] ")[1].split(" | ", 1)
        if len(tls_parts) >= 2:
            handle_tls_packet(src_ip, src_mac, dest_ip, tls_parts)
        return
    
    
    # Handle server-side of handshake (N2)
    if SOURCE_MAC == "N2" and is_tcp_server:
        if flags == TCP_SYN:  # Step 1: Client SYN received
            # Generate server sequence number
            server_seq = random.randint(1000, 9999)
            conn_id = (dest_ip, dest_port, src_ip, source_port)
            
            # Store connection info
            tcp_connections[conn_id] = TCP_STATE_SYN_RECEIVED
            tcp_seq_num[conn_id] = server_seq
            tcp_ack_num[conn_id] = seq_num + 1
            
            # Send SYN-ACK (Step 2 of handshake)
            tcp_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TCP_SYN_ACK, server_seq, seq_num + 1)
        
        elif flags == TCP_ACK:  # Step 3: Client ACK received
            conn_id = (dest_ip, dest_port, src_ip, source_port)
            if conn_id in tcp_connections and tcp_connections[conn_id] == TCP_STATE_SYN_RECEIVED:
                # Connection is now established
                tcp_connections[conn_id] = TCP_STATE_ESTABLISHED
                print(f"[TCP] Connection established with {src_ip}:{source_port}")
        
        elif flags == TCP_ACK and len(data) > 0:  # Data packet received
            conn_id = (dest_ip, dest_port, src_ip, source_port)
            if conn_id in tcp_connections and tcp_connections[conn_id] == TCP_STATE_ESTABLISHED:
                if not "[TLS]" in data:
                    print(f"[TCP] Received data from {src_ip}:{source_port}: {data}")
                
                # Update acknowledgment number to acknowledge the data
                tcp_ack_num[conn_id] = seq_num + len(data)
                
                # Send ACK to acknowledge the data
                tcp_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, 
                        TCP_ACK, tcp_seq_num[conn_id], tcp_ack_num[conn_id])
    
    # Handle client-side of handshake (N1)
    elif SOURCE_MAC == "N1":
        if flags == TCP_SYN_ACK:  # Step 2: Server SYN-ACK received
            conn_id = (dest_ip, dest_port, src_ip, source_port)
            if conn_id in tcp_connections and tcp_connections[conn_id] == TCP_STATE_SYN_SENT:
                # Store received sequence number for future ACKs
                tcp_ack_num[conn_id] = seq_num + 1
                
                # Send ACK (Step 3 of handshake)
                tcp_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TCP_ACK, 
                         tcp_seq_num[conn_id] + 1, tcp_ack_num[conn_id])
                
                # Connection is now established
                tcp_connections[conn_id] = TCP_STATE_ESTABLISHED
                print(tcp_connections)
                print(f"[TCP] Connection established with {src_ip}:{source_port}")


# Create a simple RSA key pair for the server (for simulating TLS)
def generate_server_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


# Add a dictionary to store server keys
server_keys = {}
if SOURCE_MAC == "N2":
    private_key, public_key = generate_server_key()
    server_keys["private"] = private_key
    server_keys["public"] = public_key

# TLS functions - add these after your existing functions
def tls_handshake_client(dest_ip, dest_port=443):
    """Initiate a TLS handshake after TCP is established."""
    if SOURCE_MAC != "N1":
        print("[TLS] Only N1 can act as TLS client in this simulation")
        return
    
    # Find the TCP connection to this IP
    tcp_conn_id = None
    print(tcp_connections.keys())
    for conn_id in tcp_connections.keys():
        if conn_id[2] == dest_ip and tcp_connections[conn_id] == TCP_STATE_ESTABLISHED:
            tcp_conn_id = conn_id
            break
    
    if tcp_conn_id is None:
        print(f"[TLS] No established TCP connection to {dest_ip}")
        return
    
    source_ip, source_port, dest_ip, dest_port = tcp_conn_id
    
    # Initialize TLS connection
    tls_conn_id = tcp_conn_id
    tls_connections[tls_conn_id] = TLS_CLIENT_HELLO
    
    # Generate client random bytes (simulated)
    client_random = hashlib.sha256(str(random.randint(1, 1000000)).encode()).hexdigest()
    
    # Create Client Hello message
    client_hello = {
        "type": "ClientHello",
        "version": "TLS 1.2",
        "client_random": client_random,
        "cipher_suites": ["TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
    }
    
    # Store session data
    tls_sessions[tls_conn_id] = {
        "client_random": client_random,
        "cipher_suite": None,
        "server_random": None,
        "server_certificate": None,
        "premaster_secret": None,
        "master_secret": None
    }
    
    # Send Client Hello
    print(f"[TLS] 4️⃣ Sending Client Hello to {dest_ip}:{dest_port}")
    tls_send(source_ip, SOURCE_MAC, dest_ip, source_port, dest_port, TLS_CLIENT_HELLO, json.dumps(client_hello))


def tls_send(source_ip, source_mac, dest_ip, source_port, dest_port, tls_type, data):
    """Send a TLS message over the established TCP connection."""
    # Construct TLS header
    data_len = len(data)
    tls_header = f"{tls_type}|{data_len}"
    tls_message = f"[TLS] {tls_header} | {data}"
    
    # Find the TCP connection
    conn_id = (source_ip, source_port, dest_ip, dest_port)
    
    if conn_id in tcp_connections and tcp_connections[conn_id] == TCP_STATE_ESTABLISHED:
        # Get current sequence and ack numbers
        seq_num = tcp_seq_num[conn_id]
        ack_num = tcp_ack_num[conn_id]
        
        # Send over TCP
        tcp_send(source_ip, source_mac, dest_ip, source_port, dest_port, TCP_ACK, seq_num, ack_num, tls_message)
        
        # Update TCP sequence number
        tcp_seq_num[conn_id] = seq_num + len(tls_message)
    else:
        print(f"[TLS] No established TCP connection to {dest_ip}:{dest_port}")

def handle_tls_packet(src_ip, src_mac, dest_ip, tls_data):
    """Process received TLS packets and handle the handshake logic."""
    # Parse TLS message
    tls_header_parts = tls_data[0].split('|')
    if len(tls_header_parts) > 1:
        # New format with message length
        tls_type = int(tls_header_parts[0])
        # You can use message_length if needed
        message_length = int(tls_header_parts[1])
    else:
        # Old format (for backward compatibility)
        tls_type = int(tls_data[0])
    
    tls_content = tls_data[1]
    
    # Decode JSON content
    try:
        # Check if the message appears to be truncated
        if tls_content.endswith('"W') or ']' not in tls_content[-5:]:
            print(f"[TLS] Truncated message detected: {tls_content}")
            # Potentially store partial message for reassembly
            return
        content = json.loads(tls_content)
    except json.JSONDecodeError as e:
        print(f"[TLS] JSON parsing error: {e} in message: {tls_content}")
        return
    except Exception as e:
        print(f"[TLS] Error processing TLS message: {e}")
        return
    
    # Find matching TCP connection
    matching_conn = None
    for conn_id in tcp_connections.keys():
        if conn_id[0] == dest_ip and conn_id[2] == src_ip:
            matching_conn = conn_id
            break
    
    if not matching_conn:
        print("[TLS] No matching TCP connection found")
        return
    
    source_ip, source_port, dest_ip, dest_port = matching_conn
    
    # Handle TLS message based on type
    if SOURCE_MAC == "N2":  # Server
        print(tls_type)
        if tls_type == TLS_CLIENT_HELLO:
            
            # Handle Client Hello
            print(f"[TLS] Received Client Hello from {src_ip}:{content.get('version', '')}")
            
            # Store client random
            client_random = content.get("client_random")
            
            # Generate server random
            server_random = hashlib.sha256(str(random.randint(1, 1000000)).encode()).hexdigest()
            
            # Select cipher suite
            cipher_suite = content.get("cipher_suites", [""])[0]
            
            # Store session data
            tls_conn_id = (dest_ip, dest_port, src_ip, source_port)
            tls_connections[tls_conn_id] = TLS_SERVER_HELLO
            tls_sessions[tls_conn_id] = {
                "client_random": client_random,
                "server_random": server_random,
                "cipher_suite": cipher_suite
            }
            
            # Send Server Hello
            server_hello = {
                "type": "ServerHello",
                "version": "TLS 1.2",
                "server_random": server_random,
                "cipher_suite": cipher_suite
            }
            
            print(f"[TLS] 5️⃣ Sending Server Hello to {src_ip}")
            tls_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TLS_SERVER_HELLO, json.dumps(server_hello))
            
            # Send Certificate
            certificate = {
                "type": "Certificate",
                "certificate": SERVER_CERTIFICATE.strip()
            }
            
            print(f"[TLS] 6️⃣ Sending Certificate to {src_ip}")
            tls_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TLS_CERTIFICATE, json.dumps(certificate))
            
        elif tls_type == TLS_CLIENT_KEY_EXCHANGE:
            print(f"[TLS] 7️⃣ Received Client Key Exchange from {src_ip}")
            
            # Extract encrypted premaster secret
            encrypted_premaster_secret = content.get("encrypted_premaster_secret")
            
            # In a real implementation, we would decrypt this with the private key
            # For simulation, we'll use the same premaster secret on both sides
            tls_conn_id = (dest_ip, dest_port, src_ip, source_port)
            
            if tls_conn_id in tls_sessions:
                # Calculate master secret (simplified)
                client_random = tls_sessions[tls_conn_id]["client_random"]
                server_random = tls_sessions[tls_conn_id]["server_random"]
                
                # In a real implementation, we would use the decrypted premaster_secret
                premaster_secret = "simulated_premaster_secret"
                
                # Update session with master secret
                master_secret = hashlib.sha256((premaster_secret + client_random + server_random).encode()).hexdigest()
                tls_sessions[tls_conn_id]["master_secret"] = master_secret
            
        elif tls_type == TLS_CLIENT_FINISHED:
            print(f"[TLS] 8️⃣ Received Client Finished from {src_ip}")
            
            # In a real implementation, we would verify the client's finished hash
            tls_conn_id = (dest_ip, dest_port, src_ip, source_port)
            tls_connections[tls_conn_id] = TLS_SERVER_FINISHED
            
            # Send Server Finished
            server_finished = {
                "type": "Finished",
                "verify_data": "server_verification_hash"  # Simplified
            }
            
            print(f"[TLS] 9️⃣ Sending Server Finished to {src_ip}")
            tls_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TLS_SERVER_FINISHED, json.dumps(server_finished))
            
            # TLS handshake complete
            tls_connections[tls_conn_id] = TLS_ESTABLISHED
            print(f"[TLS] Handshake completed with {src_ip}:{source_port}")
            
        elif tls_type >= 100:  # HTTPS request
            print(f"[HTTPS] 🔟 Received encrypted HTTP request from {src_ip}")
            
            # In a real implementation, we would decrypt this using the session keys
            # For simulation, we'll just parse the "encrypted" data
            
            # Generate a simple HTTP response
            http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Hello, TLS World!</h1></body></html>"
            
            # "Encrypt" the response
            encrypted_response = {
                "type": "HTTP_Response",
                "encrypted_data": base64.b64encode(http_response.encode()).decode()
            }
            
            # Send encrypted response
            print(f"[HTTPS] Sending encrypted HTTP response to {src_ip}")
            tls_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, 101, json.dumps(encrypted_response))
            
    elif SOURCE_MAC == "N1":  # Client
        if tls_type == TLS_SERVER_HELLO:
            print(f"[TLS] 5️⃣ Received Server Hello from {src_ip}")
            
            # Store server random and selected cipher suite
            server_random = content.get("server_random")
            cipher_suite = content.get("cipher_suite")
            
            # Update session data
            tls_conn_id = (dest_ip, dest_port, src_ip, source_port)
            
            if tls_conn_id in tls_sessions:
                tls_sessions[tls_conn_id]["server_random"] = server_random
                tls_sessions[tls_conn_id]["cipher_suite"] = cipher_suite
        
        elif tls_type == TLS_CERTIFICATE:
            print(f"[TLS] 6️⃣ Received Certificate from {src_ip}")
            
            # In a real implementation, we would validate the certificate
            certificate = content.get("certificate")
            
            # Update session data
            tls_conn_id = (dest_ip, dest_port, src_ip, source_port)
            
            if tls_conn_id in tls_sessions:
                tls_sessions[tls_conn_id]["server_certificate"] = certificate
                
                # Generate premaster secret
                premaster_secret = "simulated_premaster_secret"
                
                # In a real implementation, we would encrypt this with the server's public key
                encrypted_premaster_secret = "encrypted_" + premaster_secret
                
                # Send Client Key Exchange
                key_exchange = {
                    "type": "ClientKeyExchange",
                    "encrypted_premaster_secret": encrypted_premaster_secret
                }
                
                print(f"[TLS] 7️⃣ Sending Client Key Exchange to {src_ip}")
                tls_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TLS_CLIENT_KEY_EXCHANGE, json.dumps(key_exchange))
                
                # Calculate master secret (simplified)
                client_random = tls_sessions[tls_conn_id]["client_random"]
                server_random = tls_sessions[tls_conn_id]["server_random"]
                master_secret = hashlib.sha256((premaster_secret + client_random + server_random).encode()).hexdigest()
                
                # Update session with master secret
                tls_sessions[tls_conn_id]["premaster_secret"] = premaster_secret
                tls_sessions[tls_conn_id]["master_secret"] = master_secret
                
                # Send Client Finished
                client_finished = {
                    "type": "Finished",
                    "verify_data": "client_verification_hash"  # Simplified
                }
                
                print(f"[TLS] 8️⃣ Sending Client Finished to {src_ip}")
                tls_send(dest_ip, SOURCE_MAC, src_ip, dest_port, source_port, TLS_CLIENT_FINISHED, json.dumps(client_finished))
                
        elif tls_type == TLS_SERVER_FINISHED:
            print(f"[TLS] 9️⃣ Received Server Finished from {src_ip}")
            
            # In a real implementation, we would verify the server's finished hash
            tls_conn_id = (dest_ip, dest_port, src_ip, source_port)
            tls_connections[tls_conn_id] = TLS_ESTABLISHED
            
            print(f"[TLS] Handshake completed with {src_ip}:{source_port}")
            print(f"[TLS] You can now send HTTPS requests using 'https get' or 'https post'")
        
        elif tls_type == 101:  # HTTPS response
            print(f"[HTTPS] Received encrypted HTTP response from {src_ip}")
            
            # In a real implementation, we would decrypt this using the session keys
            # For simulation, we'll just decode the "encrypted" data
            encrypted_data = content.get("encrypted_data")
            
            try:
                decrypted_data = base64.b64decode(encrypted_data).decode()
                print(f"[HTTPS] Decrypted HTTP Response:\n{decrypted_data}")
            except:
                print(f"[HTTPS] Could not decode response: {encrypted_data}")

def send_https_request(dest_ip, request_type, path="/", data=None):
    """Send an HTTPS request over an established TLS connection."""
    if SOURCE_MAC != "N1":
        print("[HTTPS] Only N1 can act as HTTPS client in this simulation")
        return
    
    # Find TLS connection to this IP
    tls_conn_id = None
    for conn_id in tls_connections.keys():
        if conn_id[2] == dest_ip and tls_connections[conn_id] == TLS_ESTABLISHED:
            tls_conn_id = conn_id
            break
    
    if tls_conn_id is None:
        print(f"[HTTPS] No established TLS connection to {dest_ip}")
        return
    
    source_ip, source_port, dest_ip, dest_port = tls_conn_id
    
    # Create HTTP request
    http_request = f"{request_type} {path} HTTP/1.1\r\nHost: {dest_ip}\r\n"
    
    if request_type == "POST" and data:
        http_request += f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n{data}"
    else:
        http_request += "\r\n"
    
    # "Encrypt" the request
    encrypted_request = {
        "type": "HTTP_Request",
        "encrypted_data": base64.b64encode(http_request.encode()).decode()
    }
    
    print(f"[HTTPS] 🔟 Sending encrypted {request_type} request to {dest_ip}")
    # Use 100 as the message type for HTTPS requests
    tls_send(source_ip, SOURCE_MAC, dest_ip, source_port, dest_port, 100, json.dumps(encrypted_request))

if __name__ == '__main__':

 
    print("Assigned IP: " + SOURCE_IP)
    # Start the node's server.
    threading.Thread(target=start_server, args=(bind_port,), daemon=True).start()

    print("Enter messages in the format '<dest_ip> <data>' (e.g., '1A Hello World')")
    print("Type 'release worm' to infect the network.")
    print("Type 'arpspoof <target_ip> <fake_mac>' to simulate ARP poisoning.")
    print("Type '<target_ip> [TEARDROP]' to simulate Teardrop Attack.")
    print("Type 'tcp connect <dest_ip>' to initiate TCP handshake.")

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
        elif user_input.startswith("tcp connect"):
            try:
                _, _, dest_ip = user_input.split()
                tcp_handshake_client(dest_ip)
            except ValueError:
                print("Invalid input. Please type 'tcp connect <dest_ip>'.")        
        elif user_input.startswith("tls connect"):
            try:
                _, _, dest_ip = user_input.split()
                tls_handshake_client(dest_ip)
            except ValueError:
                print("Invalid input. Please type 'tls connect <dest_ip>'.")
        elif user_input.startswith("https get"):
            try:
                _, _, dest_ip = user_input.split()
                send_https_request(dest_ip, "GET")
            except ValueError:
                print("Invalid input. Please type 'https get <dest_ip>'.")
        elif user_input.startswith("https post"):
            try:
                parts = user_input.split(" ", 3)
                if len(parts) < 4:
                    data = "{}"  # Empty JSON object
                else:
                    data = parts[3]
                dest_ip = parts[2]
                send_https_request(dest_ip, "POST", "/", data)
            except ValueError:
                print("Invalid input. Please type 'https post <dest_ip> <data>'.")
        elif user_input.startswith("arpspoof"):
            tokens = user_input.split(" ")
            if len(tokens) != 3:
                print("Invalid input. Please type 'arpspoof <target_ip> <fake_mac>'.")
            else:
                target_ip = tokens[1]
                fake_mac = tokens[2]
                message = f"[ARP SPOOF] {target_ip} {fake_mac}"
                print(f"[ARP SPOOF] Sending spoofed ARP reply to {target_ip}...")
                logical_send_data(SOURCE_IP, SOURCE_MAC, target_ip, message)
        else:
            try:
                dest_ip, message = user_input.split(' ', 1)
                logical_send_data(SOURCE_IP, SOURCE_MAC, dest_ip, message)
            except ValueError:
                print("Invalid input. Please type '<dest_ip> <data>'.")
