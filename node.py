import socket
import threading
import time
import random
import hashlib
import json
import hmac
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

# TCP connection table: {(source_ip, source_port, dest_ip, dest_port): state}
tcp_connections = {}
connected_clients = {}
# TCP sequence numbers
tcp_seq_num = {}
tcp_ack_num = {}

tls_sessions = {}
client_tls_con_id = ()
server_tls_con_id = ()
SERVER_CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIIDETCCAfkCFCOkcQJ0z0cxMTmi61ADfCETPA5MMA0GCSqGSIb3DQEBCwUAMEUx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
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

SSL_DOWNGRADE = input("Enable SSL downgrade attack? (yes/no): ").strip().lower() == "yes"
if SSL_DOWNGRADE:
        print("[!] SSL/TLS downgrade attack enabled")
        print("[!] The simulation will attempt to force connections to use weaker encryption")

WAF_SECRET = b"supersecurekey"
KNOWN_SIGNATURES = set()

original_payload = "INFECTED BY "
KNOWN_SIGNATURES.add(original_payload)

def waf_filter(message):
    try:
        msg_obj = json.loads(message)
        if msg_obj.get("type") == "malware":
            expected_hmac = msg_obj.get("hmac", "")
            payload = msg_obj.get("payload", "")

            recalculated = hmac.new(WAF_SECRET, payload.encode(), hashlib.sha256).hexdigest()
            if recalculated != expected_hmac:
                print(f"[WAF] Invalid HMAC for malware payload; blocked")
                return True
            
            for signature in KNOWN_SIGNATURES:
                if payload.startswith(signature):
                    print(f"[WAF] Known malware signature detected; blocked")
                    return True
            
            print(f"[WAF] Unknown malware signature; allowing through")
            return False
    except json.JSONDecodeError:
        # Not JSON - allow the message
        return False
    return False
    
def create_polymorphic_worm(propagator_ip):
    variants = [
        f"INFECTED_BY_{propagator_ip}_{random.randint(1,10000)}",
        f"HACKED{{{propagator_ip}}}",
        f"{propagator_ip}-PAYLOAD-{random.randint(100, 999)}",
        f"{random.choice(['X', 'Y', 'Z'])}_{propagator_ip}_INFECT"
    ]
    payload = random.choice(variants)
    signature = hmac.new(WAF_SECRET, payload.encode(), hashlib.sha256).hexdigest()

    worm_mesage = {
        "type": "message",
        "payload": payload,
        "hmac": signature
    }
    return json.dumps(worm_mesage)

def create_signed_worm(propagator_ip):
    payload = f"INFECTED BY {propagator_ip}"
    signature = hmac.new(WAF_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    worm_message = {
        "type": "malware",
        "payload": payload,
        "hmac": signature
    }
    return json.dumps(worm_message)

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
    if "[TLS]" in data: 
        tls_connection_receive(data)
        return 
    
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
    
    #server receives client msg 
    if len(server_tls_con_id) != 0:
        if frame_src_ip == server_tls_con_id[1]:
            k = tls_sessions[server_tls_con_id]["master_secret"]
            message = json.loads(message)
            print(f"Received encrypted message from {frame_src_ip}:{server_tls_con_id[-1]}: {message['enc_msg']}")
            nonce_bytes  = base64.b64decode(message["nonce"])
            enc_msg_bytes = base64.b64decode(message["enc_msg"])
            
            decypted_msg = aes_decrypt_message(k,nonce_bytes,enc_msg_bytes)
            print(f"Packet received from {frame_src_ip}: {decypted_msg}")
            #source_ip, source_mac, dest_ip, message
            logical_send_data(dest_ip, frame_dest_mac, frame_src_ip, f"[REPLY] {decypted_msg}")
            return 
    
    #client receives server msg 
    if len(client_tls_con_id) != 0:
        if frame_src_ip == client_tls_con_id[1]:
            k = tls_sessions[client_tls_con_id]["master_secret"]
            message = json.loads(message)
            print(f"Received encrypted message from {frame_src_ip}:{client_tls_con_id[-1]}: {message['enc_msg']}")
            nonce_bytes  = base64.b64decode(message["nonce"])
            enc_msg_bytes = base64.b64decode(message["enc_msg"])
            decypted_msg = aes_decrypt_message(k, nonce_bytes, enc_msg_bytes)
            print(f"Packet received from {frame_src_ip}: {decypted_msg}")
            return 
    
    # Firewall check
    if frame_src_ip in FIREWALL_BLOCK:
        print(f"[Firewall] Packet from {frame_src_ip} blocked.")
        return
    
        # WAF check
    if WAF_ENABLED:
        if waf_filter(message):
            return

    # Add TCP packet handling
    if "[TCP]" in tcp_message[0]:
        handle_tcp_packet(frame_src_ip, frame_src_mac, dest_ip, tcp_message)
        return
    
    if len(tokens) == 10:
        #IP packet: source IP | dest IP | protocol | dataLength | flag | offset | payload
        flag = tokens[-3]
        offset = int(tokens[-2])
        if frame_dest_mac == SOURCE_MAC:
            if len(fmessage) >= (offset*8):
                fmessage = fmessage[0:offset*8] + message 
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
                    
                    if "[PING REPLY]" not in fmessage:
                        reply_message = "[PING REPLY] " + fmessage  
                        logical_send_data(dest_ip, SOURCE_MAC, frame_src_ip, reply_message)
                    fmessage = ""
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
    try:
        msg_obj = json.loads(message)
        if msg_obj.get("type") == "malware":
            expected_hmac = msg_obj.get("hmac", "")
            payload = msg_obj.get("payload", "")

            # Verify signature
            recalculated = hmac.new(WAF_SECRET, payload.encode(), hashlib.sha256).hexdigest()
            if recalculated != expected_hmac:
                print("[WORM] Invalid worm signature; rejecting message.")
                return
        
            if INFECTED:
                print("[WORM] Node already infected; ignoring worm.")
                return

            INFECTED = True
            print(f"[!] Worm detected from {frame_src_ip}! {SOURCE_IP} is now infected.")

            if payload.startswith("INFECTED BY "):
                propogator = payload.split("BY ")[1]
            else: 
                propogator = frame_src_ip
            logical_send_data(SOURCE_IP, SOURCE_MAC, propogator, f"{SOURCE_IP} successfully infected.")
            propagate_worm(propogator)
            return
    except json.JSONDecodeError:
        pass  # Message is not a worm

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
        worm_payload = create_signed_worm(propogator)
        logical_send_data(SOURCE_IP, SOURCE_MAC, target_ip, worm_payload)

def propagate_poly_worm(propogator):
    for target_ip in ARP_Cache.keys():
        if target_ip == SOURCE_IP:
            continue
        time.sleep(random.uniform(0.5, 2.0))  # Add delay for realism
        print(f"[!] Spreading worm to {target_ip}...")
        worm_payload = create_polymorphic_worm(propogator)
        logical_send_data(SOURCE_IP, SOURCE_MAC, target_ip, worm_payload)

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

    #client to server communication after tls
    if len(client_tls_con_id) != 0: 
        if dest_ip == client_tls_con_id[1]:
            k = tls_sessions[client_tls_con_id]["master_secret"]
            nonce, enc_msg = aes_encrypt_message(k, message)
            msg = {
                "nonce": nonce,
                "enc_msg":enc_msg 
            }
            tcp = f"{client_tls_con_id[2]} | {client_tls_con_id[3]} | {json.dumps(msg)}"
            packet = f"{source_ip} | {dest_ip} | 0x00 | {2 + len(json.dumps(msg))} | {tcp}"
            frame = f"{source_mac} | R1 | {6 + len(json.dumps(msg))} | {packet}"  
        
            for port in local_ports:
                if port != bind_port:
                    send_data(port, frame)
            return 
    #server to client communication after tls 
    if len(server_tls_con_id) != 0: 
        if dest_ip == server_tls_con_id[1]:
            k = tls_sessions[server_tls_con_id]["master_secret"]
            nonce, enc_msg = aes_encrypt_message(k, message)
            msg = {
                "nonce": nonce,
                "enc_msg":enc_msg 
            }
            tcp = f"{server_tls_con_id[2]} | {server_tls_con_id[3]} | {json.dumps(msg)}"
            packet = f"{source_ip} | {dest_ip} | 0x00 | {2 + len(json.dumps(msg))} | {tcp}"
            frame = f"{source_mac} | R2 | {6 + len(json.dumps(msg))} | {packet}" 
            for port in local_ports:
                if port != bind_port:
                    send_data(port, frame)
            return
    
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
    """Process received TCP packets and handle the handshake logic."""
    # Parse TCP header
    
    
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
                print(f"[TCP] Connection established with {src_ip}:{source_port}")
                print("Establishing TLS connection")
                tls_connection_send(src_ip, src_mac, dest_port, source_port)

def tls_connection_send(dest_ip, dest_mac, src_port, dest_port):
    #Step 1 Client Hello 
    #Generate client random bytes (simulated).
    client_random = hashlib.sha256(str(random.randint(1, 100000)).encode()).hexdigest()
    tls_conn_id = (SOURCE_IP, dest_ip, src_port, dest_port) #(1A, 2A, rand, 80)
    tls_sessions[tls_conn_id] = {
        "client_random": client_random,
        "cipher_suite": None,
        "server_random": None,
        "premaster_secret": None,
        "master_secret": None,
        "TLS_version": None
    }
    # Create Client Hello message
    payload = {
        "type": "ClientHello",
        "version": "TLS 1.2",
        "r0": client_random,
        "cipher_suites": ["AES", "RSA", "ECDHE"] #simulated example 
    }
    
        
    tcp = f"[TLS] {src_port} | {dest_port} | {json.dumps(payload)}"
    packet = f"{SOURCE_IP} | {dest_ip} | 0x00 | {2 + len(json.dumps(payload))} | {tcp}"
    frame = f"{SOURCE_MAC} | {dest_mac} | {6 + len(json.dumps(payload))} | {packet}"
    
    print(f"[TLS] Sent: {SOURCE_IP}:{src_port} -> {dest_ip}:{dest_port} Client Hello")
    print(payload["version"])
    
    send_data(ROUTER_PORT, frame)
    return

def tls_connection_receive(message): 
    tokens = message.split(" | ")
    src_port, dest_port, payload = int(tokens[-3].replace("[TLS]", "")), int(tokens[-2]), json.loads(tokens[-1])
    src_mac, dest_mac, src_ip, dest_ip = tokens[0], tokens[1], tokens[3], tokens[4]
    tls_conn_id = (dest_ip, src_ip, dest_port, src_port)
    
    if dest_ip[0] == "1":
        local_ports = [8000, 10000]
    else:
        local_ports = [9000, 9001, 10000]
    
    if SOURCE_MAC == "N2" or SOURCE_MAC == "N3":
        if dest_mac != SOURCE_MAC: 
            print("Packet not addressed to me; dropped.")
            return
    
    # Handle ClientHello with potential downgrade
    if payload["type"] == "ClientHello":
        print(f"[TLS] received: {src_ip}:{src_port} -> {dest_ip}:{dest_port} Client Hello")
        r1 = hashlib.sha256(str(random.randint(1, 100000)).encode()).hexdigest()
        
        # Original client settings
        client_version = payload["version"]
        client_ciphers = payload["cipher_suites"]
        
        # Apply downgrade if enabled
        if SSL_DOWNGRADE and SOURCE_MAC == "N2":  # Assuming N2 is the attacking node
            original_version = client_version
            original_ciphers = client_ciphers
            
            # Force downgrade to TLS 1.0 and RSA
            downgraded_version = "TLS 1.0"
            downgraded_cipher = "RSA"
            
            print(f"[DOWNGRADE] Original TLS version: {original_version} → Downgraded to: {downgraded_version}")
            print(f"[DOWNGRADE] Original cipher suites: {original_ciphers} → Downgraded to: {downgraded_cipher}")
            
            # Store downgraded parameters
            tls_sessions[tls_conn_id] = {
                "client_random": payload["r0"],
                "cipher_suite": downgraded_cipher,
                "server_random": r1,
                "premaster_secret": None,
                "master_secret": None,
                "keys": None,
                "original_version": original_version,
                "original_ciphers": original_ciphers,
                "downgraded": True,
                "downgraded_version": downgraded_version
            }
            
            # Send Server Hello with downgraded parameters
            server_hello = {
                "type": "ServerHello",
                "version": downgraded_version,
                "r1": r1,
                "cipher_suites": downgraded_cipher
            }
        else:
            # Normal behavior without downgrade
            tls_sessions[tls_conn_id] = {
                "client_random": payload["r0"],
                "cipher_suite": "AES",  # Use strongest cipher by default
                "server_random": r1,
                "premaster_secret": None,
                "master_secret": None,
                "keys": None,
                "downgraded": False
            }
            
            # Normal Server Hello
            server_hello = {
                "type": "ServerHello",
                "version": client_version,
                "r1": r1,
                "cipher_suites": "AES"  # Use strongest cipher
            }
       
        # Send the Server Hello (either normal or downgraded)
        tcp = f"[TLS] {dest_port} | {src_port} | {json.dumps(server_hello)}"
        packet = f"{dest_ip} | {src_ip} | 0x00 | {2+ len(json.dumps(server_hello))} | {tcp}"
        frame = f"{dest_mac} | {src_mac} | {6 + len(json.dumps(server_hello))} | {packet}"  
        print(f"[TLS] Sent: {dest_ip}:{dest_port} -> {src_ip}:{src_port} Server Hello")
        
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
        
        time.sleep(1.5)
        
        # Generate server keys
        private_pem, public_pem, private_key, public_key = generate_server_key()
        tls_sessions[tls_conn_id]["keys"] = (private_pem, public_pem, private_key, public_key)
        
        # Continue with certificate exchange
        pk_cert = {
            "type": "ServerCertificate",
            "cert": SERVER_CERTIFICATE,
            "publicKey": public_pem.decode() 
        }
        
        tcp = f"[TLS] {dest_port} | {src_port} | {json.dumps(pk_cert)}"
        packet = f"{dest_ip} | {src_ip} | 0x00 | {250} | {tcp}"
        frame = f"{dest_mac} | {src_mac} | {254} | {packet}"
        print(f"[TLS] Sent: {dest_ip}:{dest_port} -> {src_ip}:{src_port} Server Certificate")
        
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
                
        # If this is a downgrade attack, log information about vulnerabilities
        if SSL_DOWNGRADE and tls_sessions[tls_conn_id].get("downgraded", False):
            print("\n[DOWNGRADE ATTACK] Connection successfully downgraded:")
            print(f"TLS Version: {server_hello['version']} (Vulnerable to POODLE, BEAST)")
            print(f"Cipher Suite: {server_hello['cipher_suites']} (No Forward Secrecy)")
            print("This connection would be susceptible to various attacks.")
            print("In a real-world scenario, encrypted traffic could potentially be decrypted.\n")
    
    # Rest of your original tls_connection_receive function for handling other message types...
    elif payload["type"] == "ServerHello":
        # Your existing ServerHello handling code...
        print(f"[TLS] received: {src_ip}:{src_port} -> {dest_ip}:{dest_port} Server Hello")
        
        # Check if this is a downgraded connection
        if payload["version"] == "TLS 1.0" or payload["cipher_suites"] == "RSA":
            print("[WARNING] Server offered downgraded security parameters:")
            print(f"TLS Version: {payload['version']}")
            print(f"Cipher Suite: {payload['cipher_suites']}")
            print("This connection may be compromised by a downgrade attack.")
        
        tls_sessions[tls_conn_id]["TLS_version"] = payload["version"]
        tls_sessions[tls_conn_id]["server_random"] = payload["r1"]
        tls_sessions[tls_conn_id]["cipher_suite"] = payload["cipher_suites"]
        
        # Generate premaster secret key
        premaster_secret = hashlib.sha256(str(random.randint(1, 100000)).encode()).digest()
        tls_sessions[tls_conn_id]["premaster_secret"] = premaster_secret
        print(f"[Client] Generated pre-master secret: {premaster_secret}")
        
        # Generate master secret key
        master_secret = derive_master_secret(premaster_secret, tls_sessions[tls_conn_id]["client_random"].encode(), payload["r1"].encode())
        tls_sessions[tls_conn_id]["master_secret"] = master_secret
        print(f"[Client] Generated master secret: {master_secret}")
        print(tls_sessions[tls_conn_id]["TLS_version"])
    
    elif payload["type"] == "ServerCertificate":
        print(f"[TLS] received: {src_ip}:{src_port} -> {dest_ip}:{dest_port} Server Certificate")
        retrieved_public_key_pem = payload["publicKey"]
        server_pk = serialization.load_pem_public_key(retrieved_public_key_pem.encode())
        #step 4: Client Key Exchange
        #public key encryption of s
        s = tls_sessions[tls_conn_id]["premaster_secret"]
        rsa_encrypted_s = rsa_encrypt_message(server_pk, s)
        rsa_encrypted_s_base64 = base64.b64encode(rsa_encrypted_s).decode()
        print(f'Encrypted S: {rsa_encrypted_s_base64}')     
        
        client_key_encryption = {
            "type": "ClientKeyExchange",
            "encrypted_s": rsa_encrypted_s_base64,
        }
        tcp = f"[TLS] {dest_port} | {src_port} | {json.dumps(client_key_encryption)}"
        packet = f"{dest_ip} | {src_ip} | 0x00 | {2 + len(json.dumps(client_key_encryption))} | {tcp}"
        frame = f"{dest_mac} | {src_mac} | {6 + len(json.dumps(client_key_encryption))} | {packet}"
        print(f"[TLS] Sent: {dest_ip}:{dest_port} -> {src_ip}:{src_port} Client Key Exchange")
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
        
        time.sleep(1.5)
        #step 5: Client Finish 
        #HMAC using master secret K message: client Finish 
        k = tls_sessions[tls_conn_id]["master_secret"]
        hmac0 = generate_hmac(k, "ClientFinish")
        client_finish = {
            "type": "ClientFinish",
            "hmac": hmac0,
        }
        tcp = f"[TLS] {dest_port} | {src_port} | {json.dumps(client_finish)}"
        packet = f"{dest_ip} | {src_ip} | 0x00 | {2 + len(json.dumps(client_finish))} | {tcp}"
        frame = f"{dest_mac} | {src_mac} | {6 + len(json.dumps(client_finish))} | {packet}"
        print(f"[TLS] Sent: {dest_ip}:{dest_port} -> {src_ip}:{src_port} Client Finish")
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
        
    elif payload["type"] == "ClientKeyExchange":
        print(f"[TLS] received: {src_ip}:{src_port} -> {dest_ip}:{dest_port} ClientKeyExchange")
        #need rsa decrypt to get premaster S, and generate key K with S, r0 and r1 
        #(private_pem, public_pem, private_key, public_key)
        keys = tls_sessions[tls_conn_id]["keys"]
        server_prk = keys[2]
        rsa_encrypted_s_received = base64.b64decode(payload["encrypted_s"])
        decrypted_s = rsa_decrypt_message(server_prk, rsa_encrypted_s_received)
        tls_sessions[tls_conn_id]["premaster_secret"] = decrypted_s
        
        print(f"[Server] Decrypted pre-master key: {decrypted_s}")
        
        #generate master key K 
        r0 = tls_sessions[tls_conn_id]["client_random"]
        r1 = tls_sessions[tls_conn_id]["server_random"]
        master_secret_svr = derive_master_secret(decrypted_s, r0.encode(), r1.encode())
        print(f"[Server] Generated master secret: {master_secret_svr}")
        tls_sessions[tls_conn_id]["master_secret"] = master_secret_svr
    
    elif payload["type"] == "ClientFinish":
        print(f"[TLS] received: {src_ip}:{src_port} -> {dest_ip}:{dest_port} Client Finish")
        #check for integrity using hashing
        hmac_received = payload["hmac"]
        master_secret_svr = tls_sessions[tls_conn_id]["master_secret"]
        hmac_svr = generate_hmac(master_secret_svr, "ClientFinish")
        if hmac_svr == hmac_received:
            print(f"[Server] hmac generated matches hmac received")
        
        #step 6: Server finish 
        hmac1 = generate_hmac(master_secret_svr, "ServerFinish")
        server_finish = {
            "type": "ServerFinish",
            "hmac": hmac1
        }
        tcp = f"[TLS] {dest_port} | {src_port} | {json.dumps(server_finish)}"
        packet = f"{dest_ip} | {src_ip} | 0x00 | {2 + len(json.dumps(server_finish))} | {tcp}"
        frame = f"{dest_mac} | {src_mac} | {6 + len(json.dumps(server_finish))} | {packet}"
        print(f"[TLS] Sent: {dest_ip}:{dest_port} -> {src_ip}:{src_port} Server Finish")
        show_attack_results()
        for port in local_ports:
            if port != bind_port:
                send_data(port, frame)
        global server_tls_con_id
        server_tls_con_id = tls_conn_id
        # print(f"severconID: {server_tls_con_id}")
        
    elif payload["type"] == "ServerFinish":
        print(f"[TLS] received: {src_ip}:{src_port} -> {dest_ip}:{dest_port} Server Finish")
        hmac_received = payload["hmac"]
        master_secret_clt = tls_sessions[tls_conn_id]["master_secret"]
        hmac_gen = generate_hmac(master_secret_clt, "ServerFinish")
        if hmac_gen == hmac_received:
            print(f"[Client] hmac generated matches hmac received")
            
        
        global client_tls_con_id
        client_tls_con_id = tls_conn_id
        # print(f"clientconID: {client_tls_con_id}")

# Add this function to send data over an established TCP connection
def tcp_send_data(dest_ip, dest_port, data):
    """Send data over an established TCP connection."""
    if SOURCE_MAC != "N1":
        print("[TCP] Only N1 can send data as TCP client in this simulation")
        return
    
    # Find the connection in the connection table
    source_port = None
    conn_id = None
    for conn in tcp_connections:
        if conn[2] == dest_ip and conn[3] == dest_port and tcp_connections[conn] == TCP_STATE_ESTABLISHED:
            source_port = conn[1]
            conn_id = conn
            break
    
    if conn_id is None:
        print(f"[TCP] No established connection to {dest_ip}:{dest_port}")
        return
    
    # Send the data
    seq_num = tcp_seq_num[conn_id] + 1  # Increment sequence number
    tcp_seq_num[conn_id] = seq_num      # Update sequence number
    
    tcp_send(SOURCE_IP, SOURCE_MAC, dest_ip, source_port, dest_port, TCP_ACK, seq_num, tcp_ack_num[conn_id], data)
    print(f"[TCP] Data sent to {dest_ip}:{dest_port}: {data}")
    
def generate_server_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024  # Reduced key size to 1024 bits
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

    return private_pem, public_pem, private_key, public_key

# Encrypt a message using the public key
def rsa_encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message,  # Convert string to bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted
# Decrypt a message using the private key
def rsa_decrypt_message(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted 

def derive_master_secret(pre_master_secret, R0, R1):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires a 32-byte key
        salt=None,
        info=b"master secret" + R0 + R1,  # Concatenated R0 and R1
    )
    master_secret = hkdf.derive(pre_master_secret)
    return master_secret

def generate_hmac(key, message):
    """ Generate an HMAC for message using the secret key """
    hmac_obj = hmac.new(key, message.encode(), hashlib.sha256)
    return hmac_obj.hexdigest()   
def aes_encrypt_message(key, plaintext):
    """ Encrypts plaintext using AES-GCM with the given key """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    nonce_b64 = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return nonce_b64, ciphertext_b64

def aes_decrypt_message(key, nonce, ciphertext):
    """ Decrypts the ciphertext using AES-GCM with the given key """
    aesgcm = AESGCM(key)
    decrypted_text = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_text.decode()

def show_attack_results():
    """Display what information could be obtained after a successful downgrade attack"""
    if SSL_DOWNGRADE:
        print("\n[DOWNGRADE ATTACK RESULTS]")
        print("=" * 60)
        print("Here's what an attacker might learn in a real-world scenario:")
        
        for conn_id, session in tls_sessions.items():
            if session.get("downgraded", False):
                src_ip, dest_ip, src_port, dest_port = conn_id
                print(session)
                print(f"\nConnection: {src_ip}:{src_port} <-> {dest_ip}:{dest_port}")
                print(f"Original security parameters requested: {session.get('original_version', 'Unknown')}, {session.get('original_ciphers', 'Unknown')}")
                print(f"Downgraded to: {session.get('downgraded_version', 'Unknown')}, {session.get('cipher_suite', 'Unknown')}")
                
                # Explain the vulnerabilities
                if session.get("downgraded_version") == "TLS 1.0":
                    print("\nTLS 1.0 Vulnerabilities:")
                    print("- BEAST attack: Allows recovering HTTP cookies and authentication tokens")
                    print("- POODLE attack: Can decrypt parts of the encrypted traffic")
                
                if session.get("cipher_suite") == "RSA":
                    print("\nRSA Key Exchange Vulnerabilities:")
                    print("- No forward secrecy: If server's private key is compromised in the future,")
                    print("  all past encrypted traffic can be decrypted")
                
                # Show the master secret (which would be compromised in a real attack)
                if session.get("master_secret"):
                    print(f"\nMaster Secret (would be compromised): {session.get('master_secret').hex() if isinstance(session.get('master_secret'), bytes) else session.get('master_secret')}")
        
        print("\nMitigation: Always use TLS 1.2+ with strong cipher suites like ECDHE.")
        print("=" * 60)
 
if __name__ == '__main__':

 
    print("Assigned IP: " + SOURCE_IP)
    # Start the node's server.
    threading.Thread(target=start_server, args=(bind_port,), daemon=True).start()

    print("Enter messages in the format '<dest_ip> <data>' (e.g., '1A Hello World')")
    print("Type 'release worm' to infect the network with a worm.")
    print("Type 'release poly worm' to infect the network with polymorphic worm.")
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
        elif user_input.lower() == "release poly worm":
            print("[!] Releasing polymorphic worm from this node...")
            print("[!] Once you have acquired a botnet, type 'DDoS <IP>' to execute DDoS")
            propagate_poly_worm(SOURCE_IP)
        elif "DDoS" in user_input:
            for ip in BOTNET:
                logical_send_data(SOURCE_IP, SOURCE_MAC, ip, "DDoS " + user_input.split(" ")[1])
        elif user_input.startswith("tcp connect"):
            try:
                _, _, dest_ip = user_input.split()
                tcp_handshake_client(dest_ip)
            except ValueError:
                print("Invalid input. Please type 'tcp connect <dest_ip>'.")  
        # In the main input loop, add this case
        # Simplified version with default port
        elif user_input.startswith("tcp send"):
            try:
                # Parse input as: tcp send <dest_ip> <data>
                parts = user_input.split(' ', 3)
                if len(parts) < 4:
                    print("Invalid input. Please type 'tcp send <dest_ip> <data>'.")
                else:
                    _, _, dest_ip, data = parts
                    dest_port = 80  # Default to HTTP port
                    tcp_send_data(dest_ip, dest_port, data)
            except ValueError:
                print("Invalid input. Please type 'tcp send <dest_ip> <data>'.")     
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
