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

# TCP sequence numbers
tcp_seq_num = {}
tcp_ack_num = {}

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
