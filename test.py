import socket
import threading
import struct
import sys

# MAC Addresses (2 ASCII chars)
MAC_ADDRESSES = {
    "N1": "N1", "N2": "N2", "N3": "N3", "R1": "R1", "R2": "R2"
}

# IP Addresses (1 Byte Hex)
IP_ADDRESSES = {
    "N1": 0x1A, "N2": 0x2A, "N3": 0x2B, "R1": 0x11, "R2": 0x21
}

# Protocols
PING = 0
KILL = 1  # Not used

# Firewall Rules (Example: Block all packets from Node2)
FIREWALL_RULES = {"N3": {"block": ["N2"], "allow": ["N1", "R1"]}}

# Network Settings
UDP_PORT = 12345  # Common port for all nodes
BUFFER_SIZE = 1024


class Node:
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # 🔥 Allow multiple nodes to bind to the same port!
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock.bind(("127.0.0.1", UDP_PORT))
        self.running = True


    def send_ethernet_frame(self, dest_mac, data):
        """Emulates sending an Ethernet frame with MAC filtering."""
        frame = f"{self.mac}{dest_mac}{data}"
        self.sock.sendto(frame.encode(), ("127.0.0.1", UDP_PORT))

    def send_ip_packet(self, dest_ip, protocol, message):
        """Encapsulates data in an IP packet and sends via Ethernet."""
        packet = struct.pack("BBB", self.ip, dest_ip, protocol) + message.encode()
        self.send_ethernet_frame("R1", packet)

    def handle_packet(self, data):
        """Processes incoming Ethernet frames and IP packets."""
        src_mac, dest_mac, payload = data[:2], data[2:4], data[4:]

        # Drop packet if not intended for this node
        if dest_mac != self.mac and dest_mac != "R1":
            return

        # Extract IP packet
        src_ip, dest_ip, protocol = struct.unpack("BBB", payload[:3])
        message = payload[3:].decode()

        # Firewall filtering
        if self.mac in FIREWALL_RULES:
            blocked = FIREWALL_RULES[self.mac]["block"]
            if any(hex(src_ip) == IP_ADDRESSES[node] for node in blocked):
                print(f"[FIREWALL] Packet from {hex(src_ip)} blocked!")
                return

        print(f"[RECEIVED] From {hex(src_ip)} to {hex(dest_ip)} | Protocol: {protocol} | Data: {message}")

        # Respond to ping
        if protocol == PING and dest_ip == self.ip:
            self.send_ip_packet(src_ip, PING, message)

    def sniff_packets(self):
        """Node3 listens to all network traffic (sniffing attack)."""
        if self.mac != "N3":
            return
        while self.running:
            data, _ = self.sock.recvfrom(BUFFER_SIZE)
            print(f"[SNIFFING] Captured: {data.decode()}")

    def listen(self):
        """Listens for incoming packets."""
        print(f"[STARTED] Node {self.mac} listening...")
        while self.running:
            data, _ = self.sock.recvfrom(BUFFER_SIZE)
            self.handle_packet(data.decode())

    def stop(self):
        """Stops the node."""
        self.running = False
        self.sock.close()


def start_node(node_name):
    """Starts a network node."""
    if node_name not in MAC_ADDRESSES:
        print("Invalid node name!")
        return

    node = Node(MAC_ADDRESSES[node_name], IP_ADDRESSES[node_name])
    listener_thread = threading.Thread(target=node.listen)
    listener_thread.start()

    if node_name == "N3":  # Sniffer
        sniffer_thread = threading.Thread(target=node.sniff_packets)
        sniffer_thread.start()

    while True:
        cmd = input(f"{node_name}> ")
        if cmd.startswith("send"):
            _, dest, msg = cmd.split(" ", 2)
            if dest in IP_ADDRESSES:
                node.send_ip_packet(IP_ADDRESSES[dest], PING, msg)
        elif cmd == "exit":
            node.stop()
            break


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network.py <NodeName>")
        sys.exit(1)

    start_node(sys.argv[1])
