import socket
import struct
import threading

BROADCAST_PORT = 5000
BROADCAST_IP = '<broadcast>'  # or use '255.255.255.255' if needed

def create_ethernet_frame(source, destination, data):
    source_bytes = source.encode('ascii')
    destination_bytes = destination.encode('ascii')
    data_length = len(data)
    if data_length > 256:
        raise ValueError("Data too long")
    header = struct.pack('!2s2sB', source_bytes, destination_bytes, data_length)
    frame = header + data.encode('ascii')
    return frame

def parse_ethernet_frame(frame):
    header = frame[:5]
    source_bytes, destination_bytes, data_length = struct.unpack('!2s2sB', header)
    data = frame[5:5+data_length].decode('ascii')
    return source_bytes.decode('ascii'), destination_bytes.decode('ascii'), data

def node_listener(mac):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', BROADCAST_PORT))
    while True:
        frame, addr = sock.recvfrom(1024)
        source, dest, data = parse_ethernet_frame(frame)
        # Process the frame only if the destination MAC matches or it's a broadcast
        if dest == mac or dest == "FF":  # "FF" can denote broadcast if you choose
            print(f"Node {mac} received frame from {source}: {data}")

def send_frame(source, destination, data):
    frame = create_ethernet_frame(source, destination, data)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(frame, (BROADCAST_IP, BROADCAST_PORT))

# Example usage:
if __name__ == '__main__':
    # Start listener threads for two nodes with different MAC addresses
    threading.Thread(target=node_listener, args=('N1',), daemon=True).start()
    threading.Thread(target=node_listener, args=('N2',), daemon=True).start()
    
    # Give the threads a moment to start up
    import time
    time.sleep(1)
    
    # Node N1 sends a frame intended for N2
    send_frame('N1', 'N2', 'HELLO FROM N1')
    # Node N1 sends a broadcast frame (destination "FF")
    send_frame('N1', 'FF', 'BROADCAST MESSAGE')
    
    # Keep the main thread alive to listen for messages
    while True:
        time.sleep(1)
