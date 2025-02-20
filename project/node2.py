import socket
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host, port = "127.0.0.1", 8100
client.connect((host, port))

node2_IP = "0x2A"
node2_MAC = "N2"

IP_address = {
    "node1": "0x1A",
    "node3": "0x2B",
    "router": "0x21"
}

#MAC address of each Node 
ARP_Cache = {
    "0x21":"R2",
    "0x2B":"N3"
}

def client_receive():
    while True: 
        try: 
            packet= client.recv(1024).decode("utf-8")
            print("Packet received: " + packet)
            process_packet(packet)
        except: 
            print("Error")
            client.close()
            break 

def client_send():
    while True: 
        msg = input("Ping (node1, node3): ")
        # client.send(msg.encode("utf-8"))
        construct_packet(msg)
        
def construct_packet(msg): #node1 or node3
    #Ethernet frame: MAC Source | MAC Destination | length | data/IP Packet 
    # IP packet IP source | IP destination | Protocol | data length | Data 
    IP_destination = IP_address[msg]
    packet = [node2_MAC,"",node2_IP,IP_destination,"Hello"]
    
    packet[1] = ARP_Cache.get(IP_destination,"R2")
    packet = "|".join(packet)
    client.send(packet.encode("utf-8"))
    
    
def process_packet(packet):
    print("Processing packet")
    #Packet = mac source, mac destination, IP source, IP destination, Data 
    packet = packet.split("|")
    if packet[1] != node2_MAC: 
        print("Packet dropped")
    else: 
        if packet[3] == node2_IP:
            print(f'Source IP Address: {packet[2]}, Data: {packet[-1]}')
        else:
            print("Processing Error") 
            

receive_thread = threading.Thread(target=client_receive)
receive_thread.start()

send_thread = threading.Thread(target=client_send)
send_thread.start()