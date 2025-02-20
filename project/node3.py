import socket
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host, port = "127.0.0.1", 8100
client.connect((host, port))

node3_IP = "0x2B"
node3_MAC = "N3"

IP_address = {
    "node1": "0x1A",
    "node2": "0x2A",
    "router": "0x21"
}

#MAC address of each Node 
ARP_Cache = {
    "0x21":"R2", #router
    "0x2A":"N2"  #Node2
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
        msg = input("Ping (node1, node2): ")
        construct_packet(msg)
        
        
def construct_packet(msg):#either node1, node2  
    #Ethernet frame: MAC Source | MAC Destination | length | data/IP Packet 
    #IP packet IP source | IP destination | Protocol | data length | Data 
    IP_destination = IP_address[msg]
    #Packet = mac source, mac destination, IP source, IP destination, Data 
    packet = [node3_MAC,"",node3_IP,IP_destination,"Hello"]
    packet[1] = ARP_Cache.get(IP_destination,"R2")
    packet = "|".join(packet)
    client.send(packet.encode("utf-8"))
    
    
def process_packet(packet):
    print("Processing packet")
    #Packet = mac source, mac destination, IP source, IP destination, Data 
    packet = packet.split("|")
    if packet[1] != node3_MAC: 
        print("Packet dropped")
    else: 
        if packet[3] == node3_IP:
            print(f'Source IP Address: {packet[2]}, Data: {packet[-1]}')
        else:
            print("Processing Error")         
        
receive_thread = threading.Thread(target=client_receive)
receive_thread.start()

send_thread = threading.Thread(target=client_send)
send_thread.start()