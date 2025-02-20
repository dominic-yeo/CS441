import socket
import threading

node1_IP = "0x1A"
node1_MAC = "N1"

IP_address = {
    "node2" : "0x2A",
    "node3" : "0x2B",
    "router": "0x11"
}

router_MAC = "R1"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host, port = "127.0.0.1", 8000
client.connect((host, port))

def client_receive():
    while True: 
        try: 
            packet = client.recv(1024).decode("utf-8")
            print("Packet received: " + packet)
            #process packet
            process_packet(packet) 
        except: 
            print("Error")
            client.close()
            break 

def client_send():
    while True: 
        msg = input("Ping (node2, node3): ")
        # client.send(msg.encode("utf-8"))
        construct_packet(msg)

def construct_packet(msg): #node 2 or node 3 
    #Ethernet frame: MAC Source | MAC Destination | length | data/IP Packet 
    #IP packet IP source | IP destination | Protocol | data length | Data 
    ip_des = IP_address[msg] 
    
    #node1 be default always send to router MAC
    #Packet = mac source, mac destination, IP source, IP destination, Data 
    packet = node1_MAC + "|" + router_MAC + "|" + node1_IP + "|" + ip_des + "|" + "Hello"
    client.send(packet.encode("utf-8"))
    
def process_packet(packet):
    print("Processing packet")
    #Packet = mac source, mac destination, IP source, IP destination, Data 
    packet = packet.split("|")
    if packet[1] != node1_MAC: 
        print("Packet dropped")
    else: 
        if packet[3] == node1_IP:
            print(f'Source IP Address: {packet[2]}, Data: {packet[-1]}')
        else:
            print("Processing Error") 
             
        

receive_thread = threading.Thread(target=client_receive)
receive_thread.start()

send_thread = threading.Thread(target=client_send)
send_thread.start()