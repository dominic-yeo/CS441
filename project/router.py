import socket
import threading

router_IP1, router_IP2 = "0x11", "0x21"
router_MAC1, router_MAC2 = "R1", "R2"

#MAC address of each Node
ARP_Cache = {
   "0x1A": "N1",
   "0x2A": "N2",
   "0x2B": "N3"
 }

clients = []

def handle_client(client_socket, addr):
    try:
        while True:
            # receive and print client messages
            request = client_socket.recv(1024).decode("utf-8")
            if request.lower() == "close":
                client_socket.send("closed".encode("utf-8"))
                break
            print(f"Received packet: {request}")
            #process message
            process_msg(client_socket,request) 
            
    except Exception as e:
        print(f"Error when hanlding client: {e}")
    finally:
        client_socket.close()
        print(f"Connection to client ({addr[0]}:{addr[1]}) closed")

def process_msg(client_socket, msg):
    print("Processing packet")    
    msg = msg.split("|")
    #Packet = mac source, mac destination, IP source, IP destination, Data
    if msg[1] == router_MAC1 or msg[1] == router_MAC2: 
        ip_destination = msg[3]
        mac_destination = ARP_Cache[ip_destination]
        mac_source = router_MAC2 if msg[1] == router_MAC1 else router_MAC1
        msg[0] = mac_source
        msg[1] = mac_destination
        msg = "|".join(msg)
        #reply
        print(f'Update MAC headers: Source: {mac_source}, Destination: {mac_destination}') 
        reply_client = clients[0]
        if reply_client == client_socket:
            reply_client = clients[1]

        print("Routing packet")
        reply_client.send(msg.encode("utf-8"))
    else:
        #check ip destination and change mac source and mac destination  
        print("Packet dropped")
    

#To receive incoming connections and created threads
def run_server():
    server_ip, port = "127.0.0.1", 8000 
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket to the host and port
        server.bind((server_ip, port))
        # listen for incoming connections
        server.listen()
        print(f"Listening on {server_ip}:{port}")

        while True:
            # accept a client connection
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr[0]}:{addr[1]}")
            # start a new thread to handle the client
            clients.append(client_socket)
            thread = threading.Thread(target=handle_client, args=(client_socket, addr,))
            thread.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close()


run_server()

