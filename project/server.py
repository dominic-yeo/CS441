import socket
import threading

#connects to router
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host, port = "127.0.0.1", 8000
client.connect((host, port))

connections = []
connections.append(client)

#receves packet from router 
def client_receive():
    while True: 
        try: 
            msg = client.recv(1024).decode("utf-8")
            print("Packet received from router: " + msg)            
            #broad cast to node 2 & 3
            broadcast(client,msg)
        except: 
            print("Error")
            client.close()
            break 

def broadcast(s, msg):
    print("Broadcasting packet")    
    for socket in connections:
        if s != socket: 
            socket.send(msg.encode("utf-8"))


#Receive connections from node 2 & node 3
def run_server():
    server_ip, port = "127.0.0.1", 8100 
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
            # clients.append(client_socket)
            connections.append(client_socket)
            thread = threading.Thread(target=handle_client, args=(client_socket, addr,))
            thread.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close()

#handles msg incoming from node 2 and 3 
def handle_client(client_socket, addr):
    try:
        while True:
            # receive and print client messages
            request = client_socket.recv(1024).decode("utf-8")
            if request.lower() == "close":
                client_socket.send("closed".encode("utf-8"))
                break
            print(f"Received: {request}")
            
            broadcast(client_socket, request) 
            
            
    except Exception as e:
        print(f"Error when hanlding client: {e}")
    finally:
        client_socket.close()
        print(f"Connection to client ({addr[0]}:{addr[1]}) closed")

receive_thread = threading.Thread(target=client_receive)
receive_thread.start()        
run_server()