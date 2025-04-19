## Overview
This project is a hands-on implementation designed for the CS441 course. It emulates a simplified IP-over-Ethernet network with additional security features to demonstrate practical network security concepts and system implementation skills.

## Project Description
The emulated network comprises three nodes and one router:

### Nodes:
Node1 with IP 0x1A and MAC N1
Node2 with IP 0x2A and MAC N2
Node3 with IP 0x2B and MAC N3

### Router:
Has two interfaces:
R1 (for subnet 1) with IP 0x11
R2 (for subnet 2) with IP 0x21
Listens on a fixed port (10000) for inter-subnet traffic.

### Emulated Protocols and Features
**Ethernet Emulation:**
Emulates Ethernet frames with a structure that includes source MAC, destination MAC, a data length, and payload data. Broadcast is implemented by sending frames to all nodes in a subnet, where nodes filter based on destination MAC.

**IP Emulation:**
Encapsulates IP packets with a format including source IP, destination IP, protocol identifier, data length, and payload.

**Ping Protocol:**
A ping message triggers an automatic reply with the same message (marked with "[PING REPLY]") to demonstrate basic protocol functionality.

**IP Spoofing:**
Node1 can impersonate Node3 to simulate malicious packet injection.

**Sniffing Attack:**
A node can be put into sniffer mode to capture and display packets not directly addressed to it, simulating a network sniffing attack.

**Firewall:**
Nodes (e.g., Node3) can be configured with firewall rules to block packets from specified sources.

**IP fragmentation:**
IP fragmentation is the process of breaking a large IP packet into smaller fragments so that they can traverse networks. This process occurs when when the IP packet exceeds 256 bytes.

**Teardrop Attack:**
A node (attacker) can send malformed, overlapping IP fragments with manipulated offset values to another node (victim). When the victim attempts to reassemble these fragments, it encounters errors or buffer overflows, causing the system to crash.

**TCP/TLS Handshake:**
A node (client) can establish TCP/TLS handshake with the server to setup a secure channel for data transfer. 

**SSL Downgrade:**
An attacker can perform a SSL downgrade attack by tricking the client and server into using an older, less secure protocol version.

## Files
### router.py:
Implements the router’s functionality. It receives Ethernet frames, parses the embedded IP packet, updates the frame headers, and forwards packets to the appropriate subnet based on the destination IP.

### node.py:
Implements the node functionalities. It handles:

## Receiving and processing Ethernet frames.
Sending messages either directly to local nodes or via the router for inter-subnet communication.
Interactive configuration of firewall rules and enabling packet sniffing.
A simple mechanism for IP spoofing using a command-line flag.


## How to Run
### Prerequisites
Python 3.x
Ensure that Python 3 is installed on your system. This project uses Python's built-in libraries (socket, threading), so no additional packages are needed.

#### Running the Router
Open a terminal.

Navigate to the project directory.

Run the following command:
```
python router.py
```
The router will start listening on port 10000 and log incoming connections and packet forwarding events.

#### Running a Node
Open a separate terminal for each node.
Run the following command:
```
python node.py
```
When prompted, enter the node's MAC address (e.g., N1, N2, or N3).

You will be prompted to add firewall rules (e.g., entering block 2B to block packets from a specific IP) and to decide whether to enable packet sniffing.

Once the node's server is running, send messages using the format:
```
<dest_ip> <message>
```
For example:
```
1A Hello World
```
To test IP spoofing, include the -s flag in the message as documented in the code comments.

Security Features:

IP Spoofing: Node1 can send spoofed packets to impersonate another node.

Sniffing: Nodes can be set to sniff packets not directly addressed to them.

Firewall: Nodes can add custom firewall rules to filter incoming packets.
