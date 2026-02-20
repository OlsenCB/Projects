# HackTheBox: Intro to Network Traffic Analysis - Technical Walkthrough

## Networking Primer - Layers 1-4

### Q1: How many layers does the OSI model have?
The standard OSI model consists of **7 layers**, which serves as a conceptual framework for understanding network interactions.
* **Physical Layer:** Handles physical components like cables and network cards.
* **Data-Link Layer:** Switches operate here, forwarding frames within a LAN using MAC addresses.
* **Network Layer:** Routers operate here, directing packets between different networks using IP addresses.
* **Transport Layer:** Responsible for end-to-end communication, port selection, and protocols (TCP/UDP).
* **Session Layer:** Manages the establishment, maintenance, and termination of sessions between applications.
* **Presentation Layer:** Ensures data is in a usable format for the application, handling encryption and compression.
* **Application Layer:** The layer closest to the user, where protocols like HTTP, FTP, and DNS operate.



[Image of the 7 layers of the OSI model]


---

### Q2: How many layers are there in the TCP/IP model?
The TCP/IP model is a simplified version of OSI. In the 5-layer version, the Physical, Data-Link, Network, and Transport layers remain, while Session, Presentation, and Application are merged into a single **Application Layer**. In the 4-layer version, Physical and Data-Link are merged into the **Link Layer**.

---

### Q3: True or False: Routers operate at layer 2 of the OSI model?
**False**. Routers direct traffic between networks based on logical addressing, meaning they operate at the **Network Layer (Layer 3)**.

---

### Q4: What addressing mechanism is used at the Link Layer of the TCP/IP model?
At the Link Layer, communication is based on physical addressing, specifically the **MAC-Address**.

---

### Q5: At what layer of the OSI model is a PDU encapsulated into a packet? (the number)
The Protocol Data Unit (PDU) changes names at each layer. It becomes a **packet** at **Layer 3** (Network Layer). For comparison, it is a "frame" at Layer 2 and a "segment" or "datagram" at Layer 4.

---

### Q6: What addressing mechanism utilizes a 32-bit address?
**IPv4** utilizes 4 bytes, totaling **32 bits**. In contrast, MAC addresses use 48 bits, and IPv6 uses 128 bits.

---

### Q7: What Transport layer protocol is connection oriented?
**TCP** (Transmission Control Protocol) is connection-oriented because it relies on the **three-way handshake**, requiring every packet to be acknowledged to ensure reliability.

---

### Q8: What Transport Layer protocol is considered unreliable?
**UDP** (User Datagram Protocol) is considered unreliable or connectionless. It sends data in a continuous stream without checking if the recipient received it, prioritizing speed over accuracy.

---

### Q9: What is the final packet of the TCP three-way handshake?
The sequence is: 1. **SYN**, 2. **SYN/ACK**, and 3. **ACK** (Acknowledge). The final ACK packet confirms that the connection is established.



---

## Networking Primer - Layers 5-7

### Q1: What is the default operational mode method used by FTP?
FTP supports Passive and Active modes. **Active** mode is the default, where the server initiates the data connection back to the client.

---

### Q2: FTP utilizes what two ports for command and data transfer?
FTP uses port **20** for data transfer and port **21** for issuing commands and controlling the session.

---

### Q3: Does SMB utilize TCP or UDP as its transport layer protocol?
Modern SMB relies on **TCP**. This protocol is significant in security history due to the **WannaCry** attack, which exploited vulnerabilities in SMB version 1.

---

### Q4: SMB has moved to using what TCP port?
SMB now primarily operates on TCP port **445**.

---

### Q5: Hypertext Transfer Protocol uses what well known TCP port number?
Unencrypted **HTTP** uses port **80**. For security, **HTTPS** (port **443**) was created to encrypt traffic via TLS, preventing attackers from reading intercepted data in cleartext.

---

### Q6: What HTTP method is used to request information and content from the webserver?
The **GET** method is used to retrieve data or content from a web server.

---

### Q7: What web based protocol uses TLS as a security measure?
**HTTPS** uses **TLS** (Transport Layer Security) to encrypt data. It replaced the now-deprecated and insecure SSL protocol.

---

### Q8: True or False: when utilizing HTTPS, all data sent across the session will appear as TLS Application data?
**True**. Once the TLS handshake is complete, all HTTP layer information (URL, headers, payload) is encrypted and encapsulated as **Application Data**.

---

## Tcpdump Fundamentals

### Q1: Utilizing the output shown in question-1.png, who is the server in this communication?
The server is **174.143.213.184**. We can see the client (192.168.1.140) initiated communication from a high ephemeral port (57678) to the standard **HTTP port 80** on the server.

![Tcpdump Server Identification](screenshots/tcpdump_server.png)

---

### Q2: Were absolute or relative sequence numbers used during the capture?
**Relative** sequence numbers were used. By default, tcpdump displays relative numbers for readability unless the `-S` (Absolute) switch is specified.

---

### Q3: What are the switches for: no hostname resolution, verbose, ASCII/Hex, and first 100 packets?
The correct command is `tcpdump -nvXc 100`.
* `-n`: No DNS resolution.
* `-v`: Verbose output.
* `-X`: Display content in Hex and ASCII.
* `-c 100`: Capture a count of 100 packets.

---

### Q4: What tcpdump command will enable you to read from a capture and show contents in Hex and ASCII?
The command is `sudo tcpdump -Xr [path]`. The `-r` switch is used to read a pcap file.

---

### Q5: What TCPDump switch will increase the verbosity of our output?
The switch is **-v**. Multiple 'v's (e.g., `-vv`) further increase verbosity.

---

### Q6: What built in terminal help reference can tell us more about TCPDump?
The **man** (Manual) page is the standard reference. Running `man tcpdump` provides detailed information about parameters.

---

### Q7: What TCPDump switch will let me write my output to a file?
The **-w** switch is used to write captured packets to a file.

---

## Fundamentals Lab

### Q1: What TCPDump switch will allow us to pipe the contents of a pcap file out to another function?
The **-l** switch puts the stdout line buffered, allowing you to pipe the output to tools like `grep` or `awk` effectively.

---

### Q2: True or False: The filter "port" looks at source and destination traffic.
**True**. The `port` filter captures packets where the specified port is either the source or the destination.

---

### Q3: If we wished to filter out ICMP traffic from our capture, what filter could we use?
We use the word **not** (e.g., `tcpdump not icmp`).

---

### Q4: What command will show you where / if TCPDump is installed?
The **which** command (e.g., `which tcpdump`) identifies the binary's location.

---

### Q5: How do you start a capture with TCPDump to capture on eth0?
We use the **-i** switch: `tcpdump -i eth0`.

---

## Interrogating Network Traffic

### Q1: What are the client and server port numbers used in first full TCP three-way handshake?
Using `sudo tcpdump -nc 20 -r file proto TCP`, I looked for the `[S]` (SYN) and `[.]` (ACK) sequence. Client port **43806** was the first to successfully complete the handshake with server port **80** after a previous attempt on port 43804 was reset.

![TCP Handshake Discovery](screenshots/handshake_ports.png)

---

### Q2: Based on the traffic seen in the pcap file, who is the DNS server?
Filtering for port 53 (`sudo tcpdump -nc 20 -r file port 53`) reveals that the IP ending in **.1** is providing DNS resolution services.

![DNS Server Identification](screenshots/dns_traffic.png)

---

## Wireshark

### Q1: True or False: Wireshark can run on both Windows and Linux.
**True**. Wireshark is cross-platform and includes a CLI version called **TShark**.

---

### Q2: Which Pane allows a user to see a summary of each packet grabbed?
The **Packet List** pane provides a high-level summary of every packet captured.

---

### Q3: Which pane displays traffic in both ASCII and Hex?
The **Packet Bytes** pane shows the raw data in both formats.

---

### Q4: What switch is used with TShark to list possible interfaces?
The **-D** switch lists available interfaces.

---

### Q5: What switch allows us to apply filters in TShark?
The **-f** switch is used for capture filters (e.g., `tshark -f "host 1.1.1.1"`).

---

### Q6: Is a capture filter applied before the capture starts or after?
**Before**. Capture filters must be defined at the start to determine what data is recorded.

---

## Familiarity With Wireshark

### Q1: Which plugin tab provides conversation metadata for the entire PCAP file?
The **Statistics -> Conversations** window provides a detailed breakdown of all host-to-host communications.

![Wireshark Conversations](screenshots/wireshark_conversations.png)

---

### Q2: What plugin tab will allow me to accomplish tasks such as following streams?
The **Analyze** tab is used to follow streams (TCP/HTTP) and view expert info.

---

### Q3: What stream oriented Transport protocol enables us to follow conversations?
**TCP** is stream-oriented, allowing Wireshark to rebuild and follow the entire conversation.

---

### Q4: True or False: Wireshark can extract files from HTTP traffic.
**True**. By going to **File -> Export Objects -> HTTP**, we can reconstruct and save files transferred over the network.

---

### Q5: True or False: The ftp-data filter will show us any data sent over TCP port 21.
**False**. Port 21 is for FTP Control. Actual data is sent over port 20 or ephemeral ports, which is what the `ftp-data` filter tracks.

---

## Packet Inception & Guided Lab

### Q1: What was the filename of the image that contained a certain Transformer Leader?
By filtering for HTTP GET requests and images, I found **Rise-up.jpg**.

![HTTP Object Export](screenshots/http_objects.png)

---

### Q2: What was the name of the new user created on mrb3n's host?
By using **Follow TCP Stream** on the suspicious traffic on port 4444, I identified the creation of a user named **h4xor**.

![TCP Stream Analysis](screenshots/tcp_stream_user.png)

---

### Q3: What was the suspicious port that was being used?
The attacker used port **4444**, a common default for reverse shells.

---

### Q4: What user account was used to initiate the RDP connection?
After adding the RSA key in **Preferences -> Protocols -> TLS**, I decrypted the RDP traffic to reveal the username **mrb3n**.

![TLS Decryption Settings](screenshots/tls_config.png)
![RDP Decryption Configuration](screenshots/rdp_config_details.png)
![Decrypted RDP Traffic](screenshots/rdp_decrypted.png)

---

## Summary
In this module, I learned how to analyze network traffic using both CLI and GUI tools. I practiced rapid filtering with **tcpdump** and performed deep forensic analysis with **Wireshark**, including following TCP streams and decrypting TLS-encrypted RDP sessions. These skills are essential for identifying unauthorized actions and understanding protocol behavior at a packet level.