# Network1 Final Project

**Packet Sniffer** *part1*
* protocols: Ethernet, ARP, IPV4, ICMP, TCP, UDP, HTTP, DNS
* pcap writer
		 
**Port Scanner** *part2*
* modes: Connect, ACK, SYN, FIN, Windows
* parallel and multiple port scanning

**Packet Responder** *part3*
* replies these packets:
	* ARP Requests (arp.Operation == 1)
	* any ICMPs except Replies (arp.Type != 0)
	* DNS standard Queries (arp.OpCode == 0)
