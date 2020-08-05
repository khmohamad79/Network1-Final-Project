import link_layer
import network_layer
import transport_layer
import application_layer
from utilities import *

import socket

input("""
this script replies these packets:
    ARP Requests (arp.Operation == 1)
    any ICMPs except Replies (arp.Type != 0)
    DNS standard Queries (arp.OpCode == 0)

    Ctrl+C to finish.
    Press ENTER to continue.""")
print(80*"=")

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    raw_data, address = raw_socket.recvfrom(65535)
    frame = link_layer.Ethernet(raw_data)
    fragment = frame.next()
    if isinstance(fragment, link_layer.ARP) and fragment.OP == 1:
        print('ARP Received.')
        eth = link_layer.Ethernet.generatePacekt(frame.src, frame.dest, frame.proto)
        arp = link_layer.ARP.generatePacket(1,0x0800,2,bytes(6),bytes(4),bytes(6),bytes(4))
        packet = eth.data + arp.data
        raw_socket.sendto(packet, (address[0], address[1]))
        print('ARP Sent.')
    elif isinstance(fragment, network_layer.IPV4):
        segment = fragment.next()
        if isinstance(segment, network_layer.ICMP) and segment.type != 0:
            print('ICMP Received.')
            icmp = network_layer.ICMP.generatePacket(0, 0, bytes(4))
            try:
                icmp_socket.sendto(icmp.data, (fragment.srcip, 0))
                print('ICMP Sent.')
            except socket.gaierror as e:
                print('ICMP is Forbidden.' + str(e))
        elif isinstance(segment, transport_layer.UDP):
            application = segment.next()
            if isinstance(application, application_layer.DNS) and application.opcode == 0:
                print('DNS Received.')
                dns = application_layer.DNS.generatePacket()
                udp_socket.sendto(dns.data, (fragment.srcip, segment.src_port))
                print('DNS Sent.')

print(80*"=")