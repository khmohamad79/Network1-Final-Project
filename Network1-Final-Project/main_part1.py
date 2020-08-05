import link_layer
import network_layer
import transport_layer
import application_layer
from utilities import *

import socket
import struct
from pcap import Pcap

def parse_packet(raw_data):
    layer = link_layer.Ethernet(raw_data)
    print(layer)
    while callable(getattr(layer, 'next', None)):
        temp = type(layer).__name__
        layer = layer.next()
        if isinstance(layer, bytes) and len(layer) > 0:
            print('► ' + temp + ' Unparsed Data: ')
            print(layer)
            # print(bytes_to_ascii(layer))
        elif isinstance(layer, bytes):
            pass
        else:
            print(layer)


filename = input('Enter pcap filename: ')
pcap = Pcap(filename)

try:
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, address = conn.recvfrom(65535)
        pcap.write_data(raw_data)
        parse_packet(raw_data)
        print(80*'=')
        print(80*'=')
except:
    pass

pcap.close()
print(80*'=')
