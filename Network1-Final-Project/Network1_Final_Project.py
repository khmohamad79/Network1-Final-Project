import link_layer
import network_layer
import transport_layer
import application_layer
from utilities import *

import socket
import struct
import _thread

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

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
i=0
while i<500:
    i +=1
    raw_data, address = conn.recvfrom(65535)
    parse_packet(raw_data)
    print(80*'=')
    print(80*'=')
    #_thread.start_new_thread(parse_packet, (raw_data,))


# main
# frame = fetchFrame()
# segment = frame.next()
# datagram = segment.next()



