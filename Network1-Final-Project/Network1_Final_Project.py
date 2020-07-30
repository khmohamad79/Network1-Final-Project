import link_layer
import network_layer
import transport_layer
import application_layer

import socket
import struct
import _thread

def parse_packet(raw_data):
    frame = link_layer.Ethernet(raw_data)
    print(frame.src_mac)
    print(frame.dest_mac)
    print(type(frame))

    segment = frame.next()
    print(type(segment))
    if(frame.proto==2054):
        print("ARP Data:", str(segment.next()))
    elif frame.proto==2048:
        print("Source IP: ", segment.srcip)

    datagram = segment.next()
    print(type(datagram))

    application = datagram.next()
    print(type(application))


def parse_packet2(raw_data):
    layer = link_layer.Ethernet(raw_data)
    print(type(layer))
    while callable(getattr(layer, 'next', None)):
        layer = layer.next()
        print(type(layer))
        if isinstance(layer, application_layer.HTTP):
            print(layer)
        if isinstance(layer, application_layer.DNS):
            print(layer)

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
i=0
while i<100:
    i +=1
    raw_data, address = conn.recvfrom(65535)
    parse_packet2(raw_data)
    print(30*'-')
    #_thread.start_new_thread(parse_packet2, (raw_data,))


# main
# frame = fetchFrame()
# segment = frame.next()
# datagram = segment.next()



