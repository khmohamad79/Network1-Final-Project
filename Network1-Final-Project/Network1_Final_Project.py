import link_layer
import network_layer
import transport_layer
import application_layer

import socket
import struct 


conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    raw_data, address = conn.recvfrom(65535)
    segment = link_layer.Ethernet(raw_data)

# main
# frame = fetchFrame()
# segment = frame.next()
# datagram = segment.next()



