import struct
from network_layer import *
from utilities import *

class Ethernet:
	def __init__(self, data):
		self.data = data
		dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) 
		self.dest_mac = reformat_address(dest_mac.hex(), 2, ':')
		self.src_mac = reformat_address(src_mac.hex(), 2, ':')
		self.proto = proto

		if self.proto == 2048:
			self.next_layer = IPV4(self.data[14:])
		elif self.proto == 2054:
			self.next_layer = ARP(self.data[14:])
		else:
		   print("Error: Protocol Number Not Identified")

	def next(self):
		return self.next_layer

class ARP:
	def __init__(self, data):
		self.data = data
		Htype, Ptype, Hlength, Plength, op = struct.unpack('! H H B B H', data[:64])
		self.Htype = Htype
		self.Ptype = Ptype
		self.Hlength = Hlength
		self.Plength = Plength
		self.op = op
		start = 64;
		self.SHA = data[start:start+Hlength*8]
		start += Hlength*8
		self.SPA = data[start:start+Plength*8]
		start += Plength*8
		self.THA = data[start:start+Hlength*8]
		start += Hlength*8
		self.TPA = data[start:start+Plength*8]
