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

	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			if self.proto == 2048:
				self.nextlayer = IPV4(self.data[14:])
			elif self.proto == 2054:
				self.nextlayer = ARP(self.data[14:])
			else:
				print("Error: Protocol Number " + str(self.proto) + " Not Identified")
				self.nextlayer = self.data[14:]
			return self.nextlayer


class ARP:
	def __init__(self, data):
		self.data = data
		Htype, Ptype, Hlength, Plength, OP = struct.unpack('! H H B B H', data[:8])
		self.Htype = Htype
		self.Ptype = Ptype
		self.Hlength = Hlength
		self.Plength = Plength
		self.OP = OP
		start = 8;
		self.SHA = data[start:start+Hlength]
		start += Hlength
		self.SPA = data[start:start+Plength]
		start += Plength
		self.THA = data[start:start+Hlength]
		start += Hlength
		self.TPA = data[start:start+Plength]
		start += Plength
		self.start = start
		

	def next(self):
		return self.data[self.start:]