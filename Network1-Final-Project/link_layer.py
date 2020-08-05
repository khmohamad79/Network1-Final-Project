import struct
from network_layer import *
from utilities import *

class Ethernet:
	def __init__(self, data):
		self.data = data
		self.dest, self.src, proto = struct.unpack('! 6s 6s H', data[:14]) 
		self.dest_mac = reformat_address(self.dest.hex(), 2, ':')
		self.src_mac = reformat_address(self.src.hex(), 2, ':')
		self.proto = proto

	def generatePacekt(dest_mac, src_mac, proto):
		data = pack('! 6s 6s H', dest_mac, src_mac, proto)
		return Ethernet(data)

	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			if self.proto == 2048:
				self.nextlayer = IPV4(self.data[14:])
			elif self.proto == 2054:
				self.nextlayer = ARP(self.data[14:])
			else:
				#print("Error: Protocol Number " + str(self.proto) + " Not Identified")
				self.nextlayer = self.data[14:]
			return self.nextlayer

	def __str__(self):
		string = "► Ethernet\n"
		string += "\tDestination: " + self.dest_mac + "\n"
		string += "\tSource: " + self.src_mac + "\n"
		string += "\tType: "
		if self.proto == 2048:
			string += "IPV4 (" + str(hex(self.proto)) + ")\n"
		elif self.proto == 2054:
			string += "ARP (" + str(hex(self.proto)) + ")\n"
		else:
			pass
			#string += "Undefined (" + str(hex(self.proto)) + "\n"
		return string


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
		cond = '! '
		cond += str(self.Hlength) + 's '
		cond += str(self.Plength) + 's '
		cond += str(self.Hlength) + 's '
		cond += str(self.Plength) + 's'
		self.SHA, self.SPA, self.THA, self.TPA = struct.unpack(cond, data[start: start + 2*self.Plength + 2*self.Hlength])
		#self.SHA = data[start:start+Hlength]
		#start += Hlength
		#self.SPA = data[start:start+Plength]
		#start += Plength
		#self.THA = data[start:start+Hlength]
		#start += Hlength
		#self.TPA = data[start:start+Plength]
		#start += Plength
		self.start = start + 2*self.Plength + 2*self.Hlength

	def generatePacket(Htype, Ptype, OP, SHA, SPA, THA, TPA):
		Hlength = len(SHA)
		Plength = len(SPA)
		cond = '! H H B B H '
		cond += str(Hlength) + 's '
		cond += str(Plength) + 's '
		cond += str(Hlength) + 's '
		cond += str(Plength) + 's'
		data = struct.pack(cond, Htype, Ptype, Hlength, Plength, OP, SHA, SPA, THA, TPA)
		return ARP(data)

	def next(self):
		return self.data[self.start:]

	def __str__(self):
		string = "► ARP (Address Resolution Protocol)\n"
		string += "\tHardware Type: " + str(self.Htype) + "\n"
		string += "\tProtocol Type: " + str(self.Ptype) + "\n"
		string += "\tHardware Address Length: " + str(self.Hlength) + "\n"
		string += "\tProtocol Address Length: " + str(self.Plength) + "\n"
		string += "\tOperation: " + str(self.OP) + "\n"
		string += "\tSender Hardware Address: " + str(reformat_address(self.SHA.hex(), 2, ':')) + "\n"
		string += "\tSender Protocol Address: " + str(reformat_ipv4(self.SPA)) + "\n"
		string += "\tTarget Hardware Address: " + str(reformat_address(self.THA.hex(), 2, ':')) + "\n"
		string += "\tTarget Protocol Address: " + str(reformat_ipv4(self.TPA)) + "\n"
		return string