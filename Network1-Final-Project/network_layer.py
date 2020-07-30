from struct import *
from utilities import *
from transport_layer import *

class IPV4:
	def __init__(self, data):
		self.data = data
		ver_headlen, ToSECN, packetlength = unpack('! B B H', data[:4])
		self.version = ver_headlen//16
		self.header_length = (ver_headlen) - (self.version*16)
		self.ToS = (ToSECN)//4
		self.ECN = (ToSECN) - (self.ToS*4)
		self.packetlength = packetlength
		ID, fraginfo, ttl , proto, headerchecksum, src_ip, dest_ip = unpack('! H 2s B B H 4s 4s', data[4:20])
		self.ID = ID
		self.frag_flag = int(fraginfo[0])//32
		self.frag_offset = int(fraginfo[1]) + 256*(int(fraginfo[0]) - self.frag_flag*32)
		self.ttl = ttl
		self.proto = proto
		self.checksum = headerchecksum
		self.srcip = reformat_ipv4(src_ip)
		self.destip = reformat_ipv4(dest_ip)
		if self.header_length>5:
			cond = '! ' + str(self.header_length - 5) + 's'
			self.option = unpack(cond,data[20:self.header_length*4])


	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			try:
				if self.proto == 1:
					self.nextlayer = ICMP(self.data[self.header_length*4:])
				elif self.proto == 6:
					self.nextlayer = TCP(self.data[self.header_length*4:])
				elif self.proto == 17:
					self.nextlayer = UDP(self.data[self.header_length*4:])
				else:
					print("Wrong Protocol Number " + str(self.proto))
					self.nextlayer = self.data[self.header_length*4:]
			except:
				print("Exception in IPV4.next")
				self.nextlayer = self.data[self.header_length*4:]
			return self.nextlayer


class ICMP:
	def __init__(self, data):
		self.data = data
		Type, Code, Checksum, ROH = unpack('! B B H 4s', data[:8])
		self.type = Type
		self.code = code
		self.checksum = Checksum
		self.restofheader = ROH

	def next(self):
		return self.data[8:]