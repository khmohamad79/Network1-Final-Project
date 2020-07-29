from struct import *
from utilities import *
from transport_layer import *

class IPV4:
	def __init__(self, data):
		self.data = data
		ver_headlen, ToSECN, packetlength = unpack('! s s H', data[:32])
		self.version = int(ver_headlen)//16
		self.header_length = int(ver_headlen) - (self.version*16)
		self.ToS = int(ToSECN)//4
		self.ECN = int(ToSECN) - (self.ToS*4)
		self.packetlength= packetlength
		ID, fraginfo, ttl , proto, headerchecksum, src_ip, dest_ip = unpack('! H 2s B B H 4s 4s', data[32:160])
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
			self.option = unpack(cond,data[160:160+(self.header_length-5)*32])
		if self.proto == 1:
			self.nextlayer = ICMP(self.data[(160+(self.header_length-5)*32):])
		elif self.proto == 6:
			self.nextlayer = TCP(self.data[(160+(self.header_length-5)*32):])
		elif self.proto == 17:
			self.nextlayer = UDP(self.data[(160+(self.header_length-5)*32):])
		else:
			print("Wrong Protocol Number")
			self.nextlayer = data[(160+(self.header_length-5)*32):]

	def next(self):
		return self.nextlayer


class ICMP:
	def __init__(self, data):
		self.data = data
		Type, Code, Checksum, ROH = unpack('! B B 2s 4s', data[:64])
		self.type = Type
		self.code = code
		self.checksum = Checksum
		self.restofheader = ROH
		self.nextlayer = data[64:]

	def next(self):
		return self.nextlayer