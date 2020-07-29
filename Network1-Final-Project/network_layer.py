from struct import *

class IPV4:
	def __init__(self, data):
		self.data = data
		ver, headlen, ToS, ECN, packetlength = unpack('! 4s 4s 6s 2s  H', data[:32])
		self.version = int(ver)
		self.header_length = int(headlen)
		self.ToS = int(ToS)
		self.ECN = int(ECN)
		self.packetlength= packetlength
		if self.version != 4:
			print("Wrong IP version")
		else:
			pass


	def next(self):
		pass


class ICMP:
	def __init__(self):
		pass