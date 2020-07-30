from struct import *
from application_layer import *

class TCP:
	def __init__(self, data):
		self.data = data
		self.src_port, self.dest_port, self.seq_num, self.ack_num, DataFlags, self.window_size, self.checksum, self.urg_pointer = unpack('! H H L L 2s H H H', data[:20])
		self.data_offset = DataFlags[0] // 16
		self.NS = 1 if (DataFlags[0]&1)>0 else 0
		self.FIN = 1 if (DataFlags[1]&1)>0 else 0
		self.SYN = 1 if (DataFlags[1]&2)>0 else 0
		self.RST = 1 if (DataFlags[1]&4)>0 else 0
		self.PSH = 1 if (DataFlags[1]&8)>0 else 0
		self.ACK = 1 if (DataFlags[1]&16)>0 else 0
		self.URG = 1 if (DataFlags[1]&32)>0 else 0
		self.ECE = 1 if (DataFlags[1]&64)>0 else 0
		self.CWR = 1 if (DataFlags[1]&128)>0 else 0
		if self.data_offset > 5:
			self.option = data[20:self.data_offset*4]

	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			try:
				if self.dest_port == 53 or self.src_port == 53:
					self.nextlayer = DNS(self.data[self.data_offset*4:])
				elif self.dest_port == 80 or self.src_port == 80:
					self.nextlayer = HTTP(self.data[self.data_offset*4:])
				else:
					print("Undefined Port Number src:" + str(self.src_port) + " dst:" + str(self.dest_port))
					self.nextlayer = self.data[self.data_offset*4:]
			except:
				print("Exception in TCP.next")
				self.nextlayer = self.data[self.data_offset*4:]
			return self.nextlayer

class UDP:
	def __init__(self, data):
		self.data = data
		self.src_port, self.dest_port, self.UDPlength ,self.checksum = unpack('! H H H H', data[:8])
		
	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			try:
				if self.dest_port == 53 or self.src_port == 53:
					self.nextlayer = DNS(self.data[8:self.UDPlength]) # [8:]
				elif self.dest_port == 80 or self.src_port == 80:
					self.nextlayer = HTTP(self.data[8:self.UDPlength]) # [8:]
				else:
					print("Undefined Port Number src:" + str(self.src_port) + " dst:" + str(self.dest_port))
					self.nextlayer = self.data[8:self.UDPlength] # [8:]
			except:
				print("Exception in UDP.next")
				self.nextlayer = self.data[self.data_offset*4:]
			return self.nextlayer

