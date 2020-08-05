from struct import *
from application_layer import *
import socket
import random
from utilities import *

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

	def generatePacket(src_ipv4, dest_ipv4, dest_port, syn, ack, fin, window = 120):
		temp1 = ipv4_to_bytes(src_ipv4)
		temp2 = ipv4_to_bytes(dest_ipv4)
		temp3 = bytes([0, 6, 0, 20])
		src_port = random.randint(1024, 65535)
		dest_port = dest_port
		seq_num = random.randint(0, 0xFFFFFFFF)
		ack_num = random.randint(0, 0xFFFFFFFF)
		data_offset = 5
		NS = 0
		FIN = fin
		SYN = syn
		RST = 0
		PSH = 0
		ACK = ack
		URG = 0
		ECE = 0
		CWR = 0
		window_size = window
		checksum = 0
		urg_pointer = 0
		byte25 = bits_to_int([0,1,0,1,0,0,0,NS])
		byte26 = bits_to_int([CWR, ECE, URG, ACK, PSH, RST, SYN, FIN])
		checksum = calc_checksum(pack('! 4s 4s 4s H H L L B B H H H', temp1, temp2, temp3, src_port, dest_port, seq_num, ack_num, byte25, byte26, window_size, checksum, urg_pointer))
		data = pack('! H H L L B B H H H', src_port, dest_port, seq_num, ack_num, byte25, byte26, window_size, checksum, urg_pointer)
		return TCP(data)

	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			try:
				if (self.dest_port == 53 or self.src_port == 53):
					self.nextlayer = DNS(self.data[self.data_offset*4:])
				elif (self.dest_port == 80 or self.src_port == 80):
					self.nextlayer = HTTP(self.data[self.data_offset*4:])
				else:
					#print("Undefined Port Number src:" + str(self.src_port) + " dst:" + str(self.dest_port))
					self.nextlayer = self.data[self.data_offset*4:]
			except Exception as e:
				print("Exception in TCP.next")
				self.nextlayer = self.data[self.data_offset*4:]
			return self.nextlayer

	def __str__(self):
		string = "► TCP (Transmission Control Protocol)\n"
		string += "\tSource Port: " + str(self.src_port) + "\n"
		string += "\tDestination Port: " + str(self.dest_port) + "\n"
		string += "\tSequence Number: " + str(self.seq_num) + "\n"
		string += "\tAcknowledgment Number: " + str(self.ack_num) + "\n"
		string += "\tHeader Length: " + str(self.data_offset*4) + " Bytes\n"
		string += "\tFlags: \n"
		string += "\t\tNS: " + str(self.NS) + "\n"
		string += "\t\tCWR: " + str(self.CWR) + "\n"
		string += "\t\tECE: " + str(self.ECE) + "\n"
		string += "\t\tURG: " + str(self.URG) + "\n"
		string += "\t\tACK: " + str(self.ACK) + "\n"
		string += "\t\tPSH: " + str(self.PSH) + "\n"
		string += "\t\tRST: " + str(self.RST) + "\n"
		string += "\t\tSYN: " + str(self.SYN) + "\n"
		string += "\t\tFIN: " + str(self.FIN) + "\n"
		string += "\tWindow Size: " + str(self.window_size) + "\n"
		string += "\tChecksum: " + str(hex(self.checksum)) + "\n"
		string += "\tUrgent Data Pointer: " + str(self.urg_pointer) + "\n"
		if hasattr(self, "option"):
			string += "\tOptions: \n\t\t" + str(self.option) + "\n"
		return string


class UDP:
	def __init__(self, data):
		self.data = data
		self.src_port, self.dest_port, self.UDPlength ,self.checksum = unpack('! H H H H', data[:8])
		
	def next(self):
		if hasattr(self, 'nextlayer'):
			return self.nextlayer
		else:
			try:
				if (self.dest_port == 53 or self.src_port == 53):
					self.nextlayer = DNS(self.data[8:self.UDPlength]) # [8:]
				elif (self.dest_port == 80 or self.src_port == 80):
					self.nextlayer = HTTP(self.data[8:self.UDPlength]) # [8:]
				else:
					#print("Undefined Port Number src:" + str(self.src_port) + " dst:" + str(self.dest_port))
					self.nextlayer = self.data[8:self.UDPlength] # [8:]
			except:
				print("Exception in UDP.next")
				self.nextlayer = self.data[8:self.UDPlength]
			return self.nextlayer

	def __str__(self):
		string = "► UDP (User Datagram Protocol)\n"
		string += "\tSource Port: " + str(self.src_port) + "\n"
		string += "\tDestination Port: " + str(self.dest_port) + "\n"
		string += "\tLength: " + str(self.UDPlength) + "\n"
		string += "\tChecksum: " + str(hex(self.checksum)) + "\n"
		return string