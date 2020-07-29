from struct import *

class DNS:
	def __init__(self, data):
		self.data = data
		self.ID, flags, self.NoQues, self.NoAns, self.NoAuth, self.NoAdd = unpack('! H H H H H H', data[:96])
		self.option = data[96:]
		self.Rcode = flags&15
		flags = flags//16
		self.CD = flags&1
		self.AD = flags&2
		self.Z = flags&4
		self.RA = flags&8
		flags = flags//16
		self.RD = flags&1
		self.TC = flags&2
		self.AA = flags&4
		flags = flags//8
		self.opcode = flags&15
		self.QR = 1 if (flags & 16)>0 else 0
		start = 96
		for i in range(NoQues):
			pass
			# self.Questions = []
			# Questions.append(data[start:])



class HTTP:
	def __init__(self, data: bytes):
		self.data = data
		message = data.decode('ASCII')
		
