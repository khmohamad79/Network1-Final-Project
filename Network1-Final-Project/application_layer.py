from struct import *

class DNS:
	def __init__(self, data):
		self.data = data
		self.ID, flags, self.NoQues, self.NoAns, self.NoAuth, self.NoAdd = unpack('! H H H H H H', data[:12])
		self.option = data[12:12 + self.NoQues*8 + (self.NoAns+self.NoAuth+self.NoAdd)*16]
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
		start = 12
		self.Questions = []
		self.Answers = []
		self.Auth_ans = []
		self.Add_ans = []
		for i in range(self.NoQues):
			self.Questions.append(data[start:start+8])
			start+=8
		
		for i in range(self.NoAns):
			self.Answers.append(data[start:start+16])
			start+=16

		for i in range(self.NoAuth):
			self.Auth_ans.append(data[start:start+16])
			start+=16

		for i in range(self.NoAdd):
			self.Add_ans.append(data[start:start+16])
			start+=16
		self.start = start

	def next(self):
		return self.data[self.start:]

class HTTP:
	def __init__(self, data: bytes):
		self.data = data
		message = data.decode('ASCII')
		middle = message.find('\r\n\r\n')
		header = message[:middle]
		self.nextlayer = message[middle+4:].encode('ASCII')
		flag_first = True
		self.headers = {}
		for line in header.split('\n'):
			if flag_first:
				words = line.split(' ')
				if words[0].startswith('HTTP'):
					self.response_version = words[0]
					self.response_code = words[1]
					self.response_phrase = words[2]
				else:
					self.request_method = words[0]
					self.request_uri = words[1]
					self.request_version = words[2]
				flag_first = False
			else:
				mid = line.find(':')
				self.headers[line[:mid]] = line[mid+2:-1]
		for key in self.headers.keys():
			print(key + ': ' + self.headers[key])

	def next(self):
		return self.nextlayer
