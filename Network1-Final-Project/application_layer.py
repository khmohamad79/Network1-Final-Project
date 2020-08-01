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
		#self.Questions = []
		#self.Answers = []
		#self.Auth_ans = []
		#self.Add_ans = []
		#for i in range(self.NoQues):
		#	self.Questions.append(data[start:start+8])
		#	start+=8
		
		#for i in range(self.NoAns):
		#	self.Answers.append(data[start:start+16])
		#	start+=16

		#for i in range(self.NoAuth):
		#	self.Auth_ans.append(data[start:start+16])
		#	start+=16

		#for i in range(self.NoAdd):
		#	self.Add_ans.append(data[start:start+16])
		#	start+=16
		self.start = start

	def next(self):
		return self.data[self.start:]

	def __str__(self):
		string = "► DNS (Domain Name System)\n"
		string += "\tID : "+ str(self.ID) +"\n" 
		string += "\tFlags: \n" +  "\t\tDNS "
		if self.QR:
			string += "Query\n"
		else:
			string += "Respone\n"
		string += "\t\tOpcode: "
		if self.opcode==0:
			string += "Standard Query\n"
		elif self.opcode==1:
			string += "Inverse Query\n"
		elif self.opcode==2:
			string += "Server Status Request\n"
		elif self.opcode==4:
			string += "Notify\n"
		elif self.opcode==5:
			string += "Update\n"
		else:
			string += "-\n"
		string += "\t\tAuthorative: "
		if self.AA:
			string += "True\n"
		else:
			string += "False\n"
		string += "\t\tTrunctuated: "
		string += "True\n" if self.TC else "False\n"
		string += "\t\tReccursion Desired: "
		string += "True\n" if self.RD else "False\n"
		string += "\t\tRecursion Available: "
		string += "True\n" if self.RA else "False\n"
		string += "\t\tAll Data is Authorative: "
		string += "True\n" if self.AD else "False\n"
		string += "\t\tChecking: "
		string += "Disabled\n" if self.CD else "Enabled\n"
		string += "\t\tR Code: " + str(self.Rcode) + "\n"
		string += "\tQuestions: " + str(self.NoQues) + "\n"
		string += "\tAnswers RR: " + str(self.NoAns) + "\n"
		string += "\tAuthorative RR: " + str(self.NoAuth) + "\n"
		string += "\tAdditional RR: " + str(self.NoAdd) + "\n"
		#if self.NoQues > 0:
		#	string += "\tQueries: \n"
		#	for i in self.Questions:
		#		string += "\t\t" + str(i) + "\n"
		#if self.NoAns > 0:
		#	string += "\tAnswers: \n"
		#	for i in self.Answers:
		#		string += "\t\t" + str(i) + "\n"
		#if self.NoAuth > 0:
		#	string += "\tAuthoratives: \n"
		#	for i in self.Auth_ans:
		#		string += "\t\t" + str(i) + "\n"
		#if self.NoAdd > 0:
		#	string += "\tAdditional: \n"
		#	for i in self.Add_ans:
		#		string += "\t\t" + str(i) + "\n"	

		return string


class HTTP:
	def __init__(self, data: bytes):
		self.data = data
		
		data_offset = -1
		for i in range(len(data)):
			if int(data[i]) < 128:
				data_offset = i
			else:
				break

		message = (data[:data_offset+1]).decode('ASCII')
		mid = message.find('\r\n\r\n')
		if mid>=0:
			self.header = message[0:mid+4]
			self.nextlayer = data[mid+4:]
		else:
			if data_offset==len(data)-1:
				self.header = message
				self.nextlayer = bytes(0)
			else:
				self.header = ""
				self.nextlayer = data

		"""
		if (data_offset<0):
			self.nextlayer = data
			return
		elif (data_offset==(len(data)-1)):
			message = data.decode('ASCII')
			middle = message.find('\r\n\r\n')
			if(middle>0):
				header = data[:middle+1].decode('ASCII')
				self.nextlayer = data[middle+4:]
			else:
				header = data.decode('ASCII')
				self.nextlayer = bytes(0)
		elif (data_offset>=0 and data_offset<(len(data)-1)):
			message = data[0:data_offset+1].decode('ASCII')
			middle = message.find('\r\n\r\n')
			if(middle>0):
				header = data[:middle+1].decode('ASCII')
				self.nextlayer = data[middle+4:]
			else:
				self.nextlayer = data
				return

		flag_first = True
		self.headers = {}
		for line in header.split('\n'):
			if flag_first:
				words = line.split(' ')
				if len(words)>=3 and line.find(':')<0:
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
					flag_first = False
			else:
				mid = line.find(':')
				self.headers[line[:mid]] = line[mid+2:-1]
			"""


	def next(self):
		return self.nextlayer

	def __str__(self):
		output = ""
		if (len(self.header)>0) :
			output += '► HTTP (HyperText Transfer Protocol)\n'
			for line in self.header.split('\n'):
				output += "\t" + line + "\n"
		return output

		"""
		if hasattr(self, 'response_code'):
			output += '\t' + self.response_version + ' ' + self.response_code + ' ' + self.response_phrase + '\n'
			output += '\t\tResponse Version: ' + self.response_version + '\n'
			output += '\t\tResponse Code: ' + self.response_code + '\n'
			output += '\t\tResponse Phrase: ' + self.response_phrase + '\n'
		elif hasattr(self, 'request_method'):
			output += '\t' + self.request_method + ' ' + self.request_uri + ' ' + self.request_version + '\n'
			output += '\t\tRequest Method: ' + self.request_method + '\n'
			output += '\t\tRequest URI: ' + self.request_uri + '\n'
			output += '\t\tRequest Version: ' + self.request_version + '\n'
		if hasattr(self, 'headers'):
			for key in self.headers.keys():
				output +=  '\t' + key + ': ' + self.headers[key] + '\n'
		"""
		#return output