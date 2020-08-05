from struct import *
from utilities import *

class DNS:
	def __init__(self, data):
		self.data = data
		self.ID, flags, self.NoQues, self.NoAns, self.NoAuth, self.NoAdd = unpack('! H H H H H H', data[:12])
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
		data_labels = dict()
		self.Questions = []
		self.Answers = []
		self.Auth_ans = []
		self.Add_ans = []
		
		option = data[start:]
		i = 0
		while len(self.Questions) < self.NoQues:
			name = ''
			while option[i] > 0:
				if option[i] < 64:
					label = option[ i+1 : i+1+int(option[i]) ].decode('ASCII')
					data_labels[i] = label
					name += label + '.'
					i += int(option[i]) + 1
				elif option[i] >= 192:
					offset = (int(option[i])*256) + int(option[i+1])
					offset = offset & 0x3FFF
					label = get_label(data_labels, offset-12)
					data_labels[i] = label
					name += label + '.'
					i += 1
					break
				else:
					name += str(int(option[i])) + '.'
					i += 1
			i += 1
			qu_type, qu_class = unpack('! H H', option[i:i+4])
			i += 4
			self.Questions.append({'name':name, 'type':qu_type, 'class':qu_class})
		while len(self.Answers) < self.NoAns:
			name = ''
			while option[i] > 0:
				if option[i] < 64:
					label = option[ i+1 : i+1+int(option[i]) ].decode('ASCII')
					data_labels[i] = label
					name += label + '.'
					i += int(option[i]) + 1
				elif option[i] >= 192:
					offset = (int(option[i]) *256) + int(option[i+1])
					offset = offset & 0x3FFF
					label = get_label(data_labels, offset-12)
					data_labels[i] = label
					name += label + '.'
					i += 1
					break
				else:
					name += str(int(option[i])) + '.'
					i += 1
			i += 1
			ans_type, ans_class, ans_ttl, ans_rdlen  = unpack('! H H L H', option[i:i+10])
			i += 10
			ans_rdata,  = unpack('! ' + str(ans_rdlen) + 's', option[i: i+ans_rdlen])
			i += ans_rdlen
			if ans_type == 1:
				ans_rdata = reformat_ipv4(ans_rdata)
			elif ans_type == 5:
				data_labels[i-ans_rdlen] = get_url(ans_rdata, data_labels)
			self.Answers.append({'name':name, 'type':ans_type, 'class':ans_class, 'ttl':ans_ttl, 'rdata':ans_rdata})
		while len(self.Auth_ans) < self.NoAuth:
			name = ''
			while option[i] > 0:
				if option[i] < 64:
					label = option[ i+1 : i+1+int(option[i]) ].decode('ASCII')
					data_labels[i] = label
					name += label + '.'
					i += int(option[i]) + 1
				elif option[i] >= 192:
					offset = (int(option[i])*256) + int(option[i+1])
					offset = offset & 0x3FFF
					label = get_label(data_labels, offset-12)
					data_labels[i] = label
					name += label + '.'
					i += 1
					break
				else:
					name += str(int(option[i])) + '.'
					i += 1
			i += 1
			ans_type, ans_class, ans_ttl, ans_rdlen  = unpack('! H H L H', option[i:i+10])
			i += 10
			ans_rdata,  = unpack('! ' + str(ans_rdlen) + 's', option[i: i+ans_rdlen])
			i += ans_rdlen
			if ans_type == 1:
				ans_rdata = reformat_ipv4(ans_rdata)
			elif ans_type == 5:
				data_labels[i-ans_rdlen] = get_url(ans_rdata, data_labels)
			self.Auth_ans.append({'name':name, 'type':ans_type, 'class':ans_class, 'ttl':ans_ttl, 'rdata':ans_rdata})
		while len(self.Add_ans) < self.NoAdd:
			name = ''
			while option[i] > 0:
				if option[i] < 64:
					label = option[ i+1 : i+1+int(option[i]) ].decode('ASCII')
					data_labels[i] = label
					name += label + '.'
					i += int(option[i]) + 1
				elif option[i] >= 192:
					offset = (int(option[i])*256) + int(option[i+1])
					offset = offset & 0x3FFF
					label = get_label(data_labels, offset-12)
					data_labels[i] = label
					name += label + '.'
					i += 1
					break
				else:
					name += str(int(option[i])) + '.'
					i += 1
			i += 1
			ans_type, ans_class, ans_ttl, ans_rdlen  = unpack('! H H L H', option[i:i+10])
			i += 10
			ans_rdata,	= unpack('! ' + str(ans_rdlen) + 's', option[i: i+ans_rdlen])
			i += ans_rdlen
			if ans_type == 1:
				ans_rdata = reformat_ipv4(ans_rdata)
			elif ans_type == 5:
				data_labels[i-ans_rdlen] = get_url(ans_rdata, data_labels)
			self.Add_ans.append({'name':name, 'type':ans_type, 'class':ans_class, 'ttl':ans_ttl, 'rdata':ans_rdata})
		start += i	
		self.start = start

	def generatePacket():
		data = bytes(2) + pack('! B', 0b10010000) + bytes(9)
		return DNS(data)

	def next(self):
		return self.data[self.start:]

	def __str__(self):
		string = "► DNS (Domain Name System)\n"
		string += "\tID : "+ str(self.ID) +"\n" 
		string += "\tFlags: \n" +  "\t\tDNS: " 
		if self.QR:
			string += "1 Response\n"
		else:
			string += "0 (Query)\n"
		string += "\t\tOpcode: "
		if self.opcode==0:
			string += "0 (Standard Query)\n"
		elif self.opcode==1:
			string += "1 (Inverse Query)\n"
		elif self.opcode==2:
			string += "2 (Server Status Request)\n"
		elif self.opcode==4:
			string += "4 (Notify)\n"
		elif self.opcode==5:
			string += "5 (Update)\n"
		else:
			string += str(self.opcode) + "\n"
		string += "\t\tAuthorative Answer: "
		if self.AA:
			string += "True\n"
		else:
			string += "False\n"
		string += "\t\tTruncated: "
		string += "True\n" if self.TC else "False\n"
		string += "\t\tRecursion Desired: "
		string += "True\n" if self.RD else "False\n"
		string += "\t\tRecursion Available: "
		string += "True\n" if self.RA else "False\n"
		string += "\t\tReserved Bit Z: " + str(self.Z) + '\n'
		string += "\t\tAll Data is Authorative: "
		string += "True\n" if self.AD else "False\n"
		string += "\t\tSecurity Checking: "
		string += "Disabled\n" if self.CD else "Enabled\n"
		string += "\t\tR Code: " + str(self.Rcode) + ' ' + dns_rcode(self.Rcode) + "\n"
		string += "\tQuestions: " + str(self.NoQues) + "\n"
		string += "\tAnswers RR: " + str(self.NoAns) + "\n"
		string += "\tAuthorative RR: " + str(self.NoAuth) + "\n"
		string += "\tAdditional RR: " + str(self.NoAdd) + "\n"
		if self.NoQues > 0:
			string += "\tQueries: \n"
			for q in self.Questions:
				string += "\t\tName: " + q['name'] + "\n"
				string += "\t\tType: " + str(q['type']) + "\n"
				string += "\t\tClass: " + str(q['class']) + "\n"
				string += "\t\t----------------\n"
		if self.NoAns > 0:
			string += "\tAnswers: \n"
			for q in self.Answers:
				string += "\t\tName: " + q['name'] + "\n"
				string += "\t\tType: " + str(q['type']) + "\n"
				string += "\t\tClass: " + str(q['class']) + "\n"
				string += "\t\tTTL: " +str( q['ttl']) + "\n"
				string += "\t\tRR Data: " + str(q['rdata']) + "\n"
				string += "\t\t----------------\n"
		if self.NoAuth > 0:
			string += "\tAuthoratives: \n"
			for q in self.Auth_ans:
				string += "\t\tName: " + q['name'] + "\n"
				string += "\t\tType: " + str(q['type']) + "\n"
				string += "\t\tClass: " + str(q['class']) + "\n"
				string += "\t\tTTL: " +str( q['ttl']) + "\n"
				string += "\t\tRR Data: " + str(q['rdata']) + "\n"
				string += "\t\t----------------\n"
		if self.NoAdd > 0:
			string += "\tAdditional: \n"
			for q in self.Add_ans:
				string += "\t\tName: " + q['name'] + "\n"
				string += "\t\tType: " + str(q['type']) + "\n"
				string += "\t\tClass: " + str(q['class']) + "\n"
				string += "\t\tTTL: " + str(q['ttl']) + "\n"
				string += "\t\tRR Data: " + str(q['rdata']) + "\n"
				string += "\t\t----------------\n"

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