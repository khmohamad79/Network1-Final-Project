import socket

def reformat_address(addr, group, ch):
    addr = str(addr)
    return ch.join(addr[i:i+group] for i in range(0, len(addr), group))

def reformat_ipv4(addr):
    output = ''
    for ch in addr:
        output += str(int(ch)) + '.'
    return output[:-1]

def bytes_to_ascii(data):
    output = 'ascii<'
    for i in range(len(data)):
        if int(data[i])<128:
            output += chr(data[i])
        else:
            output += ' '
    output += '>'
    return output

def bits_to_int(bits):
    x = 0
    for bit in bits:
        x <<= 1
        if bit>0:
            x |= 1
    return x

def ipv4_to_bytes(ip):
	bytes_arr = []
	bt = ip.split('.')
	for i in bt:
		bytes_arr.append(int(i))
	#result
	#for i in range(bytes_arr)

	return bytes(bytes_arr)

def calc_checksum2(data):
	s = 0
	for i in range(0, len(data), 2):
		w = (int(data[i]) << 8) + (int(data[i+1]) )
		s += w
		# s += (s >> 16)
		# s = ((s>>16)+(s&0xFFFF))
		
	while s>>16:
		s = (s & 0xFFFF) + (s >> 16)
	s = ~s & 0xFFFF
	# s = s^(0x0000ffff)	
	return s

def calc_checksum(data):
	s = 0
	n = len(data) % 2
	for i in range(0, len(data)-n, 2):
		s+= (int(data[i]) << 8) + int(data[i+1])
	if n:
		s+= int(data[i+1])
	while (s >> 16):
		s = (s & 0xFFFF) + (s >> 16)
	s = ~s & 0xffff
	return s


def get_host_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	ip = s.getsockname()[0]
	s.close()
	return ip