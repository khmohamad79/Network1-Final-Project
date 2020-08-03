import socket
from transport_layer import *

def connect_scan(target, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	# s.settimeout(delay)
	try:
		s.connect((target, port))
		return True
	except Exception as e:
		print(e)
		print(e.args)
		return False

def syn_scan(host, target, port):
	print('syn_scan')
	print((target, port))
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	obj = TCP(host, target, port, 1, 0, 0)
	print(obj)
	print(obj.data)
	print((target, 0))
	result = s.sendto(obj.data, (target, 0))
	return result


def ack_scan(target, port):
	pass

def fin_scan(target, port):
	pass

def windows_scan(target, port):
	pass