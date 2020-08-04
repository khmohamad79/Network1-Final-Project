import socket
from transport_layer import *

def connect_scan(target, port, delay):
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

def syn_scan(host, target, port, delay):
	print('syn_scan')
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	# s.settimeout(delay)
	obj = TCP(host, target, port, 1, 0, 0)
	s.sendto(obj.data, (target, 0))
	result = 0
	#checking result
	return result


def ack_scan(host ,target, port, delay):
	print('ack_scan')
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	# s.settimeout(delay)
	obj = TCP(host, target, port, 0, 1, 0)
	s.sendto(obj.data, (target, 0))
	result = 0
	#checking result
	return result

def fin_scan(host, target, port, delay):
	print('fin_scan')
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	# s.settimeout(delay)
	obj = TCP(host, target, port, 0, 0, 1)
	s.sendto(obj.data, (target, 0))
	result = 0
	#checking result
	return result

def windows_scan(host, target, port, delay):
	print('window_scan')
	print((target, port))
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	# s.settimeout(delay)
	obj = TCP(host, target, port, 0, 1, 0)
	#print(obj)
	#print(obj.data)
	#print((target, 0))
	s.sendto(obj.data, (target, 0))
	result = 0
	#checking result
	return result