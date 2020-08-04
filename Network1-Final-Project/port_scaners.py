import socket
from transport_layer import *
from network_layer import *

def connect_scan(host, target, port, delay):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.settimeout(delay)
	try:
		s.connect((target, port))
		return "open"
	except Exception as e:
		return "closed"

def syn_scan(host, target, port, delay):
	print('syn_scan')
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	obj = TCP.generatePacket(host, target, port, 1, 0, 0)
	try:
		s.sendto(obj.data, (target, 0))
		resp_data = s.recv(1024)
		resp_obj = IPV4(resp_data)
		if resp_obj.proto == 1:
			return "filtered"
		elif resp_obj.proto == 6:
			tcp_response = resp_obj.next()
			if tcp_response.SYN == 1:
				return "open"
			elif tcp_response.RST == 1:
				return "closed"
	except:
		return "filtered"



def ack_scan(host ,target, port, delay):
	print('ack_scan')
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	obj = TCP.generatePacket(host, target, port, 0, 1, 0)
	try:
		s.sendto(obj.data, (target, 0))
		resp_data = s.recv(1024)
		resp_obj = IPV4(resp_data)
		if resp_obj.proto == 1:
			return "filtered"
		elif resp_obj.proto == 6:
			tcp_response = resp_obj.next()
			if tcp_response.RST == 1:
				return "unfiltered"
	except:
		return "filtered"

def fin_scan(host, target, port, delay):
	print('fin_scan')
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	obj = TCP.generatePacket(host, target, port, 0, 0, 1)
	try:
		s.sendto(obj.data, (target, 0))
		resp_data = s.recv(1024)
		resp_obj = IPV4(resp_data)
		if resp_obj.proto == 1:
			return "filtered"
		elif resp_obj.proto == 6:
			tcp_response = resp_obj.next()
			if tcp_response.RST == 1:
				return "closed"
	except:
		return "open|filtered"

def windows_scan(host, target, port, delay):
	print('window_scan')
	print((target, port))
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	obj = TCP.generatePacket(host, target, port, 0, 1, 0)
	try:
		s.sendto(obj.data, (target, 0))
		resp_data = s.recv(1024)
		resp_obj = IPV4(resp_data)
		if resp_obj.proto == 1:
			return "filtered"
		elif resp_obj.proto == 6:
			tcp_response = resp_obj.next()
			if tcp_response.RST == 1:
				if tcp_response.window_size>0:
					return "open"
				else:
					return "closed"
	except:
		return "filtered"