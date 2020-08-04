import socket
from transport_layer import *
from network_layer import *
import time
	
def connect_scan(result, host, target, port, delay):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(delay)
	try:
		s.connect((target, port))
		result[port] = "Open"
	except Exception as e:
		result[port] = "Closed"


def syn_scan(host, target, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	obj = TCP.generatePacket(host, target, port, 1, 0, 0)
	s.sendto(obj.data, (target, 0))


def receive_syn(result, target, ports, delay):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	td = len(ports)
	while td>0:
		try:
			resp_data = s.recv(1024)
			resp_obj = IPV4(resp_data)
			if resp_obj.srcip == target and resp_obj.proto == 6:
				td -= 1
				tcp_response = resp_obj.next()
				if tcp_response.SYN == 1:
					result[tcp_response.src_port] = "Open"
				elif tcp_response.RST == 1:
					result[tcp_response.src_port] = "Closed"
		except:
			td -= 1

	for port in ports:
		if not port in result.keys():
			result[port] = "Filtered"


def ack_scan(host, target, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	obj = TCP.generatePacket(host, target, port, 0, 1, 0)
	s.sendto(obj.data, (target, 0))
	

def receive_ack(result, target, ports, delay):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	td = len(ports)
	
	while td>0:
		try:
			resp_data = s.recv(1024)
			resp_obj = IPV4(resp_data)
			if resp_obj.srcip == target and resp_obj.proto == 6:
				tcp_response = resp_obj.next()
				td-=1
				if tcp_response.RST == 1:
					result[tcp_response.src_port] = "Unfiltered"
		except:
			td-=1 

	for port in ports:
		if not port in result.keys():
			result[port] = "Filtered"


def fin_scan(host, target, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	obj = TCP.generatePacket(host, target, port, 0, 0, 1)
	s.sendto(obj.data, (target, 0))


def receive_fin(result, target, ports, delay):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	td = len(ports)
	try:
		while td>0:
			resp_data = s.recv(1024)
			resp_obj = IPV4(resp_data)
			if resp_obj.srcip == target and resp_obj.proto == 6:
				td-=1
				tcp_response = resp_obj.next()
				if tcp_response.RST == 1:
					result[tcp_response.src_port] = "Closed"
	except:
		td-=1
		pass

	for port in ports:
		if not port in result.keys():
			result[port] = "Open|Filtered"


def windows_scan(host, target, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	obj = TCP.generatePacket(host, target, port, 0, 1, 0)
	s.sendto(obj.data, (target, 0))


def receive_window(result, target, ports, delay):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.settimeout(delay)
	td =len(ports)
	try:
		while td>0:
			resp_data = s.recv(1024)
			resp_obj = IPV4(resp_data)
			if resp_obj.srcip == target and resp_obj.proto == 6:
				tcp_response = resp_obj.next()
				if tcp_response.RST == 1:
					td-=1
					if tcp_response.window_size>0:
						result[tcp_response.src_port] = "Open"
					else:
						result[tcp_response.src_port] = "Closed"
	except:
		td-=1

	for port in ports:
		if not port in result.keys():
			result[port] = "Filtered"