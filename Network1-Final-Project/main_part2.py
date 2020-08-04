from port_scaners import *
from os import system
#import msvcrt
import time
import threading
	
print("\n======================== Port Scanner By DM=========================\n")
target_url = input('Target IP or Hostname: ')
while True:
	try:
		target = socket.gethostbyname(target_url)
	except socket.gaierror as e:
		print("DNS working...")
		continue
	except:
		print("Unvalid Input.")
		target_url = input('Target IP or Hostname: ')
		continue
	break
print("\nTarget IP: " + target)
	

host = get_host_ip()
print("\nHost IP: " + host)


ports = []
mode = 0
receive = None
delay = 0

while True:
	portmode = input("""
	
Select The Port Mode: 
	1. Single Port
	2. Mutiple Port
	3. Range
	""")
	try:
		if portmode == "1":
			input_port = int(input("\n\tEnter The Port Number(1-65535): "))
			if input_port<=0 or input_port>65535:
				raise Exception("Unvalid Port Number.")
			ports.append(input_port)
		elif portmode == "2":
			input_port = input("\n\tEnter The Ports Seperated by Slash Sign (/) (1-65535): ")
			for x in input_port.split('/'):
				if int(x)<=0 or int(x)>65535:
					raise Exception("Unvalid Port Number.")
				else:
					ports.append(int(x))
		elif portmode == "3":
			range_start = int(input("\n\tEnter Starting Port(1-65535): "))
			if range_start<=0 or range_start>65535:
				raise Exception("Unvalid Port Number.")
			range_end = int(input("\tEnter Last Port(1-65535): "))
			if range_end<=0 or range_end>65535:
				raise Exception("Unvalid Port Number.")
			if range_end<range_start:
				raise Exception("Last Port Should be greater than Starting Port.") 
			ports = list(range(range_start, range_end+1))
		else:
			raise Exception("Unvalid Mode Number.")
	except Exception as e:
		if len(e.args)>0 :
			print(e.args[0])
		else:
			print("Unvalid Input.")
		#msvcrt.getch()
		continue
	break

m =""
while True:
	scanmode = input("""

Select Scan Type:
	1.Connect Scan
	2.ACK Scan
	3.SYN Scan
	4.FIN Scan
	5.Windows Scan
	""") 
	try:
		if scanmode == "1":
			mode = connect_scan
			m += "Connect"
		elif scanmode == "2":
			mode = ack_scan
			receive = receive_ack
			m += "ACK"
		elif scanmode == "3":
			mode = syn_scan
			receive = receive_syn
			m += "SYN"
		elif scanmode == "4":
			mode = fin_scan
			receive = receive_fin
			m += "FIN"
		elif scanmode == "5":
			mode = windows_scan
			receive = receive_window
			m += "Window"
		else:
			raise Exception("Unvalid Scan Type Number.")
		#Alternate Mode Assinging
	except Exception as e:
		if len(e.args)>0 :
			print(e.args[0])
		else:
			print("Unvalid Scan Type Input.")
		#msvcrt.getch()
		continue
	break

while True:
	try:
		sdelay = int(input("\nEnter Sending Delay(msec): "))
		if sdelay < 0:
			raise Exception()
	except:
		print("Unvalid Input.")
		continue
	break

while True:
	try:
		tdelay = int(input("\nEnter Timeout(sec): "))
		if tdelay < 0:
			raise Exception()
	except:
		print("Unvalid Input.")
		continue
	break


print("\n" + m + "-Scan on Host " + target_url + " (" + target + "): ")
result = dict()
if receive == None:
	td = 0
	for port in ports:
		while True:
			if threading.active_count() < 10:
				t = threading.Thread(target=mode, args=(result, host, target, port, tdelay))
				t.start()
				td+=1
				print("                                  ", end="\r")
				print("Progression: " + str(int(td/len(ports)*100)) + "%", end='\r')
				time.sleep(sdelay/1000)
				break
			time.sleep(0.1)
	print('Waiting...         ')
	time.sleep(tdelay)
	print('Receiving Finished.')
else:
	receiver = threading.Thread(target=receive, args=(result, target, ports, tdelay))
	receiver.start()
	for i in range(len(ports)):
		mode(host, target, ports[i])
		print("                                  ", end="\r")
		print("Progression: " + str(int((i+1)/len(ports)*100)) + "%", end='\r')
		time.sleep(sdelay/1000)
	print('Waiting...         ')
	receiver.join()
	print('Receiving Finished.')

n=0
for port in ports:
	if result[port] == "Closed":
		n+=1
	else:
		print("\tPort " + str(port) + " : " + result[port])
if n>0:
	print("\n" + str(n) + " Ports are Closed") 
