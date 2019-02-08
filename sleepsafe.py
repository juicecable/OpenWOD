#ServSleepSafe by Derek Frombach

#Seamless and Easy Wake on Demand Server (makes low/medium demand remote access servers save lots of power(energy))

#This program is designed to run on Debian type Linux Operating Systems

#Written for Python 3.7

#you need to execute one command before this program can completly work
#sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP


#Import Statments
import socket
import os
import random
import time


#Declaring Constants/Variables
eth_p_all=3			#Some Constant
eth_frame_len=1514		#The MTU
netif='eth0'			#The Network Interface Name
def_t_out=1.0			#Default Socket Timout in Seconds
gateway='10.0.0.1'		#Default Gateway IP for the LAN
lan_min='10.0.0.1'		#Minimum Lan Address in Subnet
lan_max='10.0.0.254'		#Maximum Lan Address in Subnet
gateway_mac='ba9876543210'	#Default Gateway Mac for the LAN
self_mac='0123456789ab'		#Your NIC MAC Address
rem_port=80			#Remote Server Port
self_ip='10.0.0.2'		#Your Supposed Ip Address
serv_ip='10.0.0.3'		#Your Server Ip Address
dt=60				#Delay time in seconds for Wait to Sleep
debug=False			#For debug only

#Declaring Special Addresses Such as Static Servers
spec={}		#Special Ip addresses in the format ip,name
spec_mac={}	#Special Mac addresses in the format mac,name


#Initalising The Sockets
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(eth_p_all))#THIS IS THE SECRET SAUCE
s.bind((netif,0))


#Functions

#Recieve Raw Data Blocking Function
def recv(e_len=eth_frame_len,s=s):
	return s.recv(e_len)

#Recieve Raw Data Non-Blocking Function
def recv_t(t=def_t_out,e_len=eth_frame_len,s=s):
	s.settimeout(t)
	try:
		data=s.recv(e_len)
	except socket.timeout:
		s.settimeout(None)
		return False
	else:
		s.settimeout(None)
		return data

#Send Raw Data Function
def send(data,s=s):	#takes bytes data
	s.sendall(data)
	return True	#Outputs True when Completed Sucessfully

#Bytes to hexadecimal converter
def u_hex(data,l=2):	#takes bytes data [and int max output length]
	o=hex(data)[2:]
	while len(o)<l:
		o='0'+o
	return o	#Outputs hexadecimal

#Layer 2 Disassembly
def read_mac(data):	#takes bytes data
	src_mac=''
	dst_mac=''
	pckt_type=''
	for i in range(0,len(data)):
		if i<6:
			dst_mac+=u_hex(data[i])
		elif i<12:
			src_mac+=u_hex(data[i])
		elif i<14:
			pckt_type+=u_hex(data[i])
		else:
			break
	return dst_mac,src_mac,pckt_type
	"""
	returns hex destination MAC, hex source MAC, hex packet type (ethertype)"""

#Ethertype Disassembly
def get_pckt_type(pckt_type):		#takes hex packet type (ethertype)
	types={'0800':'ipv4','0806':'arp','0842':'wol','86dd':'ipv6','8808':'flow'}
	if pckt_type in types:
		return types[pckt_type]
	else:
		return 'unknown'	#Outputs a human readable packet type

#Ip Address Human Readable Formatter
def u_ip(data):			#takes hexadecimal representaion of ip
	data=list(data)
	a=['0','0','0','0']
	for i in range(0,len(data),2):
		a[i//2]=str(int(data[i]+data[i+1],16))
	return '.'.join(a)	#Outputs a human readable Ipv4 Ip Address

#Ipv4 Disassembly
def read_ipv4(data):	#takes bytes data
	v=4
	head_len=0
	dsf=''
	tot_len=0
	ident=0
	flags=''
	ttl=0
	proto=0
	check=''
	src_ip=''
	dst_ip=''
	for i in range(14,len(data)):
		if i<15:
			v=int(u_hex(data[i])[:1])
			head_len=int(u_hex(data[i])[1:])*4
		elif i<16:
			dsf=u_hex(data[i])
		elif i<18:
			if i==16:
				tot_len=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<20:
			if i==18:
				ident=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<22:
			flags+=u_hex(data[i])
		elif i<23:
			ttl=data[i]
		elif i<24:
			proto=data[i]
		elif i<26:
			check+=u_hex(data[i])
		elif i<30:
			if i==26:
				src_ip=u_ip(u_hex(data[i])+u_hex(data[i+1])+u_hex(data[i+2])+u_hex(data[i+3]))
		elif i<34:
			if i==30:
				dst_ip=u_ip(u_hex(data[i])+u_hex(data[i+1])+u_hex(data[i+2])+u_hex(data[i+3]))
	return v,head_len,dsf,tot_len,ident,flags,ttl,proto,check,src_ip,dst_ip
	"""
	returns int ipv4 version, int ipv4 header length, hex dsf (whatever that means), int ipv4 identifier,
	hex ipv4 flags, hex layer 4 protocol, hex ipv4 checksum, readable_ip source ip, readable_ip destination ip"""

#Layer 4 IPv4 Protocol Identifcation
def get_proto(proto):			#takes hexadecimal representation of protocol
	types={1:'icmp',2:'igmp',6:'tcp',17:'udp'}
	if proto in types:
		return types[proto]
	else:
		return 'unknown'	#Outputs Readable Layer 4 Protocol Name

#TCP Disassembly
def read_tcp(data):	#takes bytes data
	src_port=0
	dst_port=0
	seq=0
	ack=0
	tcp_head_len=0
	tcp_flags=''
	wind_size=0
	tcp_check=''
	urg=0
	rest=0#An Interally Used Varaible Only
	opts=''
	extra=''
	for i in range(34,len(data)):
		if i<36:
			if i==34:
				src_port=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<38:
			if i==36:
				dst_port=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<42:
			if i==38:
				seq=int(u_hex(data[i])+u_hex(data[i+1])+u_hex(data[i+2])+u_hex(data[i+3]),16)
		elif i<46:
			if i==42:
				ack=int(u_hex(data[i])+u_hex(data[i+1])+u_hex(data[i+2])+u_hex(data[i+3]),16)
		elif i<47:
			tcp_head_len=int(u_hex(data[i])[:1],16)*4#Outputs the actual Header Length
			tcp_flags+=u_hex(data[i])[1:]
			rest=34+tcp_head_len#Accounting for varaible header size
		elif i<48:
			tcp_flags+=u_hex(data[i])
		elif i<50:
			if i==48:
				wind_size=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<52:
			tcp_check+=u_hex(data[i])
		elif i<54:
			if i==50:
				urg=int(u_hex(data[i])+u_hex(data[i+1])+u_hex(data[i+2])+u_hex(data[i+3]),16)
		elif i<rest:#Accounting for variable header size
			opts+=u_hex(data[i])
		else:
			extra+=u_hex(data[i])
	return src_port,dst_port,seq,ack,tcp_head_len,tcp_flags,wind_size,tcp_check,urg,opts,extra
	"""
	returns int source port, int destination port, int tcp sequence number, int tcp acknoledgement number,
	int tcp header length, hex tcp flags, int tcp window size, hex tcp checksum, int tcp urgent number,
	hex tcp options, hex tcp payload"""

#TCP Flags Analysis
def read_flags(data):	#takes hexadecimal representaion of tcp flags
	#normalising the input data, and converting to binary list (array)
	n=str(bin(int(data,16)))[2:]
	while len(n)<12:
		n='0'+n
	n=list(n)
	#now for the useful variable declaration
	nonce=False
	cwr=False
	ecn_echo=False
	urgent=False
	ackn=False
	push=False
	reset=False
	syn_f=False
	fin=False
	#finally the conversion to booleans
	for i in range(3,len(n)):
		v=int(n[i])
		if i<4:
			if v:
				nonce=True
		elif i<5:
			if v:
				cwr=True
		elif i<6:
			if v:
				ecn_echo=True
		elif i<7:
			if v:
				urgent=True
		elif i<8:
			if v:
				ackn=True
		elif i<9:
			if v:
				push=True
		elif i<10:
			if v:
				reset=True
		elif i<11:
			if v:
				syn_f=True
		elif i<12:
			if v:
				fin=True
	return nonce,cwr,ecn_echo,urgent,ackn,push,reset,syn_f,fin
	"""
	returns bool nonce, bool cwr, bool ecn_echo, bool urgent, bool ack, bool push, bool reset, bool syn, bool fin"""

#Ip to Number
def ipton(ip):			#takes human readable ip
	ip=ip.split('.')
	ip=u_hex(int(ip[0]))+u_hex(int(ip[1]))+u_hex(int(ip[2]))+u_hex(int(ip[3]))
	return int(ip,16)	#Outputs integer that represents ip

#Ip Address Evaluator (Determines the human readable subnet category of an ip)
def ip_eval(oip,spec=spec,gateway=gateway,lan_min=lan_min,lan_max=lan_max):	#takes human readable ip
	#Constant IPs
	bcast='255.255.255.255'
	mcast_min='224.0.0.1'
	mcast_max='239.255.255.255'
	#Conversion of Ips to numbers for comparison
	ip=ipton(oip)
	bcast=ipton(bcast)
	mcast_min=ipton(mcast_min)
	mcast_max=ipton(mcast_max)
	gateway=ipton(gateway)
	lan_min=ipton(lan_min)
	lan_max=ipton(lan_max)
	lan_bcast=lan_max+1
	#Finally the logic
	if ip==gateway:
		return 'gateway'
	elif oip in spec:
		return spec[oip]#Special User Defined Ip Addresses
	elif ip>=lan_min and ip<=lan_max:
		return 'lan'
	elif ip==lan_bcast:
		return 'broadcast'
	elif ip>=mcast_min and ip<=mcast_max:
		return 'multicast'
	elif ip==bcast:
		return 'broadcast'		
	else:
		return 'wan'							#Outputs human readable subnet category string

#Arp Builder
"""
Takes boolean (true is request, false is response), hex sender MAC, human readable sender ip, hex target MAC,
human readable target ip"""
def write_arp(t,snd_mac,snd_ip,tgt_mac,tgt_ip):
	h_type='0001'#ethernet
	proto='0800'#ipv4
	h_size='06'#some constant (hardware size)
	proto_size='04'#some constant (protocol size)
	if t:
		opcode='0001'#request
	else:
		opcode='0002'#response
	o=h_type+proto+h_size+proto_size+opcode+snd_mac+iptohex(snd_ip)+tgt_mac+iptohex(tgt_ip)
	return o	#Outputs hexadecimal representaion of Arp Packet

#Hexadecimal Reversal in 16 bits for Checksum
def hex_rev(data):					#takes hexadecimal
	data=list(data)
	return data[2]+data[3]+data[0]+data[1]		#Outputs hexadecimal

#Internet Checksum Calculator (16 bit ones compliment of 16 bit ones compliment sum)
def calc_check(data):					#takes hexadecimal
	a=[]
	aa=a.append
	for i in range(0,len(data),2):
		aa(int(data[i]+data[i+1],16))
	check=0
	for i in range(0,len(a),2):
		n=a[i]+(a[i+1]<<8)
		check=check+n
		check=(check&0xffff)+(check>>16)
	return hex_rev(u_hex(~check&0xffff,4))		#Outputs hexadecimal 16 bit checksum

#Icmp (ping) Builder
"""OPTIONAL:
Takes boolean (true is request, false is response), hex icmp identifier, hex icmp sequence number,
hex icmp timestamp, hex icmp payload (48 bytes)"""
def write_ping(t=True,ident_b=os.urandom(2),seq='0001',icmp_time='eff74c5c00000000',data_b=os.urandom(48)):
	if t==True:
		t='08'#Ping Request
	else:
		t='00'#Ping Reply
	code='00'
	check='0000'
	#conversion of bytes input to hexadecimal
	ident=''
	if "b'" in str(ident_b):
		for i in range(0,len(ident_b)):
			ident+=u_hex(ident_b[i])
	else:
		ident=ident_b
	data=''
	if "b'" in str(data_b):
		for i in range(0,len(data_b)):
			data+=u_hex(data_b[i])
	else:
		data=data_b
	#building the packet
	o=t+code+check+ident+seq+icmp_time+data
	check=calc_check(o)
	o=t+code+check+ident+seq+icmp_time+data
	return o	#Outputs hexadecimal representation of icmp ping packet

#WOL Builder
def write_wol(tgt_mac):		#takes hexadecimal MAC
	start='FFFFFFFFFFFF'
	o=start
	for i in range(0,16):
		o+=tgt_mac
	return o		#Outputs hexadecimal representation of WOL payload

#TCP Flags Builder
"""
Takes bool nonce, bool cwr, bool ecn_echo, bool urgent, bool ack, bool push, bool reset,
bool syn, bool fin"""
def write_flags(nonce,cwr,ecn_echo,urgent,ackn,push,reset,syn_f,fin):
	o='0b000'#Reserved
	if nonce:
		o+='1'
	else:
		o+='0'
	if cwr:
		o+='1'
	else:
		o+='0'
	if ecn_echo:
		o+='1'
	else:
		o+='0'
	if urgent:
		o+='1'
	else:
		o+='0'
	if ackn:
		o+='1'
	else:
		o+='0'
	if push:
		o+='1'
	else:
		o+='0'
	if reset:
		o+='1'
	else:
		o+='0'
	if syn_f:
		o+='1'
	else:
		o+='0'
	if fin:
		o+='1'
	else:
		o+='0'
	return u_hex(int(o,2),3)	#Outputs hexadecimal representation of tcp flags

#TCP Builder
"""
Takes readable source ip, readable destination ip, int source port, int destination port, int tcp sequence number, int tcp acknoledgment number,
hex tcp flags, int tcp window size, int tcp urgent number, hex tcp options, hex tcp payload"""
def write_tcp(src_ip,dst_ip,src_port,dst_port,seq,ack,tcp_flags,wind_size,urg,opts,extra):
	o=u_hex(src_port,4)+u_hex(dst_port,4)+u_hex(seq,8)+u_hex(ack,8)+'0'+tcp_flags+u_hex(wind_size,4)+'0000'+u_hex(urg,4)+opts
	tcp_head_len=u_hex(len(o)//8,1)#conversion to transmitted header length
	o=u_hex(src_port,4)+u_hex(dst_port,4)+u_hex(seq,8)+u_hex(ack,8)+tcp_head_len+tcp_flags+u_hex(wind_size,4)+'0000'+u_hex(urg,4)+opts+extra
	ph=u_hex(ipton(src_ip),8)+u_hex(ipton(dst_ip),8)+'06'+u_hex(len(o),4)+o#fake header
	tcp_check=calc_check(ph)
	o=u_hex(src_port,4)+u_hex(dst_port,4)+u_hex(seq,8)+u_hex(ack,8)+tcp_head_len+tcp_flags+u_hex(wind_size,4)+u_hex(tcp_check,4)+u_hex(urg,4)+opts+extra
	return o	#Outputs hexadecimal representaion of tcp packet

#IP Builder
"""
Takes hex ip flags, int ttl, hex layer 4 protocol, human readable source ip, human readable destination ip, hex ip payload"""
def write_ip(flags,ttl,proto,src_ip,dst_ip,data):
	v='4'#ipv4
	head_len='5'#Constant header length
	dsf='00'#some ipv4 requirement
	tot_len='0000'
	ident_b=os.urandom(2)#Ipv4 identifier bytes
	check='0000'
	ident=''
	src_ip=iptohex(src_ip)
	dst_ip=iptohex(dst_ip)
	#conversion of bytes identifer to hexadecimal
	for i in range(0,len(ident_b)):
		ident+=u_hex(ident_b[i])
	#Building of packet
	o=v+head_len+dsf+tot_len+ident+flags+u_hex(ttl)+u_hex(proto)+check+src_ip+dst_ip
	head_len=u_hex(len(o)//8,1)#Conversion of header length to transmitted value
	o+=data
	tot_len=u_hex(len(o)//2,4)#Conversion of total length to transmitted value
	check=calc_check(v+head_len+dsf+tot_len+ident+flags+u_hex(ttl)+u_hex(proto)+check+src_ip+dst_ip)
	o=v+head_len+dsf+tot_len+ident+flags+u_hex(ttl)+u_hex(proto)+check+src_ip+dst_ip+data
	return o	#Outputs hexadecimal representaion of ipv4 packet

#MAC Builder
def write_mac(dst_mac,src_mac,pckt_type,data):	#takes hex destiation MAC, hex source MAC, hex packet type (ethertype), hex Ethernet Payload
	o=dst_mac+src_mac+pckt_type+data
	#conversion of hexadecimal to bytes
	o=list(o)
	a=b''
	for i in range(0,len(o),2):
		a+=int(o[i]+o[i+1],16).to_bytes(1,byteorder='big')
	return a				#Outputs bytes representation of ethernet frame and payload

#UDP Disassembly
def read_udp(data):	#takes bytes data
	src_port=0
	dst_port=0
	udp_len=0
	udp_check=''
	extra=''
	for i in range(34,len(data)):
		if i<36:
			if i==34:
				src_port=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<38:
			if i==36:
				dst_port=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<40:
			if i==38:
				udp_len=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<42:
			udp_check+=u_hex(data[i])
		else:
			extra+=u_hex(data[i])
	return src_port,dst_port,udp_len,udp_check,extra
	"""
	returns int udp source port, int udp destination port, int udp length, hex udp checksum, hex udp payload"""

#UDP Builder
def write_udp(src_port,dst_port,extra):		#takes int udp source port, int udp destination port, hex udp payload
	udp_len=0
	udp_check='0000'
	o=u_hex(src_port,4)+u_hex(dst_port,4)+'0000'+'0000'+extra
	udp_len=u_hex(len(o),4)#Calculation of udp length
	o=u_hex(src_port,4)+u_hex(dst_port,4)+udp_len+'0000'+extra
	ph=u_hex(ipton(src_ip),8)+u_hex(ipton(dst_ip),8)+'11'+u_hex(len(o),4)+o#Fake Header
	check=calc_check(ph)
	o=u_hex(src_port,4)+u_hex(dst_port,4)+udp_len+check+extra
	return o				#Outputs hexadecimal representation of udp packet

#ICMP Type Analysis
def read_icmp_type(icmp_type):		#takes int icmp type
	types={0:'ping reply',3:'unreachable',8:'ping request',9:'router advertisment',10:'router solicitation',11:'time exceeded',12:'invalid'}
	if icmp_type in types:
		return types[icmp_type]
	else:
		return 'unknown'	#Outputs human readable representation of icmp type

#ICMP Code Analysis
def read_icmp_code(icmp_type,code):	#takes int icmp type, int icmp code
	if icmp_type==0 or icmp_type==8 or icmp_type==9 or icmp_type==10:
		return 'normal'
	elif icmp_type==3:
		codes={0:'network unreachable',1:'host unreachable',2:'protocol unreachable',3:'port unreachable',4:'fragmentation required',5:'source route failed',6:'destination network unknown',7:'destination host unknown',9:'destination network administratively prohibited',10:'destination host administratively prohibited',11:'network unreachable for tos',12:'host unreachable for tos',13:'communication administratively filtered',14:'host precedence violation',15:'precedence cutoff'}
		if code in codes:
			return codes[code]
		else:
			return 'unknown'
	elif icmp_type==11:
		codes={0:'ttl expired in transit',1:'ttl expired in reassembly'}
		if code in codes:
			return codes[code]
		else:
			return 'unknown'
	elif icmp_type==12:
		codes={0:'ip header bad',1:'options missing'}
		if code in codes:
			return codes[code]
		else:
			return 'unknown'
	else:
		return 'unknown'	#Outputs human readable representation of icmp code

#ICMP Disassembly
def read_ping(data):	#takes bytes data
	ping_type=0
	code=0
	ping_check=''
	ident=0
	ping_seq=0
	icmp_time=''
	extra=''
	for i in range(34,len(data)):
		if i<35:
			ping_type=data[i]
		elif i<36:
			code=data[i]
		elif i<38:
			ping_check+=u_hex(data[i])
		elif i<40:
			if i==38:
				ident=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<42:
			if i==40:
				ping_seq=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<50:
			icmp_time+=u_hex(data[i])
		else:
			extra+=u_hex(data[i])
	return ping_type,code,ping_check,ident,ping_seq,icmp_time,extra
	"""
	returns int icmp type, int icmp code, hex icmp checksum, int icmp identifer number, int icmp sequence number,
	hex icmp timestamp, hex icmp payload"""

#ARP Disassembly
def read_arp(data):	#takes bytes data
	h_type=0
	proto=''
	h_size=0
	proto_size=0
	opcode=0
	snd_mac=''
	snd_ip=''
	tgt_mac=''
	tgt_ip=''
	extra=''
	for i in range(14,len(data)):
		if i<16:
			if i==14:
				h_type=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<18:
			proto+=u_hex(data[i])
		elif i<19:
			h_size=data[i]
		elif i<20:
			proto_size=data[i]
		elif i<22:
			if i==20:
				opcode=int(u_hex(data[i])+u_hex(data[i+1]),16)
		elif i<28:
			snd_mac+=u_hex(data[i])
		elif i<32:
			snd_ip+=u_hex(data[i])
		elif i<38:
			tgt_mac+=u_hex(data[i])
		elif i<42:
			tgt_ip+=u_hex(data[i])
		else:
			extra+=u_hex(data[i])
	#Conversion of easy hexadecimal representations to text for human readability
	if opcode==1:
		opcode='request'
	elif opcode==2:
		opcode='reply'
	else:
		opcode='unknown'
	snd_ip=u_ip(snd_ip)
	tgt_ip=u_ip(tgt_ip)
	return h_type,proto,h_size,proto_size,opcode,snd_mac,snd_ip,tgt_mac,tgt_ip
	"""
	returns int arp hardware type, hex arp protocol, int arp hardware size, int arp protocol size,
	string arp operation type, hex sender MAC, human readable sender ip, hex target MAC,
	human readable target ip"""

#MAC Address Evaluator
def mac_eval(mac,spec_mac=spec_mac,gateway_mac=gateway_mac,self_mac=self_mac):	#takes hex MAC
	#Constant Mac Addresses
	bcast='ffffffffffff'
	invalid='000000000000'
	mcast_min='01005e000000'
	mcast_max='01005e7fffff'
	#Conversion to Numbers
	nmac=int(mac,16)
	mcast_min=int(mcast_min,16)
	mcast_max=int(mcast_max,16)
	#Finally the logic
	if mac==gateway_mac:
		return 'gateway'
	elif mac==self_mac:
		return 'self'
	elif mac in spec_mac:
		return spec_mac[mac]#Special User Defined Mac Addresses
	elif mac==bcast:
		return 'broadcast'
	elif nmac>=mcast_min and nmac<=mcast_max:
		return 'multicast'
	elif mac==invalid:
		return 'none'
	else:
		return 'other'							#Outputs human readable represenation of the MAC type

#Layer 4 IPv4 Protocol Builder
def set_proto(proto):			#takes human readable representation of layer 4 protocol type
	types={'icmp':1,'igmp':2,'tcp':6,'udp':17}
	if proto in types:
		return types[proto]
	else:
		return 'unknown'	#Outputs int ipv4 protocol type, or string if error occured

#Ethertype Builder
def set_pckt_type(pckt_type):		#takes human readable represenation of ethernet packet type (ethertype)
	types={'ipv4':'0800','arp':'0806','wol':'0842','ipv6':'86dd','flow':'8808'}
	if pckt_type in types:
		return types[pckt_type]
	else:
		return 'unknown'	#Outputs hex ethernet packet type (ethertype), or string if error occured

#Ip to Hex (the more favoured function)
def iptohex(ip):	#takes human readable ip address
	ip=ip.split('.')
	ip=u_hex(int(ip[0]))+u_hex(int(ip[1]))+u_hex(int(ip[2]))+u_hex(int(ip[3]))
	return ip	#Outputs hexadecimal representaion of ip address

#DEBUG (for printing out SENT packet information)
def ndebug(data):	#I am not explaining the debug function
	print('DEBUG!')
	dst_mac,src_mac,pckt_type=read_mac(data)
	u_dst_mac=mac_eval(dst_mac)
	u_src_mac=mac_eval(src_mac)
	if u_dst_mac!='other':
		print('      Dst MAC: '+u_dst_mac)
	else:
		print('      Dst MAC: '+dst_mac)
	if u_src_mac!='other':
		print('      Src MAC: '+u_src_mac)
	else:
		print('      Src MAC: '+src_mac)
	form=get_pckt_type(pckt_type)
	print('    Pckt Type: '+form)
	if form=='ipv4':
		v,head_len,dsf,tot_len,ident,flags,ttl,proto,check,src_ip,dst_ip=read_ipv4(data)
		print('      IPv4 ID: '+str(ident))
		print('   IPv4 Flags: '+flags)
		print('          TTL: '+str(ttl))
		u_proto=get_proto(proto)
		if u_proto!='unknown':
			print('   IPv4 Proto: '+u_proto)
		else:
			print('   IPv4 Proto: '+str(proto))
		src_place=ip_eval(src_ip)
		dst_place=ip_eval(dst_ip)
		if src_place!='wan' and src_place!='lan':
			print('       Src IP: '+src_place)
		else:
			print('       Src IP: '+src_ip)
		if dst_place!='wan' and dst_place!='lan':
			print('       Dst IP: '+dst_place)
		else:
			print('       Dst IP: '+dst_ip)
		if u_proto=='tcp':
			src_port,dst_port,seq,ack,tcp_head_len,tcp_flags,wind_size,tcp_check,urg,opts,extra=read_tcp(data)
			print('     Src Port: '+str(src_port))
			print('     Dst Port: '+str(dst_port))
			print('    TCP Seq #: '+str(seq))
			print('    TCP Ack #: '+str(ack))
			nonce,cwr,ecn_echo,urgent,ackn,push,reset,syn_f,fin=read_flags(tcp_flags)
			print('   Nonce Flag: '+str(nonce))
			print('     CWR Flag: '+str(cwr))
			print('ECN-Echo Flag: '+str(ecn_echo))
			print('  Urgent Flag: '+str(urgent))
			print('     Ack Flag: '+str(ackn))
			print('    Push Flag: '+str(push))
			print('   Reset Flag: '+str(reset))
			print('     Syn Flag: '+str(syn_f))
			print('     Fin Flag: '+str(fin))
			print('  Window Size: '+str(wind_size))
			print('    Urgent ID: '+str(urg))
			print('     TCP Opts: '+opts)
			print('     TCP Data: '+extra)
		elif u_proto=='udp':
			src_port,dst_port,udp_len,udp_check,extra=read_udp(data)
			print('     Src Port: '+str(src_port))
			print('     Dst Port: '+str(dst_port))
			print('     UDP Data: '+extra)
		elif u_proto=='icmp':
			ping_type,code,ping_check,ident,ping_seq,icmp_time,extra=read_ping(data)
			u_type=read_icmp_type(ping_type)
			if u_type!='unknown':
				print('    ICMP Type: '+u_type)
			else:
				print('    ICMP Type: '+str(ping_type))
			u_code=read_icmp_code(ping_type,code)
			if u_code!='unknown':
				print('    ICMP Code: '+u_code)
			else:
				print('    ICMP Code: '+str(code))
			print('      ICMP ID: '+str(ident))
			print('     ICMP Seq: '+str(ping_seq))
			print('    ICMP Time: '+icmp_time)
			print('    ICMP Data: '+extra)
	if form=='arp':
		h_type,proto,h_size,proto_size,opcode,snd_mac,snd_ip,tgt_mac,tgt_ip=read_arp(data)
		print('     ARP Type: '+opcode)
		u_snd_mac=mac_eval(snd_mac)
		u_tgt_mac=mac_eval(tgt_mac)
		snd_place=ip_eval(snd_ip)
		tgt_place=ip_eval(tgt_ip)
		if snd_place!='wan' and snd_place!='lan':
			print('    Sender IP: '+snd_place)
		else:
			print('    Sender IP: '+snd_ip)
		if tgt_place!='wan' and tgt_place!='lan':
			print('    Target IP: '+tgt_place)
		else:
			print('    Target IP: '+tgt_ip)
		if u_snd_mac!='other':
			print('   Sender MAC: '+u_snd_mac)
		else:
			print('   Sender MAC: '+snd_mac)
		if u_tgt_mac!='other':
			print('   Target MAC: '+u_tgt_mac)
		else:
			print('   Target MAC: '+tgt_mac)
	print('')
	print('')

#The ACTUAL PROGRAM
def doit():
	#BECAUSE WE ARE IN A FUNCTION
	global lt		#timeout start timestamp
	global tims		#stage identifier
	global tmp_tims
	global stt		#delay start timestamp
	global did
	global serv_mac
	global tmp_src_ip
	global tmp_dst_ip
	global tmp_tcp
	global tmp_src_mac
	global lst_src		#used for lan identifcation, future security measure
	#Now the Logic
	if tims==0:	#Stage 1, send arp packet to check if server is up
		o=write_arp(True,self_mac,self_ip,'000000000000',serv_ip)
		pckt_type=set_pckt_type('arp')
		a=write_mac('ffffffffffff',self_mac,pckt_type,o)#Arp Request to Broadcast
		if debug==True:
			ndebug(a)
		r=send(a)
		if did==False:#prevention of infinite loop
			lt=time.time()#Timeout Setup
			did=True
		#Advance Stage
		tims+=1
		doit()
	elif tims==1:	#Stage 2, if server responds, grab it's mac address and try again later, else advance stage
		if time.time()-lt<1:#timeout of 1 second
			if form=='arp':
				if opcode=='reply':
					if snd_place=='serv':
						serv_mac=src_mac
						#delay configuration
						tims-=1#Go Back to Stage 1 after Delay
						tmp_tims=tims
						tims=10#Start Delay
						stt=time.time()
						did=False
		else:#The server is down
			if len(serv_mac)<=0:#check to see if you actually have your servers mac address
				#delay configuration
				tmp_tims=tims
				tims=10#Start Delay
				stt=time.time()
			else:
				#Advance Stage
				tims+=1
	elif tims==2:	#Stage 3, tell the gateway that the server's ip is now at your MAC address
		o=write_arp(False,self_mac,serv_ip,gateway_mac,gateway)#Arp Response to Gateway from Server
		pckt_type=set_pckt_type('arp')
		a=write_mac(gateway_mac,self_mac,pckt_type,o)
		if debug==True:
			ndebug(a)
		r=send(a)
		#Advance Stage
		tims+=1
		doit()
	elif tims==3:	#Stage 4, send ping to check if you own the server's ip
		o=write_ping()
		proto=set_proto('icmp')
		o=write_ip('0000',2,proto,serv_ip,gateway,o)
		pckt_type=set_pckt_type('ipv4')
		a=write_mac(gateway_mac,self_mac,pckt_type,o)
		if debug==True:
			ndebug(a)
		r=send(a)
		lt=time.time()#Timeout Setup
		#Advance Stage
		tims+=1
		doit()
	elif tims==4:	#Stage 5, if you own the server's ip, you will recieve a ping response, else try again
		if time.time()-lt<1:#timeout of 1 second
			if form=='ipv4':
				if u_proto=='icmp':
					if u_type=='ping reply':
						if dst_place=='serv':
							#Advance Stage
							tims+=1
		else:#No Response Recieved, try again
			print('CRITICAL FAILURE TIMS 4')
			tims=2
	elif tims==5:	#Stage 6, Now Configured For Recieving, this is the most flexible stage, except for the icmp and arp responses
		if form=='ipv4':
			print('ipv4')
			if dst_place=='serv':
				print('serv')
				if u_proto=='tcp':
					print('tcp')
					if dst_port==rem_port:#If it is port forwarded
						print(rem_port)
						if syn_f:#If Syn Flag is Set (new connections)
							print('syn')
							if src_place=='wan':#If it's from the wan
								#Saving Recieved Packet
								tmp_src_ip=src_ip
								tmp_dst_ip=dst_ip
								tmp_tcp=''
								for i in range(34,len(data)):
									tmp_tcp+=u_hex(data[i])
								tmp_src_mac=src_mac
								print(src_ip)
								print(dst_ip)
								print(src_mac)
								#Advance Stage
								tims+=1
								doit()
				elif u_proto=='icmp':#Respond to all ICMP Ping Requests
					if u_type=='ping request':
						lst_src=src_ip#Future Security Feature
						o=write_ping(False,u_hex(ident,4),u_hex(ping_seq,4),icmp_time,extra)
						proto=set_proto('icmp')
						o=ip_write(flags,64,proto,serv_ip,src_ip,o)
						pckt_type=set_pckt_type('ipv4')
						a=write_mac(snd_mac,self_mac,pckt_type,o)
						if debug==True:
							ndebug(a)
						r=send(a)
		elif form=='arp':#Respond to all ARP Requests
			if opcode=='request':
				if tgt_place=='serv':
					o=write_arp(False,self_mac,serv_ip,snd_mac,snd_ip)#Arp Response to Sender from Server
					pckt_type=set_pckt_type('arp')
					a=write_mac(snd_mac,self_mac,pckt_type,o)
					if debug==True:
						ndebug(a)
					r=send(a)
	elif tims==6:	#Stage 7, Wake up the Server
		o=write_wol(serv_mac)#Wake on LAN (via ethernet frame)
		pckt_type=set_pckt_type('wol')
		a=write_mac(serv_mac,self_mac,pckt_type,o)
		if debug==True:
			ndebug(a)
		r=send(a)
		#Advance Stage
		tims+=1
		doit()
	elif tims==7:	#Stage 8, tell the gateway that you no-longer own the server's ip?!?!?!  This stage may not be nessicary
		o=write_arp(False,self_mac,self_ip,gateway_mac,gateway)#Arp Response to Gateway from Server (supposed to be server)
		pckt_type=set_pckt_type('arp')
		a=write_mac(gateway_mac,self_mac,pckt_type,o)
		if debug==True:
			ndebug(a)
		r=send(a)
		#Advance Stage
		tims+=1
		doit()
	elif tims==8:	#Stage 9, send arp to server to check if it owns it's own ip, and it is up
		o=write_arp(True,self_mac,self_ip,'000000000000',serv_ip)#Arp Request to Broadcast
		pckt_type=set_pckt_type('arp')
		a=write_mac('ffffffffffff',self_mac,pckt_type,o)
		if debug==True:
			ndebug(a)
		r=send(a)
		lt=time.time()#Timeout Setup
		#Advance Stage
		tims+=1
		doit()
	elif tims==9:	#Stage 10, if recieved arp response from server, send initially recieved packet to server transparently, else try again
		if time.time()-lt<1:#timeout of 1 second
			if form=='arp':
				if opcode=='reply':
					if snd_place=='serv':#if recieved arp response from server, everything below in this stage is flexible
						o=tmp_tcp#Initally received tcp packet
						proto=set_proto('tcp')
						o=write_ip('0000',2,proto,tmp_src_ip,tmp_dst_ip,o)#Has to be sent from the inital sender ip
						pckt_type=set_pckt_type('ipv4')
						a=write_mac(serv_mac,tmp_src_mac,pckt_type,o)
						if debug==True:
							ndebug(a)
						r=send(a)
						#delay configuration, not flexible
						tims=0#return to start after delay
						tmp_tims=tims
						tims=10#start delay
						stt=time.time()
						did=False
		else:#Arp Response Not Recieved, So try again
			print('CRITICAL FAILURE TIMS 9')
			tims-=1
	else:	#Stage 11, Delay with callback, this stage is not flexable
		if time.time()>stt+dt:
			tims=tmp_tims
			doit()


#The Program

#Some Variables/Constants
tims=0
tmp_tims=0
lt=0
stt=0.0
did=False
serv_mac=''
lst_src=''
#Main Loop
while True:
	#Logic
	data=recv()#REQUIRED
	dst_mac,src_mac,pckt_type=read_mac(data)
	u_dst_mac=mac_eval(dst_mac)
	u_src_mac=mac_eval(src_mac)
	#Printing
	if u_dst_mac!='other':
		print('      Dst MAC: '+u_dst_mac)
	else:
		print('      Dst MAC: '+dst_mac)
	if u_src_mac!='other':
		print('      Src MAC: '+u_src_mac)
	else:
		print('      Src MAC: '+src_mac)
	#Logic
	form=get_pckt_type(pckt_type)
	#Printing
	print('    Pckt Type: '+form)
	#Logic
	if form=='ipv4':
		v,head_len,dsf,tot_len,ident,flags,ttl,proto,check,src_ip,dst_ip=read_ipv4(data)
		#Printing
		print('      IPv4 ID: '+str(ident))
		print('   IPv4 Flags: '+flags)
		print('          TTL: '+str(ttl))
		#Logic
		u_proto=get_proto(proto)
		#Printing
		if u_proto!='unknown':
			print('   IPv4 Proto: '+u_proto)
		else:
			print('   IPv4 Proto: '+str(proto))
		#Logic
		src_place=ip_eval(src_ip)
		dst_place=ip_eval(dst_ip)
		#Printing
		if src_place!='wan' and src_place!='lan':
			print('       Src IP: '+src_place)
		else:
			print('       Src IP: '+src_ip)
		if dst_place!='wan' and dst_place!='lan':
			print('       Dst IP: '+dst_place)
		else:
			print('       Dst IP: '+dst_ip)
		#Logic
		if u_proto=='tcp':
			src_port,dst_port,seq,ack,tcp_head_len,tcp_flags,wind_size,tcp_check,urg,opts,extra=read_tcp(data)
			#Printing
			print('     Src Port: '+str(src_port))
			print('     Dst Port: '+str(dst_port))
			print('    TCP Seq #: '+str(seq))
			print('    TCP Ack #: '+str(ack))
			#Logic
			nonce,cwr,ecn_echo,urgent,ackn,push,reset,syn_f,fin=read_flags(tcp_flags)
			#Printing
			print('   Nonce Flag: '+str(nonce))
			print('     CWR Flag: '+str(cwr))
			print('ECN-Echo Flag: '+str(ecn_echo))
			print('  Urgent Flag: '+str(urgent))
			print('     Ack Flag: '+str(ackn))
			print('    Push Flag: '+str(push))
			print('   Reset Flag: '+str(reset))
			print('     Syn Flag: '+str(syn_f))
			print('     Fin Flag: '+str(fin))
			print('  Window Size: '+str(wind_size))
			print('    Urgent ID: '+str(urg))
			print('     TCP Opts: '+opts)
			#print('     TCP Data: '+extra)#Disabled by default for readability
		#Logic
		elif u_proto=='udp':
			src_port,dst_port,udp_len,udp_check,extra=read_udp(data)
			#Printing
			print('     Src Port: '+str(src_port))
			print('     Dst Port: '+str(dst_port))
			#print('     UDP Data: '+extra)#Disabled by default for readablilty
		#Logic
		elif u_proto=='icmp':
			ping_type,code,ping_check,ident,ping_seq,icmp_time,extra=read_ping(data)
			u_type=read_icmp_type(ping_type)
			#Printing
			if u_type!='unknown':
				print('    ICMP Type: '+u_type)
			else:
				print('    ICMP Type: '+str(ping_type))
			#Logic
			u_code=read_icmp_code(ping_type,code)
			#Printing
			if u_code!='unknown':
				print('    ICMP Code: '+u_code)
			else:
				print('    ICMP Code: '+str(code))
			print('      ICMP ID: '+str(ident))
			print('     ICMP Seq: '+str(ping_seq))
			print('    ICMP Time: '+icmp_time)
			print('    ICMP Data: '+extra)
	#Logic
	if form=='arp':
		h_type,proto,h_size,proto_size,opcode,snd_mac,snd_ip,tgt_mac,tgt_ip=read_arp(data)
		#Printing
		print('     ARP Type: '+opcode)
		#Logic
		u_snd_mac=mac_eval(snd_mac)
		u_tgt_mac=mac_eval(tgt_mac)
		snd_place=ip_eval(snd_ip)
		tgt_place=ip_eval(tgt_ip)
		#Printing
		if snd_place!='wan' and snd_place!='lan':
			print('    Sender IP: '+snd_place)
		else:
			print('    Sender IP: '+snd_ip)
		if tgt_place!='wan' and tgt_place!='lan':
			print('    Target IP: '+tgt_place)
		else:
			print('    Target IP: '+tgt_ip)
		if u_snd_mac!='other':
			print('   Sender MAC: '+u_snd_mac)
		else:
			print('   Sender MAC: '+snd_mac)
		if u_tgt_mac!='other':
			print('   Target MAC: '+u_tgt_mac)
		else:
			print('   Target MAC: '+tgt_mac)
	#Logic
	doit()#REQUIRED
	#Printing
	print('')
	if debug==True:
		print(tims)
		print((stt+dt)-time.time())
	print('')
