from os import times

#!/usr/bin/python3
import socket
import time
import struct


MESSAGE = "measurement for class project. questions to Xiaofan He xxh395@case.edu or professor mxr136@case.edu"
UNEXPECTED_PACKET = "Recieved Packet From Unrelated Scource"
TOTAL_SENT = 7
IP_HEADER_STRUCT = struct.Struct('!BBHHHBBH4s4s')
UDP_HEADER_STRUCT = struct.Struct('!HHHH')
PAYLOAD_LEN = 1500 - UDP_HEADER_STRUCT.size - IP_HEADER_STRUCT.size
UDP_PAYLOAD = bytes(MESSAGE	+ 'a'*(1472 - len(MESSAGE)), 'ascii')
pkt_send_times = {}
MAX_ATTEMPTS = 5
DEFAULT_TTL = 64 
DEST_PORT = 33434
MAX_MSG_LEN = 5000
SOURCE_IP = socket.gethostbyname(socket.gethostname())


#Read target.txt 
def read_targets():
    targets = {}
    for line in open('targets.txt'):
        name = line.rstrip()
        targets[name] = socket.gethostbyname(name)
    return targets

#Read target.txt 
def get_total():
    total_num = 0
    for line in open('targets.txt'):
        total_num = total_num + 1
    return total_num

TOTAL_SENT = get_total()

def generate_IP_header(TTL, send_id, source_ip, dest_ip):
    #resource: https://www.binarytides.com/raw-socket-programming-in-python-linux/ 

    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0	# kernel will fill the correct total length
    ip_id = send_id	#Id of this packet
    ip_frag_off = 0
    ip_ttl = TTL
    ip_proto = socket.IPPROTO_UDP
    ip_check = 0	# kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )
    ip_daddr = socket.inet_aton ( dest_ip )
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    return IP_HEADER_STRUCT.pack(ip_ihl_ver, ip_tos, 
                            ip_tot_len, ip_id, ip_frag_off, ip_ttl, 
                            ip_proto, ip_check, ip_saddr, ip_daddr)




# checksum functions needed for calculation checksum
def checksum(msg):
    #resource: https://www.binarytides.com/raw-socket-programming-in-python-linux/ 

	s = 0
	
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = msg[i] + (msg[i+1] << 8 )
		s = s + w
	
	s = (s>>16) + (s & 0xffff)
	s = s + (s >> 16)
	
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	
	return s

#generate UDP header 
def generate_UDP_header(source_port, dest_port, source_ip, dest_ip):
    length = UDP_HEADER_STRUCT.size + PAYLOAD_LEN
    cur_header = struct.pack('!4s4sBBH', socket.inet_aton ( source_ip ), 
     socket.inet_aton ( dest_ip ), 0, socket.IPPROTO_UDP, length)
    message = cur_header + UDP_HEADER_STRUCT.pack(source_port, dest_port, length, 0)
    check = socket.htons(checksum(message + UDP_PAYLOAD))
    UDP_header = struct.pack('!HHHH', source_port, dest_port, length, check)
    return UDP_header

#generate probe with UDP header, IP header, and payload with the disclaimer message
def generate_probe(source_port, dest_port, source_ip, dest_ip, id):
    UDP_header = generate_UDP_header(source_port, dest_port, source_ip, dest_ip)
    IP_header = generate_IP_header(DEFAULT_TTL, id, source_ip, dest_ip)
    probe_packet = IP_header + UDP_header + UDP_PAYLOAD
    return probe_packet


#Generate the sending socket
def generate_send_socket():
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    return send_socket

#Get the raw socket for receiving ICMP messages
def generate_recv_socket():
    recv_sock =	socket.socket(socket.AF_INET, socket.SOCK_RAW,	socket.IPPROTO_ICMP)
    recv_sock.setblocking(0)
    recv_sock.bind(("", 0))
    return recv_sock

#get all host info (host ip and host name) from the file
host_info = read_targets()
Items = host_info.items()


#the sending socket, send all targets from targets.txt
def send_thread(): 
    send_socket = generate_send_socket()
    #record the send time of each packet, for further calculation of RTT
    #Get all host information
    src_port = DEST_PORT + 1
    for item in Items:
        host_name = item[0]
        host_ip = item[1]  
        #Each packet sends for at most 5 times   
        attempt = 0
        successful_send = False
        id = int(time.time() * 1000) & 0xFFFF
        probe = generate_probe(src_port, DEST_PORT, SOURCE_IP, host_ip, id)
        while not successful_send and attempt < MAX_ATTEMPTS:
            try:
                #Send Packet
                packet_send_time = time.time()
                send_socket.sendto(probe, (host_ip, DEST_PORT))
                pkt_send_times[host_name] = packet_send_time
                successful_send = True
                src_port = src_port + 1
            except socket.error:
                #print failure message and resend
                print("Packet Sending failed for hostname: {}".format(host_name))
                attempt += 1
        if not successful_send:
            print("Timed Out")
    send_socket.close()

def rcv_thread(): 
        Rcv_socket = generate_recv_socket()
        times_rcved = 0
        hops_rcved = {}
        RTTs = {}
        succeed = {}
        for itm in Items: 
            succeed[itm[0]] = False
            host_name = itm[0]
        while(times_rcved < TOTAL_SENT): 
            times = 0
            try: 
                response = Rcv_socket.recv(MAX_MSG_LEN)
                pkt_receive_time = time.time()
                found = False
                #Read ICMP Packet Response Information
                source_ip = socket.inet_ntoa(response[12:16])
                host_ip = source_ip
                dest_port = struct.unpack("!H", response[50:52])[0]
                dest_ip = socket.inet_ntoa(response[16:20])
                for item in Items: 
                    if(item[1] == host_ip): 
                        host_name = item[0]
                        found = True

                if(found == True): 
                    if(succeed[host_name] != True): 
                        times_rcved = times_rcved + 1

                        #Measure Hops
                        R_TTL = response[36]
                        hops = DEFAULT_TTL - R_TTL
                        hops_rcved[host_name] = hops
                        succeed[host_name] = True

                        #Measure id
                        request_infos = IP_HEADER_STRUCT.unpack(response[28:48])
                        id =  request_infos[3]

                        #Measure RTT
                        RTT = 1000 * (pkt_receive_time - pkt_send_times[host_name])
                        RTTs[host_name] = RTT
                        print("Target: {}:{}; Hops: {}; RTT: {}ms; Matched on: {},{},{}".format(host_name, host_ip, hops, RTT, dest_ip, id, dest_port))

                    else: 
                        print("host already received: {}".format(host_name))

                else: 
                    print("Host name not found")


            except socket.error:
                times = times + 1
                if(times > 8): 
                    send_thread()

        Rcv_socket.close


def run():
    start_time = time.time()
    send_thread()
    rcv_thread()
    # Rcv_socket.close()
    end_time = time.time()
    total_time = end_time - start_time
    print("Total time taken: {}".format(total_time))


if __name__ == "__main__":
    run()
