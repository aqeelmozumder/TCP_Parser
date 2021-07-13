# Name: Aqeel Mozumder
# Vnumber: V00884880
# File: trace_cap.py
# Course: CSC 361
# Dependencies of this file:
#                           basic_structures.py
#                       Therefore, please make sure to have basic_structures.py in the same directory as it is a dependency
# How to compile and run the file:
#                            python3 tcp_cap.py <capture_filename.cap>
# Description:
#          The idea of this file is to be broken down into 4 sections. The overview of the sections are decribed as follows:
#              Section 1 will be where all the data is unpacked by reading the cap file
#              Section 2 is required to list the unique tuples in a connection list
#              Section 3 is the longest section as this section has nested loops to search for complete connections in the connection list and will print out part A and B of the assignment
#              Section 4 will only print part C and D of the assignment

import sys
from collections import OrderedDict
from basic_structures import *

#importing the classes from basic_structures.py
ipheader = IP_Header()
packet = packet()
tcpheader = TCP_Header()

#Global Variables
packet_count = 0;  
res_count = 0
first_packettimestamp = 0
reset_connections = 0
reset_counter = 0
noFins = 0
connection_num = 0
Complete_cons = 0

#Global Lists
durations = [] #list of times
totalpackets = [] #list of total packets in/out
RTT = []
Windows = []
packets = [] #list of essential datas
Con_list = [] # list of all 4 tuples
strCon_list = [] #list of unique ports that determines the Con_list connections

f = open(sys.argv[1], 'rb') #read the file from command line
global_header = f.read(24) #Ignore all data in global header

#********************************************************************************************************************************************************************#
#SECTION 1 : Will Loop through all the packets until no data is left. And for each packet, the data are unpacked by basic_structures.py.
while True: 
    packet_header_1 = f.read(16)
    if not packet_header_1:
        break
    else:
        packet_count +=1
        
        #Extracting packet_header_1 to get timestamp and length of the packet header
        ts_sec = packet_header_1[0:4]
        ts_usec = packet_header_1[4:8]
        incl_len = packet_header_1[8:12]
        orig_len = packet_header_1[12:16]
        
        if(packet_count ==1):  #here we set the firs packet's orig time as 0 to get the epoch time
            orig_time = 0.0000
            packet.packet_No_set(packet_count)
            packet.timestamp_set(ts_sec,ts_usec,orig_time)
            first_packettimestamp = packet.timestamp
            packet.timestamp = 0
        #endif    
        else: #since now we have the epoch time, our orig time will always be that
            packet.packet_No_set(packet_count)
            orig_time = first_packettimestamp
            packet.timestamp_set(ts_sec,ts_usec,orig_time)
        #endelse

        packet_data_1 = f.read(int.from_bytes(incl_len, byteorder = 'little'))

        #Extracting packet_data_1 to get ip_v4 data
        ipheader.get_header_len(packet_data_1[14:15])
        ipheader.get_total_len(packet_data_1[16:19])
        ipheader.get_IP(packet_data_1[26:30],packet_data_1[30:34])

        #Extracting packet_data_1 to get tcp and payload data
        tcpheader.get_src_port(packet_data_1[34:36])
        tcpheader.get_dst_port(packet_data_1[36:38])
        tcpheader.get_seq_num(packet_data_1[38:42])
        tcpheader.get_ack_num(packet_data_1[42:46])
        tcpheader.get_data_offset(packet_data_1[46:47])
        tcpheader.get_flags(packet_data_1[47:48])
        tcpheader.get_window_size(packet_data_1[48:49],packet_data_1[49:50])

        timestamp = packet.timestamp
        source_ip = ipheader.src_ip
        destination_ip = ipheader.dst_ip
        source_port = tcpheader.src_port
        destination_port = tcpheader.dst_port
        payload_size = ipheader.total_len - (ipheader.ip_header_len + tcpheader.data_offset)
        seqNum = tcpheader.seq_num
        ackNum = tcpheader.ack_num
        wsize = tcpheader.window_size
        flags = tcpheader.flags
        
        packets.append([source_ip,destination_ip,source_port,destination_port,timestamp,flags['SYN'],flags['RST'],flags['FIN'], payload_size, seqNum, ackNum, wsize])
        Con_list.append([source_ip,destination_ip,source_port,destination_port])
    #endelse
#endWhile

#********************************************************************************************************************************************************************#
#SECTION 2 : This section will append all the unique tuples in a connection list so that there is only one unique connection for each tuple
conlist_len = len(Con_list) #lenght of the list
for x in range(0, conlist_len):
    greater_port = Con_list[x][2]
    smaller_port = Con_list[x][3]
    src_ip = Con_list[x][0]
    dst_ip = Con_list[x][1]
    if(greater_port > smaller_port or greater_port == smaller_port):
        strCon_list.append(src_ip + dst_ip + str(greater_port) + str(smaller_port))
    #endif
    elif(greater_port < smaller_port):
        strCon_list.append(dst_ip + src_ip + str(smaller_port) + str(greater_port))
    packets[x].append(strCon_list[x])
    #endelif
#endfor
strCon_list = list(OrderedDict.fromkeys(strCon_list))

#********************************************************************************************************************************************************************#
#SECTION 3: Prints Part A of the assignment and Part B
print ("A) Total number of TCP Connections:", len(strCon_list))
print ("_____________________________________________________________________\n")

print ("B) Connections' Details")
for x in strCon_list:
    pck_src_ip = "No IP Specified"
    pck_dst_ip = pck_src_ip
    great_port = 0
    samll_port = 0
    pck_src_dst = 0
    pck_dst_src = 0
    datapck_src_dst = 0
    datapck_dst_src = 0
    syn_counter = 0
    res_counter = 0
    fin_counter = 0
    firstSynTime = 0
    lastFinTime = 0
    synFlag = False
    resFlag = False
    ipFlag = False
    resFlag = False
    seq_data_bytes = {}

    for y in range(0, conlist_len):
        src_ip = packets[y][0]
        dst_ip = packets[y][1]
        src_port = packets[y][2]
        dst_port = packets[y][3]
        time = packets[y][4]
        syn = packets[y][5]
        rst = packets[y][6]
        fin = packets[y][7]
        payload_len = packets[y][8]
        seq_num = packets[y][9]
        ack_num = packets[y][10]
        win_len = packets[y][11]
        ThestrCon_list_tuple = packets[y][12]

        if(x == ThestrCon_list_tuple):
            if(ipFlag == False):
                ipFlag = True
                pck_src_ip = src_ip
                pck_dst_ip = dst_ip
                great_port = src_port
                samll_port = dst_port
            #endif
            if(syn == 1):
                if(synFlag == False):
                    synFlag = True
                    firstSynTime = time
                #endif  
                syn_counter = syn_counter + 1
            #endif
            if(rst == 1):
                res_counter = res_counter + 1
            #endif
            if(fin == 1):
                lastFinTime = time
                fin_counter = fin_counter + 1
            #endif
            if(src_ip == pck_src_ip):
                pck_src_dst = pck_src_dst + 1
                datapck_src_dst = datapck_src_dst + payload_len
            #endif
            elif(src_ip == pck_dst_ip):
                pck_dst_src = pck_dst_src + 1
                datapck_dst_src = datapck_dst_src + payload_len
            #endelif
            Windows.append(win_len) 
        #endif
    #endfor
    connection_num = connection_num + 1
    if(fin_counter == 0): #finds number of connections that are open
        noFins = noFins + 1
    #endif
    if(res_counter >= 1): #finds number of rst flags
        reset_counter = reset_counter + 1
    #endif
    if(syn_counter >= 1 and fin_counter >= 1): #As p2 mentions, a complete connection is when there is atleast 1 syn and 1 fin
        Status = None
        Complete_cons = Complete_cons + 1
        duration = lastFinTime-firstSynTime
        durations.append(duration)
        if(res_counter == 0):
            Status = "Status: S"+str(syn_counter)+"F"+str(fin_counter)
        #endif
        else:
            Status = "Status: S"+str(syn_counter)+"F"+str(fin_counter)+"/R"
            if(resFlag == False):
                resFlag = True
                reset_connections = reset_connections + 1
            #endif
        #endelse               
        for y in range(0, conlist_len): #this loop is to append the rtt values in the RTT list
            if(x == packets[y][12]): #calculate RTT fof complete connections 
                seq_data_bytes[packets[y][4]] = packets[y][9] + packets[y][8] #sequence + payload_len
                RTT_ack = packets[y][10]
                if(RTT_ack in seq_data_bytes.values()):
                    for key, val in seq_data_bytes.items():
                        if val == RTT_ack:
                            RTT.append(packets[y][4] - key)
                            seq_data_bytes[key] = ""
                            break_true = True
                        #endif
                    #endfor
                    if(break_true == True): #have to break out the loop or else will calculate more pairs
                        break_true = False
                        break
                    #endif
                #endif
            #endif
        #endfor
        
        print ("+++++++++++++++++++++++++++++++++++++++++++++")
        print ("Connection "+str(connection_num)+':')      
        print ('Source Address:', pck_src_ip)
        print ('Destination Address:', pck_dst_ip)
        print ('Source Port:', great_port)
        print ('Destination Port:', samll_port)
        print(Status)
        print ('Start Time: ', round(firstSynTime,7), 'seconds')
        print ('End Time: ', round(lastFinTime,7), 'seconds')
        print ('Duration: ', round(duration,7), 'seconds')
        print ('Number of packets from source to destination:', pck_src_dst, 'packets')
        print ('Number of packets from destination to source:', pck_dst_src, 'packets')
        print ('Total number of packets:', pck_src_dst+pck_dst_src, 'packets')
        print('Number of data bytes from source to destination:',datapck_src_dst, 'bytes')
        print('Number of data bytes from destination to source:',datapck_dst_src, 'bytes')
        print ('Total number of data bytes:', datapck_src_dst+datapck_dst_src, 'bytes' )
        
        totalpackets.append(pck_src_dst+pck_dst_src)
    #endif
    else: 
        if(res_counter != 0 and resFlag == False):
            Status = "Status: S"+str(syn_counter)+"F"+str(fin_counter)+"/R"
            resFlag = True
            reset_connections = reset_connections + 1
        else:
            Status = "Status: S"+str(syn_counter)+"F"+str(fin_counter)
        #endif
        print ("+++++++++++++++++++++++++++++++++++++++++++++")
        print ("Connection #", connection_num)
        print ('Source Address:', pck_src_ip)
        print ('Destination Address:', pck_dst_ip)
        print ('Source Port:', great_port)
        print ('Destination Port:', samll_port)
        print(Status)

    #endelse
#endfor

#********************************************************************************************************************************************************************# 
# Section 4: Prints Part C and D of the assignment       
print ("_____________________________________________________________________\n")
print ("C) General")
print ("Total number of complete TCP connections:", Complete_cons)
print ("Total number of reset TCP connections:", reset_counter)
print ("Number of TCP connections that were still open when the trace capture ended:", noFins)
print ("_____________________________________________________________________\n")
print ("D) Complete TCP Connections")
print ("Minimum time duration: %2f" % min(durations), "seconds")
print ("Mean time duration: %2f" % float(sum(durations)/max(len(durations), 1)), "seconds")
print ("Maximum time duration: %2f" % max(durations), "seconds")
print ("\n")
print ("Minimum RTT value: %2f" % min(RTT), "seconds")
print ("Mean RTT value: %2f" % float(sum(RTT)/max(len(RTT), 1)), "seconds")
print ("Maximum RTT value: %2f" % max(RTT), "seconds")
print ("\n")
print ("Minimum number of packets including both send/received:", min(totalpackets), 'packets')
print ("Mean number of packets including both send/received: %2f" % float(sum(totalpackets)/len(totalpackets)), 'packets')
print ("Maximum number of packets including both send/received:", max(totalpackets), 'packets')
print ("\n")
print ("Minimum receive window size including both send/received:", min(Windows), "bytes")
print ("Mean receive window size including both send/received: %2f" % float(sum(Windows)/len(Windows)), "bytes")
print ("Maximum receive window size including both send/received:", max(Windows), "bytes")
print ("_____________________________________________________________________\n")