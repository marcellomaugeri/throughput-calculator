#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import math

RTS_size = 20 #byte
CTS_size = 14 #byte

#Constants for 802.11a
a802 = {
    "sifs" : 16, #μs
    "difs" : 34, #μs
    "sdur" : 4, #μs
    "min_nbits" : 1,
    "max_nbits" : 6,
    "min_crate" : 1/2,
    "max_crate" : 3/4,
    "min_nchan" : 48,
    "max_nchan" : 48 ,
    "min_nss" : 1,
    "max_nss" : 1,
    "min_ttPreamble" : 20, #μs
    "max_ttPreamble" : 20, #μs
    "data_size" : 1500, #bytes
    "mac_header_size" : 34, #bytes
    "snap_header_size" : 8, #bytes
    "tcp_ack_size" : 40, #bytes
}

#Constants for 802.11g
g802 = {
    "sifs" : 10, #μs
    "difs" : 28, #μs
    "sdur" : 4, #μs
    "min_nbits" : 1,
    "max_nbits" : 6,
    "min_crate" : 1/2,
    "max_crate" : 3/4,
    "min_nchan" : 48,
    "max_nchan" : 48,
    "min_nss" : 1,
    "max_nss" : 1,
    "min_ttPreamble" : 20, #μs
    "max_ttPreamble" : 20, #μs
    "data_size" : 1500, #bytes
    "mac_header_size" : 34, #bytes
    "snap_header_size" : 8, #bytes
    "tcp_ack_size" : 40, #bytes
    "signal_extension_to_every_frame" : 6, #μs
}

#Constants for 802.11n
n802 = {
    "sifs" : 16, #μs
    "difs" : 34, #μs
    "sdur" : 3.6, #μs
    "min_nbits" : 1,
    "max_nbits" : 6,
    "min_crate" : 1/2,
    "max_crate" : 5/6,
    "min_nchan" : 52,
    "max_nchan" : 108,
    "min_nss" : 1,
    "max_nss" : 4,
    "min_ttPreamble" : 20, #μs
    "max_ttPreamble" : 46, #μs
    "data_size" : 1500, #bytes
    "mac_header_size" : 40, #bytes
    "snap_header_size" : 8, #bytes
    "tcp_ack_size" : 40, #bytes
}

#Constants for 802.11ac_w1
acw1802 = {
    "sifs" : 16, #μs
    "difs" : 34, #μs
    "sdur" : 3.6, #μs
    "min_nbits" : 1,
    "max_nbits" : 8,
    "min_crate" : 1/2,
    "max_crate" : 5/6,
    "min_nchan" : 52,
    "max_nchan" : 234,
    "min_nss" : 1,
    "max_nss" : 3,
    "min_ttPreamble" : 20, #μs
    "max_ttPreamble" : 56.8, #μs
    "data_size" : 1500, #bytes
    "mac_header_size" : 40, #bytes
    "snap_header_size" : 8, #bytes
    "tcp_ack_size" : 40, #bytes
}

#Constants for 802.11ac_w2
acw2802 = {
    "sifs" : 16, #μs
    "difs" : 34, #μs
    "sdur" : 3.6, #μs
    "min_nbits" : 1,
    "max_nbits" : 8,
    "min_crate" : 1/2,
    "max_crate" : 5/6,
    "min_nchan" : 52,
    "max_nchan" : 468,
    "min_nss" : 1,
    "max_nss" : 8,
    "min_ttPreamble" : 20, #μs
    "max_ttPreamble" : 92.8, #μs
    "data_size" : 1500, #bytes
    "mac_header_size" : 40, #bytes
    "snap_header_size" : 8, #bytes
    "tcp_ack_size" : 40, #bytes
}

#Constants for 802.11ax
ax802 = {
    "sifs" : 16, #μs
    "difs" : 34, #μs
    "sdur" : 13.6, #μs
    "min_nbits" : 1,
    "max_nbits" : 10,
    "min_crate" : 1/2,
    "max_crate" : 5/6,
    "min_nchan" : 234,
    "max_nchan" : 1960,
    "min_nss" : 1,
    "max_nss" : 8,
    "min_ttPreamble" : 20, #μs
    "max_ttPreamble" : 92.8, #μs
    "data_size" : 1500, #bytes
    "mac_header_size" : 40, #bytes
    "snap_header_size" : 8, #bytes
    "tcp_ack_size" : 40, #bytes
}

def evaluate(standard=a802, protocol="udp", mode="max"):
    #Frame size 
    packet_size = standard["data_size"] + standard["mac_header_size"] + standard["snap_header_size"]
    #Time to transmit a symbol
    dataPerOFDM = math.floor(standard["max_nbits"] * standard["max_crate"] * standard["max_nchan"] * standard["max_nss"] if mode=="max" else standard["min_nbits"] * standard["min_crate"] * standard["min_nchan"] * standard["min_nss"] )
    #Bits to append on each frame
    tail = 6
    #Time to transfer the MAC Ack
    ttAck = math.ceil((14*8 + tail)/dataPerOFDM)*standard["sdur"]
    #Time to transfer the frame
    ttPacket = math.ceil((packet_size*8 + tail)/dataPerOFDM)*standard["sdur"]
    #Time to transfer the TCP Ack
    ttTCPAckPacket = math.ceil(((standard["tcp_ack_size"] + standard["mac_header_size"] + standard["snap_header_size"])*8 + tail)/dataPerOFDM)*standard["sdur"]
    #Time to transfer RTS
    ttRTS = math.ceil((RTS_size*8 + tail)/dataPerOFDM)*standard["sdur"]
    #Time to transfer CTS
    ttCTS = math.ceil((CTS_size*8 + tail)/dataPerOFDM)*standard["sdur"]
    #Time needed to an entire communication
    ttFull = standard["difs"] + ttRTS + 3*standard["sifs"] + ttCTS + ttPacket + ttAck + 4 * (standard["max_ttPreamble"] if mode=="max" else standard["min_ttPreamble"])
    #Time total needed to send TCP Ack
    ttTCPAck = standard["difs"] + ttRTS + 3*standard["sifs"] + ttCTS + ttTCPAckPacket + ttAck + 4 * (standard["max_ttPreamble"] if mode=="max" else standard["min_ttPreamble"])
    #Add a signal extension to each frame where using 802.11g
    if(standard==g802):
        ttFull = ttFull + standard["signal_extension_to_every_frame"]
        ttTCPAckPacket = ttTCPAck + standard["signal_extension_to_every_frame"]
    #Actual throughput calculation
    throughput = round((1500*8)/(ttFull) , 2) if protocol=="udp" else round((1500*8)/(ttFull + ttTCPAck) , 2)
    #Time to transfer 15*10^9 calculation
    time_to_15 = math.ceil((15*(10**9) *8) / (throughput*(10**6)))
    return {'throughput': throughput, "time15": time_to_15}

#Extra method to print and debug all results
def print_all():
    result = evaluate(a802, "udp", "min")
    print("802.11a - UDP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(a802, "udp", "max")
    print("802.11a - UDP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(g802, "udp", "min")
    print("802.11g - UDP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(g802, "udp", "max")
    print("802.11g - UDP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(n802, "udp", "min")
    print("802.11n - UDP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(n802, "udp", "max")
    print("802.11n - UDP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw1802, "udp", "min")
    print("802.11ac_w1 - UDP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw1802, "udp", "max")
    print("802.1ac_w1 - UDP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw2802, "udp", "min")
    print("802.11ac_w2 - UDP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw2802, "udp", "max")
    print("802.1ac_w2 - UDP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(ax802, "udp", "min")
    print("802.11ax - UDP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(ax802, "udp", "max")
    print("802.1ax - UDP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")

    result = evaluate(a802, "tcp", "min")
    print("802.11a - TCP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(a802, "tcp", "max")
    print("802.11a - TCP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(g802, "tcp", "min")
    print("802.11g - TCP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(g802, "tcp", "max")
    print("802.11g - TCP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(n802, "tcp", "min")
    print("802.11n - TCP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(n802, "tcp", "max")
    print("802.11n - TCP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw1802, "tcp", "min")
    print("802.11ac_w1 - TCP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw1802, "tcp", "max")
    print("802.1ac_w1 - TCP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw2802, "tcp", "min")
    print("802.11ac_w2 - TCP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(acw2802, "tcp", "max")
    print("802.1ac_w2 - TCP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(ax802, "tcp", "min")
    print("802.11ax - TCP - Min rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")
    result = evaluate(ax802, "tcp", "max")
    print("802.1ax - TCP - Max rate: \nThroughput: " + str(result["throughput"]) + " Mbps\nTime to transfer 15 x 10^9 bytes: " + str(result["time15"]) + " seconds\n")

print("Choose the standard:")
print("1) 802.11a")
print("2) 802.11g")
print("3) 802.11n")
print("4) 802.11ac_w1")
print("5) 802.11ac_w2")
print("6) 802.11ax")
print("7) Print all")
c1 = int(input())
if c1 == 1:
    standard = a802
elif c1 == 2:
    standard = g802
elif c1 == 3:
    standard = n802
elif c1 == 4:
    standard = acw1802
elif c1 == 5:
    standard = acw2802
elif c1 == 6:
    standard = ax802
elif c1 == 7:
    print_all()
    exit(1)
else:
    print("Incorrect")
    exit(1)
print("Choose the data rate:")
print("1) Min")
print("2) Max")
c2 = int(input())
if c2==1:
    mode = "min"
elif c2==2:
    mode = "max"
else:
    print("Incorrect")
    exit(1)
print("UDP or TCP?")
print("1) UDP")
print("2) TCP")
c3 = int(input())
if c3==1:
    protocol = "udp"
elif c3==2:
    protocol = "tcp"
else:
    print("Incorrect")
    exit(1)
result = evaluate(standard, protocol, mode)
print("The actual MAC throughput is " + str(result["throughput"]) + " Mbps, the time needed to transfer 15 x 10^9 bytes of data is " + str(result["time15"]) + " seconds")