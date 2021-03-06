#!/usr/bin/env python
'''
COMPATIBLE: python2 and python3
USAGE: Finds all of the devices on a network
ARGUMENTS:
    1) -t or --target
EXAMPLE: python3 network_scanner.py -t 10.0.0.1/24
HOW IT WORKS: Uses arp protocol to discover devices on target network
TROUBLESHOOTING: If this doesn't work, make sure wired connection is turned off

IMPROVEMENTS NEEDED:
    1) Update display when new devices are found
        To do this we must keep on sending arp packets
    2) Provide a default argument if one isnt given
        If argument given
            ip = argument
        Else
            ip = wlan0 gateway_ip/24
'''

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan_Method1(ip):
    scapy.arping(ip)

def scan_Method2(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("---------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan_Method2(options.target)
print_result(scan_result)
