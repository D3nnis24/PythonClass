#!/usr/bin/env python

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

    '''ls tells us what fields a scapy class has'''
    #scapy.ls(scapy.ARP())
    #scapy.ls(scapy.Ether())
    '''summary gives us a simple details about an object'''
    #print(arp_request.summary())
    #print(broadcast.summary())
    #print(arp_request_broadcast.summary())
    #print(answered_list.summary())
    '''show() shows us all the details/fields of each packet'''
    #arp_request.show()
    #broadcast.show()
    #arp_request_broadcast.show()
    #answered_list.show()

def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("---------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan_Method2(options.target)
print_result(scan_result)