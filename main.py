# File Invalidate Caches se non funzionano i suggerimenti sulle classi importate
import scapy.all as scapy


# scapy.ls(arp_request_broadcast)
# arp_request_broadcast.show()
# scapy.ls(broadcast)

def scan_ip(ip):
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    broadcast = scapy.Ether()
    broadcast.dst = "ff:ff:ff:ff:ff:ff"
    arp_request_broadcast = broadcast / arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    print(answered_list.summary())
    for element in answered_list:
        print(element[1].psrc)
        print(element[1].hwsrc)
        print("-------------------------------------")


scan_ip("10.0.3.0/24")
