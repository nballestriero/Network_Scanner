# File Invalidate Caches se non funzionano i suggerimenti sulle classi importate
# scapy.ls(arp_request_broadcast)
# arp_request_broadcast.show()
# scapy.ls(broadcast)
# print(answered_list.summary())
import scapy.all as scapy
import argparse


def scan_ip(ip):
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    broadcast = scapy.Ether()
    broadcast.dst = "ff:ff:ff:ff:ff:ff"
    arp_request_broadcast = broadcast / arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC_ADDRESS")
    print("- - - - - - - - - - - - - - - - - - - - - -")
    for client in result_list:
        print(client["ip"], end='\t\t')
        print(client["mac"])
        print("-------------------------------------------")


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range")
    options = parser.parse_args()
    return options


options = get_arguments()
result_list = scan_ip(options.target)
print_result(result_list)
