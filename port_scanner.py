#!/usr/bin/env python3

## port_scanner.py

import socket
from scapy.all import *
import random

# resources
# https://scapy.readthedocs.io/en/latest/usage.html
# https://docs.python.org/3/library/socket.html

# target_ip = sys.argv[0]
VERBOSE = True


def normal_port_scan(target_ip, port):
    addr = (target_ip, port)

    # set up socket to send message
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.02)  # give 20ms to respond (pinging took <=10 ms)
        refused = s.connect_ex(addr)  # 0 if port open
        if not refused:
            print(f'~~Port {port} is open.~~')
            return 1

    return 0


def port_scan(target_ip, order):
    total_open = 0

    if order == "order":
        # scan in order
        for port in range(2**16):
            # print(f'Scanning port {port}')
            total_open += normal_port_scan(target_ip, port)
    else:
        # scan in random order
        ports = list(range(2**16))
        random.shuffle(ports)  # random list of ports
        print(ports[:100])
        for port in ports:
            print(f'Scanning port {port}')
            total_open += normal_port_scan(target_ip, port)

    return total_open


def main():
    target_ip = "131.229.72.13"
    order = "random"

    # ping the target_ip to test if live
    x = IP(ttl=5)
    x.dst = target_ip  # target host  # I'm at 47.82
    live = sr1(x/ICMP())  # None if no response

    # if host is live, initiate port scanner
    if live:
        if VERBOSE:
            print(">>>Host is live.")
        total_open = port_scan(target_ip, order)
        print(f'{total_open} total ports open.')


main()

