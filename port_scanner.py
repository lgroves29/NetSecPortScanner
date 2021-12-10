#!/usr/bin/env python3

## port_scanner.py

import socket
from scapy.all import *
import random
import time
from datetime import datetime

# resources
# https://scapy.readthedocs.io/en/latest/usage.html
# https://docs.python.org/3/library/socket.html
# https://stackoverflow.com/questions/15377150/how-can-i-call-the-send-function-without-getting-output
# https://stackoverflow.com/questions/46062105/rounding-floats-with-f-string

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
            # receive response from open port
            response = s.recv(200)  # TODO: can we know which length to accept?
            print(f'Response: {response}')
            return True  # port is open

    return False


def port_scan(target_ip, order):
    open_ports = []

    if order == "order":
        # scan in order
        for port in range(2**7):
            # print(f'Scanning port {port}')
            if normal_port_scan(target_ip, port):
                open_ports.append(port)
    else:
        # scan in random order
        ports = list(range(2**7))
        random.shuffle(ports)  # random list of ports
        print(ports[:100])
        for port in ports:
            # print(f'Scanning port {port}')
            if normal_port_scan(target_ip, port):
                open_ports.append(port)

    return open_ports


def main():
    target_ip = "131.229.72.13"
    order = "order"

    start_time = time.time()
    print(f'Starting port scan {target_ip} at {datetime.now()}')

    # ping the target_ip to test if live
    x = IP(ttl=64)
    x.dst = target_ip  # target host  # I'm at 47.82
    live = sr1(x/ICMP(), verbose=False)  # None if no response

    # if host is live, initiate port scanner
    if live:
        if VERBOSE:
            print(f'>>>Host ({target_ip}) is live.')
        open_ports = port_scan(target_ip, order)

        # output table
        print('-'*30)
        print(f'Interesting ports on {target_ip}:')
        print(f'Not shown: {(2**16 if False else len([1, 2, 3])) - len(open_ports)} closed ports.')
        print(f'PORT\tSTATE\tSERVICE')
        for port in open_ports:
            # report service for each open port
            print(f'{port}\topen\t{socket.getservbyport(port)}')
        print(f'{len(open_ports)} total port(s) open.')
        print(f'scan done! 1 IP address ({target_ip}) scanned in {time.time() - start_time:.2f} seconds.')
    else:
        print(f'>>>Host ({target_ip}) is not live.')


main()
