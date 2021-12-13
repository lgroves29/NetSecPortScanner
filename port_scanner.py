#!/usr/bin/env python3

## port_scanner.py

import socket
from scapy.all import *
import random
import argparse
import time
from datetime import datetime

# resources
# https://scapy.readthedocs.io/en/latest/usage.html
# https://docs.python.org/3/library/socket.html
# https://stackoverflow.com/questions/15377150/how-can-i-call-the-send-function-without-getting-output
# https://stackoverflow.com/questions/46062105/rounding-floats-with-f-string
# https://nickmccullum.com/python-command-line-arguments
# https://docs.python.org/3/library/argparse.html#module-argparse
# common port numbers pulled from: https://en.wikipedia.org/wiki/Port_(computer_networking)

common_ports = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 123, 143, 161, 194, 443]


def normal_port_scan(target_ip, ports, order="sequential"):
    """
    input: target ip address, list of ports to scan, and port scanning order
    output: list of open ports by number
    description: normal port scan the given ip address at each port by sending
    a connection request.
    """
    open_ports = []

    # port order
    if order == "random":
        random.shuffle(ports)
    elif order == "sequential":
        pass
    else:
        raise Exception("Invalid port order selected")

    # scan each port
    for port in ports:
        # print(f'Scanning port {port}')
        # set up socket to send message
        addr = (target_ip, port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.02)  # give 20ms to respond (pinging took <=10 ms)
            refused = s.connect_ex(addr)  # 0 if port open
            if not refused:  # port is open
                print(f'>>>>Port {port} is open.')
                # receive response from open port
                response = s.recv(200)
                print(f'>>>>Response: {response}')
                open_ports.append(port)

    return open_ports


def SYN_scan(ip_addr, ports, order="sequential"):
    """
    input: target ip address, a list of ports to scan, and port scanning order
    output: list of open ports by number
    description: syn scan the given ip address at each port by sending a SYN
    packet, waiting for an ACK response, then sending RST to end the handshake
    """
    open_ports = []

    # port order
    if order == "random":
        random.shuffle(ports)
    elif order == "sequential":
        pass
    else:
        raise Exception("Invalid port order selected")

    # scan each port
    for i in ports:
        resp = sr1(IP(dst=ip_addr)/TCP(dport=i, flags='S'), timeout=.02, verbose=0)     
        try: 
            # TCP SYN/ACK flag = 0x12
            if resp.getlayer(TCP).flags == 0x12:
                print(f'>>>>Port {i} is open.')
                open_ports.append(i)
            # send RST packet to reset connection
            sr1(IP(dst=ip_addr)/TCP(dport=i, flags='R'), timeout=.02, verbose=0) 
        except: 
            pass

    return open_ports


def FIN_scan(ip_addr, ports, order="sequential"):
    """
    input: target ip address, list of ports to scan, and port scanning order
    output: list of open ports by number
    description: FIN scan the given ip address at each port by sending a FIN
    packet and watching for an RST packet in response (indicates the port is
    closed). An open port does not respond to a TCP FIN message
    """
    open_ports = []

    # port order
    if order == "random":
        random.shuffle(ports)
    elif order == "sequential":
        pass
    else:
        raise Exception("Invalid port order selected")

    # scan each port
    for i in ports:
        resp = sr1(IP(dst=ip_addr)/TCP(dport=i, flags='F'), timeout=.02, verbose=0)     
        if resp:
            # if the port responds, that indicates it is closed
            pass
        else: 
            # an open port will not respond to a FIN packet
            print(f'>>>>Port {i} is open.')
            open_ports.append(i)

    return open_ports


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process user options')
    parser.add_argument('-mode')
    parser.add_argument('-order')
    parser.add_argument('-ports')
    parser.add_argument('-ip_address')  # 131.229.72.13 for class
    args = parser.parse_args()
    mode = args.mode
    order = args.order
    ports = args.ports
    target_ip = args.ip_address
    port_nums = []
    open_ports = []

    # validate user input
    if (mode != "SYN" and mode != "FIN" and mode != "normal"):
        print("Invalid mode selected!")
        quit()
    if (ports != "common" and ports != "all" and ports != "short"):
        print("Invalid port option selected!")
        quit()
    if (order != "random" and order != "sequential"):
        print("Invalid order selected!")  
        quit()  
    if ports == "common":
        port_nums = common_ports
    elif ports == "all":
        port_nums = list(range(2**16))  # about 2200 seconds
    elif ports == "short":
        port_nums = list(range(2**7))  # a short run of all ports 0-127

    print("-"*50)
    print("starting port scan of address {} at {}".format(target_ip, datetime.now()))
    print("scanning {} ports in {} order".format(ports, order))

    # ping the target_ip to test if host is live
    x = IP(ttl=64)
    x.dst = target_ip  # target host
    live = sr1(x / ICMP(), verbose=False)  # None if no response

    # if host is live, initiate port scanner
    if live:
        print(f'>>Host ({target_ip}) is live.')
        start = time.time()
        # call given port scanning mode
        if mode == "normal":
            open_ports = normal_port_scan(target_ip, port_nums, order)
        elif mode == "SYN":
            open_ports = SYN_scan(target_ip, port_nums, order)
        elif mode == "FIN":
            open_ports = FIN_scan(target_ip, port_nums, order)

        # time the port scanning
        stop = time.time()
        execution_time = stop - start

        # output table
        print('-'*30)
        print(f'Interesting ports on {target_ip}:')
        print(f'Not shown: {len(port_nums) - len(open_ports)} closed ports.')
        print(f'PORT\tSTATE\tSERVICE')
        for port in open_ports:
            # report service for each open port
            print(f'{port}\topen\t{socket.getservbyport(port)}')
        print(f'{len(open_ports)} total port(s) open.')
        print(f'scan done! 1 IP address ({target_ip}) scanned in {execution_time:.2f} seconds.')
    else:
        print(f'>>Host ({target_ip}) is not live.')

