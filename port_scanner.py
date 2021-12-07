from scapy.all import *
import sys
import random
import argparse

# https://nickmccullum.com/python-command-line-arguments
# https://docs.python.org/3/library/argparse.html#module-argparse
# common port numbers pulled from: https://en.wikipedia.org/wiki/Port_(computer_networking)#Common_port_numbers
common_ports = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 123, 143, 161, 194, 443]

def SYN_scan(ip_addr, ports, order="sequential"):
    """
    input: target ip address, a list of ports to scan, and port scanning order
    output: list of open ports by number, total ports scanned
    description: syn scan the given ip address at each port by sending a SYN
    packet, waiting for an ACK response, then sending RST to end the handshake
    """
    open_ports = []
    if order == "random":
        ports = random.shuffle(ports)
    elif order == "sequential":
        pass
    else:
        raise Exception("Invalid ports selected")
    print("ports: ", ports)
    for i in ports:
        print(i)
        resp = sr1(IP(dst=ip_addr)/TCP(dport=i, flags='S'), timeout=.5, verbose=0)     
        try: 
            print(resp.sprintf('%TCP.src% \t %TCP.sport% \t %TCP.flags%'))
            open_ports.append(i)
        except: 
            pass
    #print(open_ports)
    return open_ports



def FIN_scan(ip_addr, ports, order="sequential"):
    """
    input: target ip address, list of ports to scan, and port scanning order
    output: list of open ports by number, total ports scanned
    description: FIN scan the given ip address at each port by sending a FIN
    packet and watching for an RST packet in respose (indicates the port is live)
    """
    
    open_ports = []
    if order == "random":
        ports = random.shuffle(ports)
    elif order == "sequential":
        pass
    else:
        raise Exception("Invalid ports selected")
    print("ports: ", ports)
    for i in ports:
        print(i)
        resp = sr1(IP(dst=ip_addr)/TCP(dport=i, flags='F'), timeout=.5, verbose=0)     
        try: 
            print(resp.sprintf('%TCP.src% \t %TCP.sport% \t %TCP.flags%'))
            if resp.getlayer(TCP).flags == 0x12:
                open_ports.append(i)
            sr1(IP(dst=ip_addr)/TCP(dport=i, flags='R'), timeout=.5, verbose=0)   
        except: 
            pass
    print(open_ports)
    return open_ports


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process user options')
    parser.add_argument('-mode')
    parser.add_argument('-order')
    parser.add_argument('-ports')
    parser.add_argument('ip_address')
    args = parser.parse_args()
    mode = args.mode
    order = args.order
    ports = args.ports
    target_ip = args.ip_address
    port_nums = []

    # validate user input
    if (mode != "SYN" and mode != "FIN" and mode != "normal"):
         raise argparse.ArgumentError(mode, "Invalid mode selected!")
    if (ports != "common" and ports != "all"):
         raise argparse.ArgumentError(ports, "Invalid port option selected!")
    if (order != "random" and order != "sequential"):
         raise argparse.ArgumentError(order, "Invalid order selected!")    
    if ports == "common":
        port_nums = common_ports

    print("starting port scan at address {}, scanning {} ports in {} order".format(target_ip, ports, order))
    if mode == "SYN":
       SYN_scan(target_ip, port_nums, order)
       # SYN_scan("131.229.72.13", port_nums, order)
    elif mode == "FIN":
        FIN_scan(target_ip, port_nums, order)


