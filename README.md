## Introduction
A port scanning tool built as a final project for CS251 Network Security by Lucy Groves and Kathleen 
Hablutzel.

## Requirements
This tool uses the following python3 modules:
* scapy
* socket
* random
* argparse
* time
* datetime

## To run:

This tool runs from the command line with the following flags:
* -mode [normal/SYN/FIN] 
    - normal: the port scanner attempts to connect with a port via a complete TCP handshake
    -  SYN: the port scanner sends a SYN packet to a port, then waits for an ACK response indicating an open port
    -  FIN: the port scanner sends a FIN packet to a port, then waits for an RST response indicating a *closed* port
* -order [sequential/random] 
    - sequential: scans ports in order
    - random: scans ports in random order
* -ports [all/known/short]
    - all: scans all 2<sup>16</sup> TCP ports
    - known: scans 16 well known ports
    - short: scans the first 2<sup>7</sup> ports (demonstrates the tool's functionality in significantly less time than scanning 2<sup>16</sup> ports)
* -ip_address: the address of the target host

Example: To SYN scan all 2<sup>16</sup> ports at the host with IP address 12.34.56.78.9 sequentially run the following:

port_scanner.py -mode SYN -ports all -order sequential -ip_address "12.34.56.78.9"

