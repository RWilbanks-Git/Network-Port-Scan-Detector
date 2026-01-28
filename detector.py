import dpkt
import sys
import os
import argparse
import socket

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", dest="filename", required=True)
    args = parser.parse_args()

    # Using Lists to collect packets (matching your original style)
    synList = []
    synackList = []
    ackList = []
    rstList = [] # Added to distinguish Half-Open scans accurately

    # Using Sets for totals to ensure we count unique (target, port) pairs
    nullTotal = set()
    christmas = set()
    udpTotal = set()
    connect = set()
    halfOpen = set()

    # Flag definitions
    TH_FIN = dpkt.tcp.TH_FIN
    TH_SYN = dpkt.tcp.TH_SYN
    TH_RST = dpkt.tcp.TH_RST
    TH_PUSH = dpkt.tcp.TH_PUSH
    TH_ACK = dpkt.tcp.TH_ACK
    TH_URG = dpkt.tcp.TH_URG

    f = open(args.filename, "rb")
    pcap = dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
        srcIp = socket.inet_ntoa(ip.src)
        dstIp = socket.inet_ntoa(ip.dst)

        # Improved UDP Logic: Filter out common noise (DNS, DHCP, NTP)
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            # Only count as a scan if it's not a common service port
            if udp.dport not in [53, 67, 68, 123]:
                udpTotal.add((dstIp, udp.dport))
            continue

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            flags = tcp.flags

            # Null Scan logic
            if flags == 0:
                nullTotal.add((dstIp, tcp.dport))

            # Christmas Scan logic
            if flags == (TH_FIN | TH_PUSH | TH_URG):
                christmas.add((dstIp, tcp.dport))

            # Collecting Handshake packets
            if (flags & TH_SYN) and not (flags & TH_ACK):
                synList.append((srcIp, dstIp, tcp.dport))

            if (flags & TH_SYN) and (flags & TH_ACK):
                synackList.append((srcIp, dstIp, tcp.sport))

            if (flags & TH_ACK) and not (flags & TH_SYN):
                ackList.append((srcIp, dstIp, tcp.dport))
            
            if (flags & TH_RST):
                rstList.append((srcIp, dstIp, tcp.dport))

    f.close()

    # Matching logic to distinguish Connect vs Half-Open
    for (scanner, target, port) in synList:
        
        # Did the target respond with a SYN-ACK?
        hasSynack = any(saSrc == target and saDst == scanner and saPort == port 
                        for (saSrc, saDst, saPort) in synackList)

        if not hasSynack:
            continue

        # Did the scanner send an ACK to complete the handshake? (Connect Scan)
        hasAck = any(aSrc == scanner and aDst == target and aPort == port 
                     for (aSrc, aDst, aPort) in ackList)
        
        # Did the scanner send a RST to abort the handshake? (Half-Open Scan)
        hasRst = any(rSrc == scanner and rDst == target and rPort == port 
                     for (rSrc, rDst, rPort) in rstList)

        if hasAck:
            connect.add((target, port))
        elif hasRst:
            halfOpen.add((target, port))

    print(f"Null: {len(nullTotal)}")
    print(f"XMAS: {len(christmas)}")
    print(f"UDP: {len(udpTotal)}")
    print(f"Half-open: {len(halfOpen)}")
    print(f"Connect: {len(connect)}")

if __name__ == "__main__":
    main()
