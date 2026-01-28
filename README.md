# Network-Port-Scan-Detector

## Overview and Scan Types 
This is a script that uses Python and the “dpkt” library to identify potentially malicious scanning patterns.. Port scanning is often the first step an attacker takes to find open "doors" into a network; this tool automates the process of finding said attempts in a large amount of data. 

Scan Types included are:

1.) Null Scan - Checking for packets with no flags set

2.) Xmas Scan - Detects "Christmas Tree" packets (FIN, PUSH, and URG flags set)

3.) Half-Open Scan - Identifies SYN scans where the connection is intentionally reset before finishing

4.) Connect Scan - Finds full three-way handshakes that were successfully completed

5.) UDP Scan - Detects connectionless probes while filtering out common network "noise"

## Instructions 
Install the dpkt library using "pip install dpkt"
Run in terminal using: "python detector.py -i fileName.pcap" (with "fileName.pcap" being the name of the .pcap file in question)
