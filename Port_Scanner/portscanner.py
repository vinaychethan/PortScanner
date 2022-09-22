#!/bin/python3
import re
from scapy.all import *
try:
    host = input("Enter a host adress: ")
    p = list(input("Enter the ports to scan: ").split(","))
    temp = map(int,p)
    ports = list(temp)
    if(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",host)):
        print("\n\nscanning...")
        print("Host: ", host)
        print("Ports: ",ports)
        ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="5"),verbose=0,timeout=2)    
        for (s,r) in ans:
            print("[+] {} open".format(s[TCP].dport))
except (ValueError, RuntimeError, TypeError, NameError):
    print("[-] Some Error Occured")
    print("[-] Exiting..")