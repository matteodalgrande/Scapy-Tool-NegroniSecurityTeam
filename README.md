# Scapy-Tool-NegroniSecurityTeam

1: SYN Flood
    --dstIP
    --dstPORT
    --numPCK \n
    [--srcIP]
2: ICMP Flood
    --dstIP
    --srcIP
    --numPCK \n
3: UDP Flood
    --dstIP
    --srcIP
    --dstPORT
    --numPCK \n
4: OS Discovery 
    --dstIP \n
5: ARP spoofing 
    --victimIP
    [--victimMAC]
    --spoofedIP
    [--spoofedMAC]
    --interface
    --numPCK \n
6: Drop Communication
    --victimIP
    --srcIP
    --numPCK 
    --sleep \n
7: ICMP Redirect 
    --victimIP
    --serverIP
    --routerIP
    --gatewayIP \n
8: TCP Connect Scan
    --dstIP
    --pSCAN 
    [--sleep] \n
9: TCP Stealth Scan ~ This technique is used to avoid port scanning detection by firewalls.
    --dstIP
    --pSCAN
    [--sleep] \n
10: XMAS Scan
    --dstIP
    --pSCAN
    [--sleep] \n
11: FIN Scan
    --dstIP
    --pSCAN
    [--sleep] \n
12: NULL Scan
    --dstIP
    --pSCAN
    [--sleep] \n
13: TCP ACK FLAG Scan ~ Statefull Firewall or not?
    --dstIP
    --pSCAN
    [--sleep] \n
14: TCP WINDOW Scan
    --dstIP
    --pSCAN
    [--sleep] \n
15: UDP Scan
    --dstIP
    --pSCAN
    [--sleep] \n
16: ARP Scan    
    --dstIP: An IP address or IP address range to scan. For example:
        - 192.168.1.1 to scan a single IP address
        - 192.168.1.1/24 to scan a range of IP addresses. \n
17: ARP spoofing RANDOM IP AND MAC
    --victimIP
    [--victimMAC]
    --interface
    --numPCK \n
18: HTTP flooding
    --url 
    --numPCK \n
19: SSH reset
    --host1
    --host2 
    --dstPORT 
    --interface \n
20: telnet reset
    --host1
    --host2 
    --dstPORT (23)
    --interface \n
21: TCP Session Hijacking Reverse Shell
    --interface 
    --dstPORT (23 telnet)\n
22: sniffer ICMP exfiltration
    --interface \n
