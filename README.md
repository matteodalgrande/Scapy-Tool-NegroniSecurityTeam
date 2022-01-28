# Scapy-Tool-NegroniSecurityTeam

Our Team developed this tool for knowladge purpose.

# Installation

`sudo apt update`

`sudo apt install python3-pip`

`sudo apt install nmap`

`sudo pyhton3 -m pip3 install python-nmap`

`sudo python3 -m pip3 install --pre scapy[basic]`

`sudo python3 script.py`

If you have problem with the scapy tool installation look at the Documentation [here](https://scapy.readthedocs.io/en/latest/installation.html).

# Attacks CLI

**1: SYN Flood**  
    --dstIP  
    --dstPORT  
    --numPCK  
    [--srcIP]  

**2: ICMP Flood**  
    --dstIP  
    --srcIP  
    --numPCK  

**3: UDP Flood**  
    --dstIP  
    --srcIP  
    --dstPORT  
    --numPCK  

**4: OS Discovery**   
    --dstIP  

**5: ARP spoofing**  
    --victimIP  
    [--victimMAC]  
    --spoofedIP  
    [--spoofedMAC]  
    --interface  
    --numPCK  

**6: Drop Communication**  
    --victimIP  
    --srcIP  
    --numPCK 
    --sleep  

**7: ICMP Redirect**  
    --victimIP  
    --serverIP  
    --routerIP  
    --gatewayIP  

**8: TCP Connect Scan**  
    --dstIP  
    --pSCAN  
    [--sleep]  

**9: TCP Stealth Scan** ~ This technique is used to avoid port scanning detection by firewalls.  
    --dstIP  
    --pSCAN  
    [--sleep]  

**10: XMAS Scan**  
    --dstIP  
    --pSCAN  
    [--sleep]  

**11: FIN Scan**  
    --dstIP  
    --pSCAN  
    [--sleep]  

**12: NULL Scan**  
    --dstIP  
    --pSCAN  
    [--sleep]  

**13: TCP ACK FLAG Scan** ~ Statefull Firewall or not?  
    --dstIP  
    --pSCAN  
    [--sleep]  

**14: TCP WINDOW Scan**  
    --dstIP  
    --pSCAN  
    [--sleep]  

**15: UDP Scan**  
    --dstIP  
    --pSCAN  
    [--sleep]  

**16: ARP Scan**      
    --dstIP: An IP address or IP address range to scan. For example:  
        - 192.168.1.1 to scan a single IP address  
        - 192.168.1.1/24 to scan a range of IP addresses.  

**17: ARP spoofing RANDOM IP AND MAC**  
    --victimIP  
    [--victimMAC]  
    --interface  
    --numPCK  

**18: HTTP flooding**  
    --url  
    --numPCK  

**19: SSH reset**  
    --host1  
    --host2   
    --dstPORT  
    --interface  

**20: telnet reset**  
    --host1  
    --host2  
    --dstPORT (23)  
    --interface  

**21: TCP Session Hijacking Reverse Shell**  
    --interface  
    --dstPORT (23 telnet)  

**22: sniffer ICMP exfiltration**  
    --interface  
