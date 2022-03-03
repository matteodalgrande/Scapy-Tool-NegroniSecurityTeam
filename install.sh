#!/bin/bash
sudo apt update
sudo apt install python3
sudo apt install python3-pip
sudo apt install nmap
# sudo pyhton3 -m pip3 install python-nmap
sudo pyhton3 -m pip3 install python3-nmap
sudo python3 -m pip3 install termcolor
sudo python3 -m pip3 install --pre scapy[basic]
sudo python3 script.py