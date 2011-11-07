##There is NO WARRANTY for this program. 
##Use at your own risk.
##A sniffer adjusted to work with Open-IMS (and any IMS) platform.
##Version 0.2 (2011-10-09)
##Author: Andis Anastasis (andisthejackassatgmaildotcom)
##!!!IMPORTANT!!!
##Make sure to backup your iptables rules before running this script

#!/bin/sh
sudo iptables -F #flush all iptables rules
sudo iptables -P INPUT ACCEPT #accept all input
sudo iptables -P OUTPUT ACCEPT #accept all output
sudo iptables -P FORWARD ACCEPT #accept all forward
sudo iptables -A INPUT -i lo -j ACCEPT #if the interface is "lo" (local) accept it
sudo iptables -A INPUT -p udp --dport 4060 -m string --string "REGISTER" -j ACCEPT --algo bm #if the protocol is udp and the destination port is 4060 and it contains string "REGISTER" accept it,
sudo iptables -A INPUT -p udp --dport 4060 -j DROP #if none of the above is true, and the destination port is 4060, then drop it
