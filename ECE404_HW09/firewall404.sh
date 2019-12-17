# !/bin/sh

#FLUSH OUT EVERYTHING
sudo iptables -F
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat    -F
sudo iptables -t nat    -X
sudo iptables -t raw    -F
sudo iptables -t raw    -X

#Masqurade all outgoing packets as mine
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

#Block a specific number of IP adresses
sudo iptables -A INPUT -s 255.146.102.62 -j DROP
sudo iptables -A INPUT -s 47.13.18.178 -j DROP

#Block all ping from other hosts
sudo iptables -A INPUT  -p icmp --icmp-type echo-request -j DROP

#Port forward to 22
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to 128.210.106.81:22
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 22 -j ACCEPT

#Allow ssh onto port 22 from only ecn domain
iptables -A INPUT -s ecn.purdue.edu -p tcp --dport 22 -j ACCEPT

#Allow Auth/Ident on port 113 for SMTP and IRC services
tcp_services="22,113"
icmp_types="ping"

sudo iptables -A INPUT -m state --state=ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -i eth0 -p tcp --dport 113 --syn -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type ping -j ACCEPT
