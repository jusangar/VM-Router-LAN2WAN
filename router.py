#!/usr/bin/python3

import os

# Variables

WAN = "ens33"
Bastion = "ens34"
DevOps = "ens37"

RedBastion = "192.168.10.0/24"
RedDevOps = "192.168.11.0/24"

os.system("iptables -F")
os.system("iptables -X")
os.system("iptables -Z")
os.system("iptables -t nat -F")

os.system("iptables -P INPUT ACCEPT")
os.system("iptables -P OUTPUT ACCEPT")
os.system("iptables -P FORWARD ACCEPT")


os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")

# Enmascaramos LAN y DMZ (para que LAN pueda salir a internet)
os.system(f"iptables -t nat -A POSTROUTING -o {WAN} -s {RedDevOps} -j MASQUERADE")
os.system(f"iptables -t nat -A POSTROUTING -o {WAN} -s {RedBastion} -j MASQUERADE")

# Permitir tráfico de LAN a WAN
os.system(f"iptables -A FORWARD -i {Bastion} -o {WAN} -j ACCEPT")
os.system(f"iptables -t nat -A POSTROUTING -o {WAN} -j MASQUERADE")
os.system(f"iptables -A FORWARD -i {WAN} -o {Bastion} -m state --state ESTABLISHED,RELATED -j ACCEPT")

os.system(f"iptables -A FORWARD -i {DevOps} -o {WAN} -j ACCEPT")
os.system(f"iptables -t nat -A POSTROUTING -o {WAN} -j MASQUERADE")
os.system(f"iptables -A FORWARD -i {WAN} -o {DevOps} -m state --state ESTABLISHED,RELATED -j ACCEPT")

os.system(f"iptables -t nat -A PREROUTING -i {WAN} -p tcp --dport 2222 -j DNAT --to 192.168.10.3:22")  # SSHBastion
os.system(f"iptables -t nat -A PREROUTING -i {WAN} -p tcp --dport 2000 -j DNAT --to 192.168.11.3:22")  # SSHDevOps

os.system(f"iptables -t nat -A PREROUTING -i {WAN} -p tcp --dport 6060 -j DNAT --to 192.168.10.3:8000")  # Apache
os.system(f"iptables -t nat -A PREROUTING -i {WAN} -p tcp --dport 8888 -j DNAT --to 192.168.10.3:80")  # Nginx
