
# Spoofing Project

This project implements ARP spoofing, DNS spoofing, and a simple web server using Flask. It is designed to demonstrate the potential security vulnerabilities in local networks.

## Features

- ARP Spoofing
- DNS Spoofing
- Redirecting users to a specified URL using a web server

## Requirements

Before you begin, ensure you have met the following requirements:

- Python 3.x
- Scapy
- Flask

You can install the required packages using pip or requirements.txt:

```bash
pip install scapy flask
```

## Code Structure

The project contains the following main components:

- `arp_spoof.py`: Contains the `ARPSpoofer` class for ARP spoofing functionality.
- `dns_spoof.py`: Contains the `DNSSpoofer` class for DNS spoofing functionality.
- `web_server.py`: Contains the `WEBServer` class for the web server that handles redirection.
- `main.py`: The entry point of the application, which initializes the spoofers and starts them using multi-threading.

## How to Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/spoofing-project.git
   cd spoofing-project
   ```

2. **Configure the parameters in `main.py`:**
   - Update the `victim_ip`, `router_ip`, `attacker_ip`, `attacker_mac`, and `redirect_to` variables with appropriate values.

3. **Run the application:**
   ```bash
   python main.py
   ```

4. **Stop the attack:**
   - To stop the spoofing attack, press `Ctrl + C` in the terminal.

## Important Notes

- This project is for educational purposes only. Ensure you have permission to test on the network you are working with.
- Misuse of this code can lead to legal consequences.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
