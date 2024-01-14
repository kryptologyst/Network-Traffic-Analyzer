# Network-Traffic-Analyzer

Network Traffic Analyzer


**Description**

This Python script serves as a basic Network Traffic Analyzer using the scapy library. It captures and displays information about IP packets, including details about TCP, UDP, and ICMP protocols.


**Features**

Captures and analyzes IP packets.
Identifies source and destination IP addresses.
Provides information about TCP, UDP, and ICMP packets.


**Prerequisites**

Python 3.x
scapy library (pip install scapy)


**Usage**

Clone the repository:

    git clone https://github.com/kryptologyst/network-traffic-analyzer.git

Navigate to the project directory:

    cd network-traffic-analyzer

Run the script with the desired network interface:

    python network_traffic_analyzer.py -i your_network_interface
    
Replace your_network_interface with the appropriate interface for your system (e.g., "eth0" or "wlan0").


**Example**

    [+] New Packet: 192.168.1.2 to 8.8.8.8, Protocol: 6
        TCP Source Port: 12345, TCP Destination Port: 80
    
    [+] New Packet: 8.8.8.8 to 192.168.1.2, Protocol: 6
        TCP Source Port: 80, TCP Destination Port: 12345
    
    [+] New Packet: 192.168.1.2 to 8.8.8.8, Protocol: 1
        ICMP Type: 8, ICMP Code: 0

    
License

This project is licensed under the MIT License - see the LICENSE file for details.


Contributing

Contributions are welcome! Please read the CONTRIBUTING guidelines before submitting a pull request.


Acknowledgments

Special thanks to the scapy developers for providing a powerful packet manipulation library.
Disclaimer

This tool is provided for educational and informational purposes only. Use responsibly and ensure compliance with all applicable laws and regulations.
