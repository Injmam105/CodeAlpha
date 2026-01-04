from scapy.all import sniff, IP, TCP, UDP, Ether, Raw


def analyze_packet(packet):
    print("\n================ PACKET DETAILS ================")

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print("Ethernet Layer:")
        print(f"  Source MAC        : {eth.src}")
        print(f"  Destination MAC   : {eth.dst}")

    # IP Layer
    if packet.haslayer(IP):
        ip = packet[IP]
        print("IP Layer:")
        print(f"  Source IP         : {ip.src}")
        print(f"  Destination IP    : {ip.dst}")
        print(f"  Protocol          : {ip.proto}")

    # TCP Layer
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("TCP Layer:")
        print(f"  Source Port       : {tcp.sport}")
        print(f"  Destination Port  : {tcp.dport}")
        print(f"  Flags             : {tcp.flags}")

    # UDP Layer
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print("UDP Layer:")
        print(f"  Source Port       : {udp.sport}")
        print(f"  Destination Port  : {udp.dport}")

    # Payload
    if packet.haslayer(Raw):
        print("Payload:")
        print(packet[Raw].load)


def main():
    print("===============================================")
    print("     Python Network Packet Analyzer Started    ")
    print("===============================================")
    print("Press CTRL + C to stop capturing packets...\n")

    sniff(prn=analyze_packet, store=False)


if __name__ == "__main__":
    main()
