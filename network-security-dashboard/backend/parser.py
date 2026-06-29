from scapy.layers.inet import IP

def parse_packet(packet):

    if packet.haslayer(IP):

        source = packet[IP].src

        destination = packet[IP].dst

        protocol = packet[IP].proto

        print(source)
        print(destination)
        print(protocol)

        packet_data = {
            "source_ip": source,
            "destination_ip": destination,
            "protocol": protocol
        }

        return packet_data