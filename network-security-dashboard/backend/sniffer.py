from parser import parse_packet
from scapy.all import sniff

def process(packet):
    
    parse_packet(packet)

sniff(prn=process,count=10)