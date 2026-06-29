from scapy.all import sniff
from parser import parse_packet
from analyzer import analyze
from detector import detect
from logger import save_log

def process(packet):
    data = parse_packet(packet)
    if data:
        save_log(data)
        analyze(data)
        ip = data["source_ip"]
        count = packet_counter.get(ip, 0)
        detect(ip, count)

print("Monitoring started...")
sniff(prn=process, count=20)