packet_counter = {}

def analyze(data):
    ip = data["source_ip"]
    if ip in packet_counter:
        packet_counter[ip] += 1
    else:
        packet_counter[ip] = 1
    print(f"{ip} → {packet_counter[ip]} packets")
    return packet_counter