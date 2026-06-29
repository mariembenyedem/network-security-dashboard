import json

def save_log(data):
    
    with open("logs/network_logs.json","a") as file:
        
        json.dump(data,file)
        
        file.write("\n")