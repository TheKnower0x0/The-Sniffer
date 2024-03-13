import scapy.all as net_tools

# Display the banner at the start of the program
print("""               ________            _____       _ ________         
              /_  __/ /_  ___     / ___/____  (_) __/ __/__  _____
               / / / __ \/ _ \    \__ \/ __ \/ / /_/ /_/ _ \/ ___/
              / / / / / /  __/   ___/ / / / / / __/ __/  __/ /    
             /_/ /_/ /_/\___/   /____/_/ /_/_/_/ /_/  \___/_/     
                                                                  
                      _____          ,  ,                           
         |)          () ||)    _    /|_/         _           _  ,_  
         |/\_|  |       ||/\  |/     |\   /|/|  / \_|  |  |_|/ /  | 
          \/  \/|/    (/ |  |/|_/    | \_/ | |_/\_/  \/ \/  |_/   |/
""")

def capture_traffic(net_iface):
    net_tools.sniff(iface=net_iface, store=False, prn=analyze_packet)

def analyze_packet(pkt):
    if pkt.haslayer(net_tools.IP):
        ip_source = pkt[net_tools.IP].src
        ip_destination = pkt[net_tools.IP].dst
        protocol_num = pkt[net_tools.IP].proto

        display_message(f"SRC IP: {ip_source}, DEST IP: {ip_destination}, Protocol: {protocol_num}")

        if pkt.haslayer(net_tools.TCP):
            src_port = pkt[net_tools.TCP].sport
            dest_port = pkt[net_tools.TCP].dport
            display_message(f"TCP SRC Port: {src_port}, TCP DEST Port: {dest_port}")

        elif pkt.haslayer(net_tools.UDP):
            src_port = pkt[net_tools.UDP].sport
            dest_port = pkt[net_tools.UDP].dport
            display_message(f"UDP SRC Port: {src_port}, UDP DEST Port: {dest_port}")

        display_message("\n")

def display_message(msg):
    print(msg)

# Interface to monitor - change as needed (e.g., "eth0", "wlan0")
monitor_iface = "ens33"

# Initiate packet capture
capture_traffic(monitor_iface)
