#---Versiyon 1.0

#FİLTRELEME ARGUMENTS I ALMAYI UNUTMA
#Arguments 
#1- IP Range
#2- Gateway IP
#3- Filter Mode (for 10.0.2.2) - Default = x.y.z.2 - ÜZERİNDE ÇALIŞILACAK
#4- Summary Mode - Default = True

from scapy.all import Ether, ARP, srp, send, ls
import argparse

class Attacker():
    def __init__(self, mac:str, ip:str, ip_type:str, hw_type:str, op: str) -> None:
        self.mac = mac
        self.ip = ip
        self.ip_type = ip_type
        self.hw_type = hw_type
        self.op = op
    
    def __str__(self) -> str:
        return f"Attacker Object - IP: {self.ip} / MAC: {self.mac}"
    
    def reverse_attack():
        pass

def get_arguments(warning:bool = False) -> dict:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-r", "--range", "--iprange", dest="ip_range", help="Indicate an IP range. - default: 10.0.2.1/24")
    arg_parser.add_argument("-g", "--gateway", "--gatewayip", dest="gateway_ip", help="Indicate your Gateway IP. - default: 10.0.2.1")
    arg_parser.add_argument("-f", "--filter", dest="filter_ip", help="IPs that are pointed as safe -which will not be considered as an attacker. - default: 10.0.2.2")
    arg_parser.add_argument("-s", "--summary", "--show", dest="boolean", help="Switches on/off summary (detailed info) mode. - default: True")
    result = arg_parser.parse_args()
    if not result.ip_range:
        result.ip_range = "10.0.2.1/24"
        if warning: print(f"[!] warning: IP range has been set to {result.ip_range} as default!")
    if not result.gateway_ip:
        result.gateway_ip = "10.0.2.1"
        if warning: print(f"[!] warning: Gateway IP has been set to {result.gateway_ip} as default!")
    if not result.filter_ip:
        result.filter_ip = "10.0.2.1"
    if not result.boolean:
        result.boolean = True
    return result

def scan_network(ip_range:str) -> dict:
    ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=1, verbose = False)[0]
    net_dict = {}
    for res in ans:
        mac = res[1].hwsrc
        ip = res[1].psrc
        if mac in net_dict.keys():
            net_dict[mac] = str(net_dict[mac] + "," + ip)
        else:
            net_dict[mac] = ip
    return net_dict

def get_gateway_mac(gateway_ip:str) -> str:
    ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip), timeout=1, verbose = False)[0]
    return ans[0][1].hwsrc

def reveal_attacker(modem_ips:list, filter_ip:str) -> Attacker:
    for ip in filter(lambda ip: ip != filter_ip, modem_ips):
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=1, verbose = False)[0][0][1]
        attacker = Attacker(ans.hwsrc, ans.psrc, ans.plen, ans.hwlen, ans.op)
    return attacker

def summary(attacker: Attacker, summary_mode:bool) -> str:
    if summary_mode:
        return f"""
  -- New Attacker! --
[!] MITM Protector has pointed an attacker!
[!] Attacker Information
 --> Ip Adress : {attacker.ip} 
 --> Ip Type: {attacker.ip_type} (4: IPV4 / 6: IPV6)
 --> MAC Adress: {attacker.mac}
 --> ARP Type: {attacker.op} (1: Req / 2: Res)
    """
    else:
        return str(attacker)

def initialize() -> None:
    get_arguments(True) #Uyarılar yapıldı.
    print(" -- Kaan MITM Detector/Protector v1.0--")
    ip_range = get_arguments().ip_range
    gateway_ip = get_arguments().gateway_ip
    filter_ip = get_arguments().filter_ip
    summary_mode = get_arguments().boolean
    net_dict = scan_network(ip_range)
    #Modem ile aynı MAC adresini taşıyan IP adresleri modem_ips değişkenindedir.
    modem_ips = str(net_dict[get_gateway_mac(gateway_ip)]).split(",")
    attacker = reveal_attacker(modem_ips, filter_ip)
    print(summary(attacker, summary_mode))

initialize()