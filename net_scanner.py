import scapy.all as scapy
import optparse

#1) Creating ARP Request - Öncelikle ARP paketimizi oluşturuyoruz ve bu ARP paketine Ip range tanımlıyoruz
#2) Live Broadcast - Tanımladığımız ARP paketini tüm cihazlara Broadcast etmek ve MAC response alabilmek
# için ff:ff:ff:ff:ff:ff adresi aracılığıyla bir paket daha oluşturuyoruz. 
#3) Combining ARP and Broadcast Packets - Oluşturulan bu iki paketi birleştiriyoruz.
#3) Response - srp methodu aracılığıyla çıktı alıyoruz.

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-r", "--range", "-i", "--iprange", dest="ip_range", help="Enter the IP range you wish to scan.")
    (user_input, arguments) = parse_object.parse_args()
    return user_input.ip_range

def send_receive_packets(ip_range):
    arp_request_packet = scapy.ARP(pdst=ip_range) #ARP paketi oluşturuldu.
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #Broadcast MAC paketi oluşturuldu.
    combined_packet = broadcast_packet/arp_request_packet #Önce Broadcast, sonra ARP paketi yazılır.
    result = scapy.srp(combined_packet, timeout=1) #timeout=1 kwargs ı aracılığıyla unanswered packetleri atlıyoruz.
    (answered_list, unanswered_list) = result
    my_mac_ip = set()
    print("---Network Table---")
    for result in answered_list: 
        my_mac_ip.add(result[1].sprintf("%Ether.dst%"))
        my_mac_ip.add(result[1].sprintf("%ARP.pdst%"))
        target_mac = result[1].sprintf("%Ether.src%") 
        target_ip = result[1].sprintf("%ARP.psrc%")
        print(f"IP Adress: {target_ip} / MAC Adress: {target_mac}")
    (mymac, myip) = my_mac_ip
    print(f"\nYour own IP adress: {myip}\nYour own MAC adress: {mymac}")

send_receive_packets(get_user_input())