from scapy.all import *
import time


def main():
    """Driver function"""
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == '1':
            print("Creating and sending packets ...")
            # TODO
            send_pkt(10, 1)
        elif option == '2':
            print("Listening to all traffic to 8.8.4.4 for 1 minute ...")
            # TODO
            pkt = sniff(iface='ens4', filter='host 8.8.4.4', prn=print_pkt, timeout = 60)
        elif option == '3':
            print("Listening continuously to only ping commands to 8.8.4.4 ...")
            # TODO
            pkt = sniff(iface='ens4', filter='icmp and host 8.8.4.4', prn=print_pkt)
        elif option == '4':
            print("Listening continuously to only outgoing telnet commands ...")
            # TODO
            pkt = sniff(iface='ens4', filter='tcp and port 23 and src 127.0.0.1', prn=print_pkt)
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


def send_pkt(number, interval):
    """
    Send a custom packet with the following fields

    #### Ethernet layer
    - Source MAC address: 00:11:22:33:44:55
    - Destination MAC address: 55:44:33:22:11:00

    #### IP layer
    - Source address: 192.168.10.4
    - Destination address: 8.8.4.4
    - Protocol: TCP
    - TTL: 26

    #### TCP layer
    - Source port: 23
    - Destination port: 80

    #### Raw payload
    - Payload: "RISC-V Education: https://riscvedu.org/"
    """

    # TODO
    for i in range(number):
        # Define the Ethernet frame
        eth = Ether(src='00:11:22:33:44:55', dst='55:44:33:22:11:00', type=0x0800)

        # Define the IP packet
        ip = IP(src='192.168.10.4', dst='8.8.4.4', proto='tcp', ttl = 26)

        # Define the TCP segment
        tcp = TCP(sport=23, dport=80, chksum=0)

        # Define the payload
        payload = b'RISC-V Education: https://riscvedu.org/'

        # Combine everything into a single packet
        packet = eth/ip/tcp/payload

        # Send the packet
        sendp(packet)

        # Sleep interval seconds before sending next packet
        time.sleep(interval)

    pass


def print_pkt(packet):
    """ 
    Print Packet fields

    - Source IP
    - Destination IP
    - Protocol number
    - TTL
    - Length in bytes
    - Raw payload (if any)
    """

    # TODO
    print("Source IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)
    print("Protocol number:", packet[IP].proto)
    print("TTL:", packet[IP].ttl)
    print("Length in bytes:", len(packet[IP]))
    if (packet[IP].load != b''):
        print("Raw Payload:", packet[IP].load)
    print("\n")
    pass


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('1. Create and send packets')
    print('2. Listen to all traffic to 8.8.4.4 for 1 minute')
    print('3. Listen continuously to only ping commands to 8.8.4.4')
    print('4. Listen continuously to only outgoing telnet commands')
    print('5. Quit')
    print('***********************************************\n')


main()
