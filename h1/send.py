from scapy.all import *
import sys
from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def build_normal_ipv4_packet(src, dst, dscp=0, payload="HELLO"):
    

    """
    Build a plain Ethernet → IPv4 → payload packet.
    The P4 program will add the tunnel header if the (src, dst, dscp) match.
    
    NOTE: DSCP in IPv4 = upper 6 bits of TOS → shift left by 2
    """
    ip_tos = dscp << 2
    iface = get_if()
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src, dst=dst, tos=ip_tos) /
        Raw(load=payload)
    )
    return pkt


if __name__ == "__main__":
    # Example packet expected to be encapsulated by the P4 program
    
    src_ip = "10.0.0.1"
    dst_ip = "10.0.0.2"
    #count = int(sys.argv[2]) if len(sys.argv) > 3 else 1
    #payload = sys.argv[3] if len(sys.argv) > 2 else "TriggerTunnel"
    count = 100
    payload = "HELLO"

    pkt = build_normal_ipv4_packet(
        src=src_ip,
        dst=dst_ip,
        dscp=8,
        payload=payload
    )

    print("\n=== Packet sent without tunnel ===")
    pkt.show2()
        
    try:
        for i in range(0, count):
            print(f"\n=== Sending packet {i+1}/{count} ===")
            sendp(pkt, iface="eth0")
            sleep(1)
    except KeyboardInterrupt:
        print("\nUser interrupted execution.")
    print("\nDone sending packets.")
