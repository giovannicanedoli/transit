from scapy.all import *
import sys
from time import sleep

# --- SCAPY HEADER DEFINITIONS ---
from scapy.layers.inet import _IPOption_HDR

class SwitchTrace(Packet):
    """
    Represents the data added by each switch:
    - 32-bit Switch ID
    - 32-bit Queue Depth
    Total: 8 bytes per hop.
    """
    fields_desc = [ IntField("swid", 0),
                    IntField("qdepth", 0)]
    
    def extract_padding(self, p):
        return "", p

class IPOption_MRI(IPOption):
    """
    The Custom IP Option for MRI (Multi-Hop Route Inspection).
    Option Number: 31
    """
    name = "MRI"
    option = 31
    fields_desc = [ 
        _IPOption_HDR,
        # Length Field: 
        #   4 bytes of fixed header (Type + Len + Count) 
        #   + (Number of Traces * 8 bytes per trace)
        FieldLenField("length", None, fmt="B",
                      length_of="swtraces",
                      adjust=lambda pkt,l:l*8+4), 
        ShortField("count", 0),
        PacketListField("swtraces",
                       [],
                       SwitchTrace,
                       count_from=lambda pkt:(pkt.count)) 
    ]
# -------------------------------

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
    Builds an Ethernet -> IP -> Payload packet.
    INJECTS the MRI IP Option.
    """
    ip_tos = dscp << 2
    iface = get_if()
    
    # We create the MRI Option initialized to empty
    mri_option = IPOption_MRI(count=0, swtraces=[])

    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src, dst=dst, tos=ip_tos, options=mri_option) /
        Raw(load=payload)
    )
    return pkt


if __name__ == "__main__":
    
    src_ip = "10.0.0.1"
    dst_ip = "10.0.0.2"
    count = 1
    payload = "HELLO"

    # Build the packet with MRI
    pkt = build_normal_ipv4_packet(
        src=src_ip,
        dst=dst_ip,
        dscp=8,
        payload=payload
    )

    print("\n=== Packet sent with MRI Option (No UDP) ===")
    # show2() forces calculation of checksums and lengths so we can see the MRI structure
    pkt.show2()
        
    try:
        for i in range(0, count):
            # print(f"Sending packet {i+1}/{count}...")
            sendp(pkt, iface="eth0", verbose=False)
            sleep(1)
    except KeyboardInterrupt:
        print("\nUser interrupted execution.")
    print("\nDone sending packets.")