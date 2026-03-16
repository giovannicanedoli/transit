#!/usr/bin/env python
from scapy.all import *
import sys
import argparse
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
    """
    Helper function to find the first interface containing 'eth0'.
    """
    ifs = get_if_list()
    iface = None 
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        sys.exit(1)
    return iface

def get_own_ip(iface):
    """
    Get the IP address assigned to the given interface.
    """
    try:
        ip = get_if_addr(iface)
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass
    print(f"Error: Could not determine IP address for interface {iface}")
    sys.exit(1)

def build_normal_ipv4_packet(iface, src, dst, dscp=0, payload="HELLO"):
    """
    Builds an Ethernet -> IP -> Payload packet.
    INJECTS the MRI IP Option.
    """
    ip_tos = dscp << 2
    
    # We create the MRI Option initialized to empty
    mri_option = IPOption_MRI(count=0, swtraces=[])

    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src, dst=dst, tos=ip_tos, options=mri_option) /
        Raw(load=payload)
    )
    return pkt

def main():
    # Get Interface first (needed for auto-detection)
    iface = get_if()
    
    # Auto-detect source IP from interface
    auto_src = get_own_ip(iface)

    # Hardcoded destination: h3 -> h4
    auto_dst = "10.0.0.4"

    # The description here appears at the top of the --help menu
    parser = argparse.ArgumentParser(
        description='Send customized IPv4 packets containing the MRI (Multi-Hop Route Inspection) Option.'
    )
    
    # Arguments
    parser.add_argument('--dst', type=str, default=auto_dst, 
                        help=f'Destination IP address (Default: {auto_dst})')
    parser.add_argument('--count', type=int, default=1, 
                        help='Number of packets to send (Default: 1)')
    parser.add_argument('--dscp', type=int, default=8, 
                        help='DSCP (TOS) value (Default: 8)')
    parser.add_argument('--payload', type=str, default="HELLO", 
                        help='String payload to send inside the packet (Default: "HELLO")')
    parser.add_argument('--interval', type=float, default=1.0, 
                        help='Time in seconds to wait between packets (Default: 1.0)')

    args = parser.parse_args()

    # Validation
    if args.count < 1:
        print("Error: Count must be at least 1.")
        sys.exit(1)

    print(f"Sending {args.count} packet(s) from {auto_src} to {args.dst} on {iface}")

    # Build the packet with MRI
    pkt = build_normal_ipv4_packet(
        iface=iface,
        src=auto_src,
        dst=args.dst,
        dscp=args.dscp,
        payload=args.payload
    )

    print("\n=== Packet Template (with MRI Option) ===")
    pkt.show2()
        
    try:
        for i in range(0, args.count):
            if args.count > 1:
                print(f"Sending packet {i+1}/{args.count}...", end='\r')
            
            sendp(pkt, iface=iface, verbose=False)
            
            if args.count > 1:
                sleep(args.interval)
                
    except KeyboardInterrupt:
        print("\nUser interrupted execution.")
    
    print("\nDone sending packets.")

if __name__ == "__main__":
    main()