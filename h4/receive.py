from scapy.all import *
import sys

print("Listening for packets...")

def handle(pkt):
    print("\n=== Packet received ===")
    sys.stdout.flush()
    pkt.show()

sniff(iface="eth0", prn=handle, store=0)

