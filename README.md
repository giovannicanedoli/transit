# Transit — P4 Multi-Hop Route Inspection (MRI)

A **Kathara-based P4 networking lab** that implements **Multi-Hop Route Inspection (MRI)** with tunnel-based forwarding and cryptographic-style path validation. Each switch along the path stamps its identity into the packet; the final switch verifies the accumulated proof before delivering the packet to the destination host.

---

## Table of Contents

- [Overview](#overview)
- [Network Topology](#network-topology)
- [Enforced Paths](#enforced-paths)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Configuration Details](#configuration-details)

---

## Overview

The goal of this project is to perform **tunnel based forwarding** in a Kathara Network using the **P4 language**. Packets are encapsulated in a custom tunnel at the ingress switch, forwarded along a predetermined path, and decapsulated at the egress switch — but only if the accumulated switch-ID sum matches the expected threshold for that tunnel. Hence a **proof of transit** mechanism is being implemented. If a packet deviates from the intended path, it is **dropped**.

### Key Features

- **Tunnel-based forwarding** — packets are assigned a tunnel ID at ingress and forwarded based on it at every hop
- **MRI validation stack** — each transit switch pushes its ID and queue depth onto an in-packet stack
- **Path verification via threshold** — the egress switch sums the switch IDs and compares against a per-tunnel expected value

---

## Network Topology

The lab consists of **4 hosts** and **6 P4 switches** interconnected via collision domains.

![Network Topology](transit.pdf)

### Hosts

| Host | IP Address     | MAC Address         | Connected To |
|------|---------------|---------------------|-------------|
| h1   | `10.0.0.1/24` | `00:01:02:03:04:11` | s1 port 1   |
| h2   | `10.0.0.2/24` | `00:01:02:03:04:22` | s6 port 3   |
| h3   | `10.0.0.3/24` | `00:01:02:03:06:22` | s1 port 4   |
| h4   | `10.0.0.4/24` | `00:01:02:03:06:11` | s6 port 4   |

### Switch Port Mapping

| Switch | Port 1 (eth0) | Port 2 (eth1) | Port 3 (eth2) | Port 4 (eth3) | swid |
|--------|---------------|---------------|---------------|---------------|------|
| s1     | A → h1        | B → s2        | C → s3        | M → h3        | 1    |
| s2     | B → s1        | D → s4        | F → s3        | H → s5        | 2    |
| s3     | F → s2        | C → s1        | I → s4        | E → s5        | 3    |
| s4     | D → s2        | I → s3        | G → s5        | J → s6        | 4    |
| s5     | G → s4        | H → s2        | E → s3        | K → s6        | 5    |
| s6     | J → s4        | K → s5        | L → h2        | N → h4        | 6    |

---

## Enforced Paths

Only **two flows** are permitted in the network. Any other src/dst combination or any deviation from these paths results in the packet being **dropped**.

### Path 1 — h1 → h2 (Tunnel ID: 10)

```
h1 ──▶ s1 ──▶ s2 ──▶ s4 ──▶ s6 ──▶ h2
       (1)    (2)    (4)    (6)
```

| Hop | Switch | In Port | Out Port | Link        |
|-----|--------|---------|----------|-------------|
| 1   | s1     | 1 (A)   | 2 (B)   | B → s2      |
| 2   | s2     | 1 (B)   | 2 (D)   | D → s4      |
| 3   | s4     | 1 (D)   | 4 (J)   | J → s6      |
| 4   | s6     | 1 (J)   | 3 (L)   | L → h2      |

- **swid sum**: 1 + 2 + 4 + 6 = **13**
- **Threshold**: 13

### Path 2 — h3 → h4 (Tunnel ID: 40)

```
h3 ──▶ s1 ──▶ s3 ──▶ s5 ──▶ s6 ──▶ h4
       (1)    (3)    (5)    (6)
```

| Hop | Switch | In Port | Out Port | Link        |
|-----|--------|---------|----------|-------------|
| 1   | s1     | 4 (M)   | 3 (C)   | C → s3      |
| 2   | s3     | 2 (C)   | 4 (E)   | E → s5      |
| 3   | s5     | 3 (E)   | 4 (K)   | K → s6      |
| 4   | s6     | 2 (K)   | 4 (N)   | N → h4      |

- **swid sum**: 1 + 3 + 5 + 6 = **15**
- **Threshold**: 15

---

## How It Works

### 1. Packet Injection (Host → Ingress Switch)

The sender (`send.py`) crafts an IPv4 packet with a custom **MRI IP Option** (option number 31) and an empty validation stack. The DSCP field is set to 8 (TOS `0x20`).

### 2. Tunnel Encapsulation (s1 — Ingress)

Switch s1 matches the packet's `(srcAddr, dstAddr, diffserv)` in the `ipv4_tunnel_forward` table. If a match is found, it:
- Inserts a **myTunnel header** with the assigned `tunnel_id`
- Sets the IP protocol to `0x88` (custom tunnel protocol)
- Forwards the packet to the next hop

### 3. Transit Forwarding (s2/s3/s4/s5)

Each intermediate switch:
1. **Ingress**: Looks up `tunnel_id` in `intermediate_tables` → forwards to the correct egress port
2. **Egress**: Stamps its **swid** and current **queue depth** onto the MRI validation stack, increments `mri.count` by its swid

### 4. Decapsulation & Validation (s6 — Egress)

The final switch s6:
1. **Ingress**: Matches `tunnel_id` → calls `tunnel_decapsulate` action (sets `meta.decapsulate = 1`)
2. **Egress**:
   - Adds its own swid to `mri.count`
   - Loads the **per-tunnel threshold** from the `load_threshold` table
   - Compares `mri.count ≤ threshold`:
     - ✅ **Pass** → packet is delivered to the host
     - ❌ **Fail** → packet is **dropped**

### Packet Header Stack

```
┌──────────┬──────┬─────────────────┬─────────────────────────┬──────────┬───────────────────────┬─────────┐
│ Ethernet │ IPv4 │ IPv4Option(MRI) │ myTunnel(proto,tunnel)  │ MRI(cnt) │ Validation[](swid,qd) │ Payload │
└──────────┴──────┴─────────────────┴─────────────────────────┴──────────┴───────────────────────┴─────────┘
```

---

## Project Structure

```
transit/
├── lab.conf                 # Kathara topology definition
├── shared/
│   └── main.p4              # P4 program (compiled by all switches)
│
├── h1/
│   └── send.py              # Sender script (src: auto, dst: 10.0.0.2)
├── h2/
│   └── receive.py           # Packet sniffer
├── h3/
│   └── send.py              # Sender script (src: auto, dst: 10.0.0.4)
├── h4/
│   └── receive.py           # Packet sniffer
│
├── h1.startup               # h1 network config (IP, MAC, ARP)
├── h2.startup               # h2 network config
├── h3.startup               # h3 network config
├── h4.startup               # h4 network config
│
├── s1/commands.txt           # Ingress rules + transit forwarding
├── s2/commands.txt           # Transit: tunnel 10 only
├── s3/commands.txt           # Transit: tunnel 40 only
├── s4/commands.txt           # Transit: tunnel 10 only
├── s5/commands.txt           # Transit: tunnel 40 only
├── s6/commands.txt           # Decapsulation + per-tunnel thresholds
│
├── s1.startup … s6.startup   # Switch startup (compile P4, start BMv2, load rules)
└── README.md                 # This file
```

---

## Getting Started

### Prerequisites

- [Kathara](https://www.kathara.org/) installed and configured
- Docker with the following images:
  - `kathara/base` (for hosts)
  - `kathara/p4` (for P4 switches — includes `p4c`, `simple_switch`, `simple_switch_CLI`)

### Launch the Lab

```bash
cd /home/gio/Desktop/transit
kathara lstart
```

This will:
1. Start all 10 containers (4 hosts + 6 switches)
2. Configure host networking (IPs, MACs, ARP entries)
3. Compile `main.p4` on each switch
4. Start `simple_switch` (BMv2) with the correct port mappings
5. Load forwarding rules from each switch's `commands.txt`

### Stop the Lab

```bash
kathara lclean
```

---

## Usage

### Sending Packets (h1 → h2)

Open a terminal on **h2** and start the receiver:
```bash
python receive.py
```

Open a terminal on **h1** and send packets:
```bash
# Send a single packet (defaults: src=auto, dst=10.0.0.2, dscp=8)
python send.py

# Send 5 packets with a custom payload
python send.py --count 5 --payload "Hello from h1!"

# Override destination
python send.py --dst 10.0.0.4

# All options
python send.py --dst 10.0.0.2 --count 10 --dscp 8 --payload "TEST" --interval 0.5
```

### Sending Packets (h3 → h4)

Open a terminal on **h4** and start the receiver:
```bash
python receive.py
```

Open a terminal on **h3** and send:
```bash
python send.py
```

### CLI Arguments for send.py

| Argument     | Default        | Description                              |
|-------------|----------------|------------------------------------------|
| `--dst`     | `10.0.0.2` (h1) / `10.0.0.4` (h3) | Destination IP address |
| `--count`   | `1`            | Number of packets to send                |
| `--dscp`    | `8`            | DSCP value (TOS = dscp << 2)             |
| `--payload` | `"HELLO"`      | String payload inside the packet         |
| `--interval`| `1.0`          | Seconds between packets (when count > 1) |

---

## Configuration Details

### Protocol Constants

| Constant          | Value  | Description                        |
|-------------------|--------|------------------------------------|
| `TYPE_IPV4`       | `0x800`| EtherType for IPv4                 |
| `PROTO_MYTUNNEL`  | `0x88` | Custom IP protocol for tunnel      |
| `IPV4_OPTION_MRI` | `31`   | Custom IP option number for MRI    |
| `MAX_HOPS`        | `6`    | Maximum validation stack entries   |

### DSCP Matching

The ingress table (`ipv4_tunnel_forward`) matches on `diffserv = 0x20`, which corresponds to **DSCP 8** (TOS = 8 << 2 = 32 = `0x20`). Packets with a different DSCP value will **not** match any rule and will be dropped.

### Per-Tunnel Thresholds (s6)

The `load_threshold` table at s6 is keyed on `tunnel_id`:

| Tunnel ID | Expected swid Sum | Path                      |
|-----------|-------------------|---------------------------|
| 10        | 13                | s1(1) + s2(2) + s4(4) + s6(6) |
| 40        | 15                | s1(1) + s3(3) + s5(5) + s6(6) |

### Switch Logs

Each switch writes logs to `/shared/sX.log.txt`. These are useful for debugging forwarding decisions, MRI updates, and threshold checks:
