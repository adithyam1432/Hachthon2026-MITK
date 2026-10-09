# 🛡️ Data Link Layer (OSI Layer 2) Security Architecture

> **Enterprise Defense-in-Depth Specification for PII Firewall**  
> *Securing the AI Agent Data Plane from Ethernet Frames (L2) to Semantic Tokens (L7)*

---

## 1. Why Data Link Layer (Layer 2) Security Matters for AI Agents

While our PII Firewall operates primarily at **Layer 7 (Application Layer)** inspecting JSON and natural language prompts, in production enterprise environments (such as **Commvault Backup & Recovery appliances, Kubernetes clusters, and multi-tenant cloud VPCs**), AI agents and tools communicate across **Layer 2 (Ethernet switches, virtual bridges, and MAC frames)**.

### The Threat Model at Layer 2:
1. **ARP Cache Poisoning / Spoofing (MITM):** A compromised container on the same subnet broadcasts malicious ARP replies to reroute tool requests through an attacker before reaching the PII Firewall.
2. **Promiscuous Sniffing on Virtual Bridges:** On container hosts (`docker0`, `cbr0`), an unprivileged pod set to promiscuous mode can capture unencrypted traffic passing across the virtual switch.
3. **MAC Flooding & CAM Table Exhaustion:** Flooding switches with fake MAC addresses to force the switch into "fail-open" hub mode, broadcasting all agent frames to all ports.
4. **VLAN Hopping (Double Tagging):** An attacker injects 802.1Q tags to cross from an untrusted tool network into the trusted AI agent control network.

---

## 2. The 5 Layer 2 Security Pillars for PII Firewall

```
 +-------------------------------------------------------------------------+
 |                      OSI DEFENSE-IN-DEPTH STACK                        |
 +-------------------------------------------------------------------------+
 | Layer 7 (Application)  | PII Firewall: Tokenization, Semantic NLP, Audit |
 | Layer 4 (Transport)    | mTLS 1.3: Cryptographic Mutual Pod Identity     |
 | Layer 3 (Network)      | IPSec / WireGuard: Encrypted IP Routing         |
 | Layer 2 (Data Link)    | MACsec (802.1AE), DAI, VLAN Segregation, eBPF  |
 +-------------------------------------------------------------------------+
```

### Pillar 1: IEEE 802.1AE MACsec (Line-Rate Frame Encryption)
* **What it does:** Encrypts every Ethernet frame (headers and payload) at line rate between the AI Agent host, PII Firewall node, and external tool gateways using **GCM-AES-128 / GCM-AES-256**.
* **Protection:** Defeats physical wiretapping, fiber taps, and rogue switch port sniffing.
* **Replay Protection:** Enforces 32-bit/64-bit Packet Numbers (PN) in the MACsec header; duplicate or out-of-window frames are dropped at the hardware NIC level.

### Pillar 2: 802.1Q VLAN Microsegmentation & Private VLANs (PVLANs)
* **Dual-Homed Network Interface Architecture:**
  * **VLAN 101 (`Agent-Ingress-Trusted`):** Only AI agent pods and the PII Firewall's ingress interface reside here.
  * **VLAN 202 (`Tool-Egress-DMZ`):** Only sanitized, tokenized outgoing payloads are forwarded onto this DMZ segment.
* **Private VLANs (Isolated Ports):** External tools cannot communicate with each other east-west; all traffic must traverse the PII Firewall bridge.

### Pillar 3: Switch Port Security & Anti-Spoofing Defenses
* **Dynamic ARP Inspection (DAI):** The switch intercepts all ARP requests/replies on the subnet and verifies MAC-IP bindings against a trusted DHCP snooping database. Prevents ARP poisoning attacks.
* **DHCP Snooping & IP Source Guard (IPSG):** Rejects rogue DHCP servers and verifies that the MAC address in the frame matches the IP assigned to that agent container.
* **Port Security (MAC Limiting):** Limits each switch virtual interface to a single known MAC address, preventing CAM table exhaustion attacks.

### Pillar 4: Container Bridge & eBPF Socket-Layer Hardening
In Kubernetes (K8s) and Docker environments:
1. **Disable Promiscuous Mode:** Explicitly enforce `promisc=off` on virtual bridge interfaces (`ip link set cbr0 promisc off`) to prevent eavesdropping across pods.
2. **eBPF-Powered Socket Redirection (Cilium/Calico):**
   * Instead of passing packets through standard Linux Layer 2 virtual ethernet (`veth`) pairs, eBPF programs hook directly into socket ops (`sock_ops`), redirecting sanitized payloads at the socket layer.
   * **Result:** Frames never traverse the shared virtual bridge, eliminating Layer 2 packet capture vectors on the host.

### Pillar 5: Hardware MAC Binding in Cryptographic Token Vault
Our firewall's [`TokenVault`](backend/pii_firewall/vault.py) can cryptographically bind generated tokens to the client's Layer 2 MAC address:
$$\text{Token} = \text{HMAC-SHA256}(\text{Raw\_PII} \parallel \text{Request\_Salt} \parallel \text{Client\_MAC})$$
* **Security Guarantee:** Even if an attacker steals a token from the wire, the response re-hydration engine rejects restoration requests originating from a different Layer 2 MAC address.

---

## 3. How to Explain This to Commvault Hackathon Judges

When judges ask: *"How does your architecture handle network-level security and Data Link Layer attacks?"*

> **Winning Answer:**  
> *"We follow an **End-to-End Zero Trust** model spanning Layer 2 to Layer 7:*  
> 1. *At **Layer 7**, our PII Firewall tokenizes data so external services only receive surrogate tokens.*  
> 2. *At **Layer 2 (Data Link)**, we enforce **IEEE 802.1AE MACsec** for hardware-encrypted Ethernet frames, **Dynamic ARP Inspection (DAI)** to prevent Man-in-the-Middle spoofing, and **VLAN microsegmentation** isolating trusted agents from untrusted tool DMZs.*  
> 3. *In Kubernetes, we leverage **eBPF socket redirection** to bypass shared virtual bridges entirely, preventing adjacent container sniffing.*  
> 4. *This creates true defense-in-depth: even if a physical wiretap intercepts Layer 2 frames, our Layer 7 tokenization guarantees zero cleartext PII leakage."*
