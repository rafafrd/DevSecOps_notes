# Redes - Fundamentos para DevSecOps e Cybersecurity

**Tags:** #networking #ccna #tcp-ip #routing #switching #network-security #devsecops #infraestrutura
**Relacionado:** [[Linux]], [[Cloud-Security]], [[Firewall]], [[VPN]], [[DevSecOps]]

---

## 📋 Índice

1. [Fundamentos de Rede](#fundamentos-de-rede)
2. [Acesso à Rede](#acesso-à-rede)
3. [Conectividade IP](#conectividade-ip)
4. [Serviços IP](#serviços-ip)
5. [Fundamentos de Segurança](#fundamentos-de-segurança)
6. [Automação e Programabilidade](#automação-e-programabilidade)
7. [Troubleshooting e Ferramentas](#troubleshooting-e-ferramentas)

---

## 🌐 Fundamentos de Rede

### Modelo OSI (Open Systems Interconnection)

**Definição:** Framework conceitual de **7 camadas** que padroniza funções de comunicação em redes.

| **Camada**                         | **Detalhes**                                                                                                                                                                |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **7. Application (Aplicação)**     | - Protocolos: HTTP, HTTPS, FTP, SSH, DNS, SMTP<br><br> <br><br>- Interface com usuário<br><br> <br><br>- Segurança: WAF, DLP, Email Gateway                                 |
| **6. Presentation (Apresentação)** | - Criptografia/Descriptografia<br><br> <br><br>- Compressão de dados<br><br> <br><br>- Formatos: ASCII, JPEG, MPEG                                                          |
| **5. Session (Sessão)**            | - Estabelecimento/Encerramento de sessões<br><br> <br><br>- Sincronização<br><br> <br><br>- Protocolos: NetBIOS, RPC                                                        |
| **4. Transport (Transporte)**      | - Protocolos: TCP, UDP<br><br> <br><br>- Portas (0-65535)<br><br> <br><br>- Segmentação e Reassembly<br><br> <br><br>- Segurança: Firewall Stateful                         |
| **3. Network (Rede)**              | - Protocolos: IP, ICMP, OSPF, BGP<br><br> <br><br>- Roteamento (path selection)<br><br> <br><br>- Endereçamento lógico (IP)<br><br> <br><br>- Segurança: Firewall, ACL, IPS |
| **2. Data Link (Enlace de Dados)** | - Protocolos: Ethernet, Wi-Fi (802.11)<br><br> <br><br>- MAC Address<br><br> <br><br>- Switching<br><br> <br><br>- Segurança: Port Security, DAI, DHCP Snooping             |
| **1. Physical (Física)**           | - Cabos: UTP, Fibra<br><br> <br><br>- Sinais elétricos/ópticos<br><br> <br><br>- Hubs, Repeaters<br><br> <br><br>- Segurança: Acesso físico, Cable locks                    |

**Encapsulamento (Data Flow):**

```yaml
Sending (Top-Down):
  Layer 7-5: Data (Application, Presentation, Session)
  Layer 4: Segment (TCP) / Datagram (UDP)
    └─ Adiciona: Source Port, Destination Port, Sequence Number

  Layer 3: Packet
    └─ Adiciona: Source IP, Destination IP, TTL, Protocol

  Layer 2: Frame
    └─ Adiciona: Source MAC, Destination MAC, VLAN tag, FCS

  Layer 1: Bits (electrical/optical signals)

Receiving (Bottom-Up):
  Layer 1: Bits → Frame
  Layer 2: Remove Frame header → Packet
  Layer 3: Remove IP header → Segment
  Layer 4: Remove TCP/UDP header → Data
  Layer 5-7: Deliver to Application
```

**Exemplo Prático (HTTP Request):**

```
User: Acessa https://www.google.com

Layer 7 (Application):
  HTTP GET / HTTP/1.1
  Host: www.google.com

Layer 4 (Transport):
  Source Port: 54321 (random)
  Destination Port: 443 (HTTPS)
  TCP Flags: SYN

Layer 3 (Network):
  Source IP: 192.168.1.100 (seu computador)
  Destination IP: 142.250.185.46 (google.com)
  TTL: 64

Layer 2 (Data Link):
  Source MAC: aa:bb:cc:dd:ee:ff (seu computador)
  Destination MAC: 11:22:33:44:55:66 (gateway/router)

Layer 1 (Physical):
  Electrical signals on cable / Radio waves (Wi-Fi)
```

---

### TCP vs UDP

```yaml
TCP (Transmission Control Protocol):
  Type: Connection-oriented (stateful)
  Reliability: Guaranteed delivery (retransmission)
  Ordering: Sequenced packets
  Flow Control: Yes (window size)
  Congestion Control: Yes
  Overhead: High (20 bytes header + handshake)
  Speed: Slower

  Use Cases:
    - HTTP/HTTPS (web browsing)
    - SSH (remote access)
    - FTP (file transfer)
    - Email (SMTP, IMAP, POP3)

  Header:
    Source Port (16 bits)
    Destination Port (16 bits)
    Sequence Number (32 bits)
    Acknowledgment Number (32 bits)
    Flags: SYN, ACK, FIN, RST, PSH, URG
    Window Size (16 bits)
    Checksum (16 bits)

UDP (User Datagram Protocol):
  Type: Connectionless (stateless)
  Reliability: Best-effort (no retransmission)
  Ordering: No guarantee
  Flow Control: No
  Congestion Control: No
  Overhead: Low (8 bytes header)
  Speed: Faster

  Use Cases:
    - DNS queries
    - DHCP
    - VoIP (SIP, RTP)
    - Video streaming
    - Gaming
    - SNMP
    - NTP

  Header:
    Source Port (16 bits)
    Destination Port (16 bits)
    Length (16 bits)
    Checksum (16 bits)
```

**TCP Three-Way Handshake:**

```
Client                                Server
  │                                      │
  │──────────SYN (SEQ=100)──────────────>│  Step 1: Client initiates
  │                                      │
  │<────SYN-ACK (SEQ=300, ACK=101)────── │  Step 2: Server responds
  │                                      │
  │──────────ACK (ACK=301)──────────────>│  Step 3: Connection established
  │                                      │
  │════════ Data Transfer ═══════════════│  Data exchange
  │                                      │
  │──────────FIN (SEQ=500)──────────────>│  Step 4: Client closes
  │                                      │
  │<─────────ACK (ACK=501)───────────────│  Step 5: Server acknowledges
  │                                      │
  │<─────────FIN (SEQ=800)───────────────│  Step 6: Server closes
  │                                      │
  │──────────ACK (ACK=801)──────────────>│  Step 7: Client acknowledges
  │                                      │
```

**Ataques TCP:**

```yaml
SYN Flood (DoS Attack):
  Attack: 1. Attacker sends thousands of SYN packets
    2. Server responds with SYN-ACK
    3. Attacker never sends final ACK
    4. Server keeps half-open connections in memory
    5. Server runs out of resources → Crash/DoS

  Packet Capture: 10.0.1.100:random → 192.168.1.50:80 [SYN]
    10.0.1.100:random → 192.168.1.50:80 [SYN]
    10.0.1.100:random → 192.168.1.50:80 [SYN]
    ... (thousands per second)

  Defense:
    - SYN Cookies (stateless connection tracking)
    - Rate limiting (max SYN per IP)
    - Firewall rules (drop excessive SYN)
    - Load balancers (proxy connections)

TCP Reset Attack (MitM):
  Attack: 1. Attacker intercepts TCP connection
    2. Sends RST (reset) packet to both parties
    3. Connection terminates abruptly

  Example: Great Firewall of China uses RST injection
    to block forbidden websites

  Defense:
    - Encryption (TLS/SSL)
    - TCP sequence number randomization

ACK Flood:
  Attack: Send ACK packets without established connection
  Impact: Server wastes CPU processing invalid ACKs
  Defense: Stateful firewall (drop ACK without SYN)
```

---

### Portas (Ports)

**Definição:** Números de **16 bits** (0-65535) que identificam **processos/serviços** em um host.

```yaml
Port Ranges:

Well-Known Ports (0-1023):
  - Reserved for system/privileged services
  - Requires root/admin to bind
  - Examples:
    21: FTP (File Transfer Protocol)
    22: SSH (Secure Shell)
    23: Telnet (Unencrypted remote access)
    25: SMTP (Email sending)
    53: DNS (Domain Name System)
    80: HTTP (Web - unencrypted)
    110: POP3 (Email retrieval)
    143: IMAP (Email retrieval)
    443: HTTPS (Web - encrypted)
    3389: RDP (Remote Desktop Protocol - Windows)

Registered Ports (1024-49151):
  - User/application services
  - Examples:
    3306: MySQL
    5432: PostgreSQL
    6379: Redis
    8080: HTTP Alternate (often used for proxies)
    8443: HTTPS Alternate
    9200: Elasticsearch

Dynamic/Private Ports (49152-65535):
  - Ephemeral ports (client-side)
  - Temporary connections
  - Auto-assigned by OS
```

**Port Scanning (Nmap):**

```bash
# TCP SYN Scan (stealth)
$ nmap -sS 192.168.1.1

Starting Nmap 7.94
Nmap scan report for 192.168.1.1
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
3389/tcp closed ms-wbt-server

# Service detection
$ nmap -sV 192.168.1.1

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp  open  http    nginx 1.18.0
443/tcp open  ssl/http nginx 1.18.0

# UDP scan (slow)
$ nmap -sU 192.168.1.1

PORT    STATE         SERVICE
53/udp  open          domain
67/udp  open|filtered dhcps
123/udp open          ntp

# Aggressive scan (OS detection, version, traceroute)
$ nmap -A 192.168.1.1

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
|_ssh-hostkey: 2048 SHA256:abc123... (RSA)
80/tcp open  http    nginx 1.18.0
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0

OS details: Linux 5.15.0-76-generic (Ubuntu 22.04)
```

**Firewall Rules (iptables):**

```bash
# Allow SSH (port 22) only from trusted IP
iptables -A INPUT -p tcp --dport 22 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Allow HTTP/HTTPS from anywhere
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow outbound DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# Drop all other inbound
iptables -A INPUT -j DROP

# List rules
iptables -L -n -v
```

---

### CIDR e Subnetting

**CIDR (Classless Inter-Domain Routing):**

```yaml
Notation: IP/prefix
  192.168.1.0/24
  └─ Network address: 192.168.1.0
  └─ Prefix: /24 (24 bits for network, 8 bits for hosts)

Subnet Mask Conversion:
  /24 = 255.255.255.0
  /16 = 255.255.0.0
  /8  = 255.0.0.0
  /32 = 255.255.255.255 (single host)
  /0  = 0.0.0.0 (entire internet)

Wildcard Mask (inverse of subnet mask):
  Subnet Mask:   255.255.255.0
  Wildcard Mask: 0.0.0.255

  Used in: Cisco ACLs, OSPF
```

**Cálculo de Sub-redes:**

```yaml
Example: 192.168.1.0/24

Binary Breakdown:
  192.168.1.0  = 11000000.10101000.00000001.00000000
  /24          = 11111111.11111111.11111111.00000000
                 └──────────────────────────┘└────────┘
                      Network (fixed)        Host (variable)

Calculations:
  Network Address: 192.168.1.0
  Broadcast Address: 192.168.1.255
  First Usable: 192.168.1.1
  Last Usable: 192.168.1.254
  Total Hosts: 2^8 - 2 = 254 (exclude network & broadcast)

Subnetting /24 into /26 (4 subnets):
  /26 = 255.255.255.192 (2 bits borrowed → 4 subnets)

  Subnet 1: 192.168.1.0/26
    Range: 192.168.1.0 - 192.168.1.63
    Usable: 192.168.1.1 - 192.168.1.62 (62 hosts)

  Subnet 2: 192.168.1.64/26
    Range: 192.168.1.64 - 192.168.1.127
    Usable: 192.168.1.65 - 192.168.1.126

  Subnet 3: 192.168.1.128/26
    Range: 192.168.1.128 - 192.168.1.191

  Subnet 4: 192.168.1.192/26
    Range: 192.168.1.192 - 192.168.1.255
```

**VLSM (Variable Length Subnet Mask):**

```yaml
Scenario: Empresa precisa de:
  - Subnet A: 120 hosts (departamento vendas)
  - Subnet B: 60 hosts (departamento TI)
  - Subnet C: 30 hosts (departamento financeiro)
  - Subnet D: 10 hosts (gerência)

Starting Network: 10.0.0.0/24

Step 1: Subnet A (120 hosts)
  Need: 2^n - 2 >= 120
  2^7 - 2 = 126 hosts → /25

  10.0.0.0/25
  Range: 10.0.0.0 - 10.0.0.127
  Usable: 10.0.0.1 - 10.0.0.126

Step 2: Subnet B (60 hosts)
  Need: 2^6 - 2 = 62 hosts → /26

  10.0.0.128/26
  Range: 10.0.0.128 - 10.0.0.191
  Usable: 10.0.0.129 - 10.0.0.190

Step 3: Subnet C (30 hosts)
  Need: 2^5 - 2 = 30 hosts → /27

  10.0.0.192/27
  Range: 10.0.0.192 - 10.0.0.223
  Usable: 10.0.0.193 - 10.0.0.222

Step 4: Subnet D (10 hosts)
  Need: 2^4 - 2 = 14 hosts → /28

  10.0.0.224/28
  Range: 10.0.0.224 - 10.0.0.239
  Usable: 10.0.0.225 - 10.0.0.238
```

---

### IPv6

**Formato:** 128 bits (vs 32 bits IPv4), escrito em **hexadecimal** (8 grupos de 16 bits).

```yaml
Full IPv6 Address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

Compressed (remove leading zeros): 2001:db8:85a3:0:0:8a2e:370:7334

Double Colon (replace consecutive zeros once): 2001:db8:85a3::8a2e:370:7334

Loopback: ::1 (equivalent to 127.0.0.1 in IPv4)

Unspecified Address:
  :: (equivalent to 0.0.0.0 in IPv4)

Link-Local: fe80::/10
  - Auto-configured on every interface
  - Not routable beyond local link

Global Unicast: 2000::/3
  - Routable on internet
  - Similar to public IPv4

Unique Local (ULA): fc00::/7
  - Private addresses (like 192.168.x.x in IPv4)
  - Not routable on internet
```

**IPv6 Subnetting:**

```yaml
Example: 2001:db8::/32 (ISP allocation)

Split into /48 for customers:
  Customer 1: 2001:db8:0000::/48
  Customer 2: 2001:db8:0001::/48
  Customer 3: 2001:db8:0002::/48

Customer 1 splits /48 into /64 subnets:
  VLAN 10: 2001:db8:0000:0010::/64
  VLAN 20: 2001:db8:0000:0014::/64
  VLAN 30: 2001:db8:0000:001e::/64

Each /64 has: 2^64 = 18,446,744,073,709,551,616 addresses!
```

**IPv6 Address Types:**

```yaml
Unicast:
  - One-to-one communication
  - Global Unicast (public)
  - Unique Local (private)
  - Link-Local (auto-configured)

Multicast:
  - One-to-many communication
  - Prefix: ff00::/8
  - Examples:
    ff02::1 (all nodes on link)
    ff02::2 (all routers on link)
    ff02::1:ff00:0/104 (solicited-node multicast)

Anycast:
  - One-to-nearest communication
  - Same address assigned to multiple interfaces
  - Routed to nearest one (by routing metric)
  - Use: Load balancing, DNS root servers

No Broadcast in IPv6:
  - Replaced by multicast
```

---

### Componentes de Rede

#### Switch (Layer 2)

**Função:** Conecta dispositivos em **mesma rede** (LAN) usando **MAC addresses**.

```yaml
Features:
  - MAC Address Learning
  - Frame Forwarding (based on MAC table)
  - VLAN segmentation
  - Spanning Tree Protocol (STP)
  - Port Security
  - Link Aggregation (EtherChannel)

MAC Address Table (CAM):
  Port  MAC Address        VLAN
  1     aa:bb:cc:dd:ee:ff  10
  2     11:22:33:44:55:66  10
  3     77:88:99:aa:bb:cc  20

  Learning:
    1. Frame arrives on port 1
    2. Switch learns source MAC + port
    3. Switch checks destination MAC in table
    4. If found: Forward to specific port
    5. If not found: Flood to all ports (broadcast)
```

**Cisco Switch Commands:**

```cisco
! Show MAC address table
Switch# show mac address-table

! Show interfaces status
Switch# show interfaces status

! Show VLANs
Switch# show vlan brief

! Configure interface
Switch# configure terminal
Switch(config)# interface FastEthernet0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# no shutdown
Switch(config-if)# exit

! Port Security (allow only specific MAC)
Switch(config)# interface FastEthernet0/5
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security mac-address sticky
Switch(config-if)# switchport port-security violation restrict
```

---

#### Router (Layer 3)

**Função:** Conecta **redes diferentes** usando **IP addresses**, toma decisões de **path selection**.

```yaml
Features:
  - IP Routing
  - NAT/PAT
  - Access Control Lists (ACL)
  - DHCP Server
  - VPN termination
  - Quality of Service (QoS)

Routing Table: Destination     Gateway         Interface  Metric
  0.0.0.0/0       192.168.1.1     eth0       10      (default route)
  10.0.0.0/8      0.0.0.0         eth1       0       (directly connected)
  172.16.0.0/16   10.0.0.254      eth1       20      (static route)
  192.168.1.0/24  0.0.0.0         eth0       0       (directly connected)

Routing Decision: 1. Packet arrives with destination IP
  2. Router checks routing table
  3. Longest prefix match wins
  4. Forward to next-hop gateway or directly connected
  5. Decrement TTL (Time To Live)
  6. If TTL = 0, drop packet (prevent loops)
```

**Cisco Router Commands:**

```cisco
! Show routing table
Router# show ip route

! Show interfaces
Router# show ip interface brief

! Configure interface
Router# configure terminal
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown
Router(config-if)# exit

! Static route
Router(config)# ip route 10.0.0.0 255.0.0.0 192.168.1.254

! Default route
Router(config)# ip route 0.0.0.0 0.0.0.0 192.168.1.1
```

---

#### Firewall (Layer 3/4/7)

**Tipos:**

```yaml
Stateless Firewall (Packet Filter):
  - Examina cada packet individualmente
  - Decisions baseadas em: Source IP, Dest IP, Port, Protocol
  - Não mantém estado de conexão
  - Example: iptables (sem connection tracking)

Stateful Firewall:
  - Mantém tabela de conexões estabelecidas
  - Permite retorno de tráfego automaticamente
  - Example: iptables (with connection tracking), ASA

  Connection Table:
    SRC_IP          DST_IP          SRC_PORT  DST_PORT  STATE
    192.168.1.10    8.8.8.8         54321     443       ESTABLISHED
    192.168.1.20    142.250.185.46  43210     80        SYN_SENT

NGFW (Next-Generation Firewall):
  - Stateful inspection
  - Deep Packet Inspection (DPI)
  - Application awareness (Layer 7)
  - Intrusion Prevention System (IPS)
  - SSL/TLS inspection
  - Identity-based policies

  Vendors: Palo Alto, Fortinet, Cisco Firepower

WAF (Web Application Firewall):
  - Layer 7 (Application layer)
  - HTTP/HTTPS traffic only
  - Protects against: SQLi, XSS, CSRF
  - Example: ModSecurity, Cloudflare WAF, AWS WAF
```

---

#### Wireless LAN Controller (WLC)

```yaml
Architecture:

Autonomous AP (Outdated):
  - Standalone Access Point
  - All configuration on AP itself
  - No centralized management
  - Use: SOHO, small offices

Controller-Based (Modern):
  - Lightweight APs (no config)
  - WLC manages all APs centrally
  - CAPWAP tunnel (Control And Provisioning of Wireless Access Points)

  Components:
    WLC (Controller):
      - Centralized authentication (RADIUS)
      - Configuration management
      - RF (Radio Frequency) optimization
      - Rogue AP detection

    LAP (Lightweight AP):
      - Forwards traffic to WLC via CAPWAP
      - No local configuration
      - Zero-touch provisioning

CAPWAP Tunnel:
  Control Plane: UDP 5246 (AP ↔ WLC control messages)
  Data Plane:
    - Local Mode: Data goes directly from AP to network
    - FlexConnect: AP can switch locally when WLC unreachable
    - Centralized: All data tunneled through WLC (deprecated)
```

---

## 🔌 Acesso à Rede

### VLANs (Virtual LANs)

**Definição:** Segmentação **lógica** de uma rede física em múltiplas redes **isoladas** (broadcast domains).

```yaml
Benefits:
  ✓ Security: Isolate sensitive traffic (Finance, HR)
  ✓ Performance: Reduce broadcast domain size
  ✓ Flexibility: Group users logically (not physically)
  ✓ Cost: No need for separate physical switches

VLAN Types:

Data VLAN:
  - User traffic (workstations, servers)
  - VLAN 1-1005

Voice VLAN:
  - VoIP traffic (Cisco IP phones)
  - Prioritized (QoS)
  - Separate from data for quality

Native VLAN:
  - Untagged frames on trunk
  - Default: VLAN 1
  - Security: Change from VLAN 1 to avoid attacks

Management VLAN:
  - Switch/router management traffic
  - Separate from user data
```

**VLAN Configuration:**

```cisco
! Create VLANs
Switch(config)# vlan 10
Switch(config-vlan)# name Sales
Switch(config-vlan)# exit

Switch(config)# vlan 20
Switch(config-vlan)# name Engineering
Switch(config-vlan)# exit

Switch(config)# vlan 99
Switch(config-vlan)# name Management
Switch(config-vlan)# exit

! Assign port to VLAN (Access Mode)
Switch(config)# interface FastEthernet0/5
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# exit

! Configure trunk (carries multiple VLANs)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk native vlan 99
Switch(config-if)# switchport trunk allowed vlan 10,20,99
Switch(config-if)# exit

! Verify
Switch# show vlan brief
Switch# show interfaces trunk
```

**802.1Q Tagging:**

```yaml
Ethernet Frame with VLAN Tag:

  ┌────────────────────────────────────────────────────────┐
  │ Destination MAC (6 bytes)                              │
  ├────────────────────────────────────────────────────────┤
  │ Source MAC (6 bytes)                                   │
  ├────────────────────────────────────────────────────────┤
  │ 802.1Q Tag (4 bytes)                                   │
  │ ┌──────────────┬──────────────┬────────────────────┐   │
  │ │ TPID (0x8100)│ PCP (3 bits) │ VLAN ID (12 bits)  │   │
  │ └──────────────┴──────────────┴────────────────────┘   │
  ├────────────────────────────────────────────────────────┤
  │ EtherType / Length (2 bytes)                           │
  ├────────────────────────────────────────────────────────┤
  │ Data (46-1500 bytes)                                   │
  ├────────────────────────────────────────────────────────┤
  │ FCS - Frame Check Sequence (4 bytes)                   │
  └────────────────────────────────────────────────────────┘

VLAN ID Range: 1-4094
  - 1: Default VLAN (cannot delete)
  - 2-1001: Normal range
  - 1002-1005: Reserved (legacy protocols)
  - 1006-4094: Extended range
```

---

### Spanning Tree Protocol (STP)

**Problema:** Loop de camada 2 causa **broadcast storm** → Crash de rede.

```yaml
Scenario: Redundant switches

  Switch A ──────── Switch B
  │                 │
  └────── Switch C ─┘

Without STP: 1. PC sends broadcast
  2. Broadcast forwarded by all switches
  3. Frame loops infinitely
  4. MAC table corruption
  5. Network meltdown

With STP: 1. Elects Root Bridge
  2. Blocks redundant paths
  3. Loop-free topology
  4. Backup path ready (convergence)
```

**STP Election:**

```yaml
Step 1: Root Bridge Election
  - Lowest Bridge ID wins
  - Bridge ID = Priority (default 32768) + MAC Address
  - All switches send BPDU (Bridge Protocol Data Unit)

Step 2: Root Port Selection (each non-root switch)
  - Port with lowest cost path to Root Bridge
  - Cost based on bandwidth:
    10 Mbps   = 100
    100 Mbps  = 19
    1 Gbps    = 4
    10 Gbps   = 2

Step 3: Designated Port Selection (each segment)
  - Port with best path to Root Bridge
  - Forwards traffic on that segment

Step 4: Block remaining ports
  - Prevents loops
  - Stays in listening state

Port States:
  Blocking (20 sec): Receives BPDUs only
  Listening (15 sec): Sends BPDUs, no forwarding
  Learning (15 sec): Builds MAC table, no forwarding
  Forwarding: Normal operation
  Disabled: Shutdown

Convergence Time: 50 seconds (20+15+15)
```

**RSTP (Rapid Spanning Tree):**

```yaml
Improvements over STP:
  - Convergence: 50 sec → 1-2 sec
  - Port roles: Root, Designated, Alternate, Backup
  - Edge ports (PortFast): Immediate forwarding

Configuration: Switch(config)# spanning-tree mode rapid-pvst
  Switch(config)# interface range FastEthernet0/1-24
  Switch(config-if-range)# spanning-tree portfast
  Switch(config-if-range)# spanning-tree bpduguard enable
```

---

### Link Aggregation (EtherChannel/LACP)

**Definição:** Combina múltiplas portas físicas em **um link lógico** para aumentar bandwidth e redundância.

```yaml
Benefits:
  - Bandwidth: 4x 1Gbps = 4Gbps aggregate
  - Redundancy: If one link fails, others continue
  - Load Balancing: Traffic distributed across links

Protocols:

PAgP (Port Aggregation Protocol):
  - Cisco proprietary
  - Modes: desirable, auto

LACP (Link Aggregation Control Protocol):
  - IEEE 802.3ad standard
  - Modes: active, passive
  - Industry standard (use this)

Static (On):
  - No negotiation protocol
  - Both sides manually configured
  - Risky (misconfiguration causes loop)
```

**LACP Configuration:**

```cisco
! Switch 1
Switch1(config)# interface range GigabitEthernet0/1-2
Switch1(config-if-range)# channel-group 1 mode active
Switch1(config-if-range)# exit

Switch1(config)# interface Port-channel1
Switch1(config-if)# switchport mode trunk
Switch1(config-if)# switchport trunk allowed vlan 10,20,30
Switch1(config-if)# exit

! Switch 2 (same configuration)
Switch2(config)# interface range GigabitEthernet0/1-2
Switch2(config-if-range)# channel-group 1 mode active
Switch2(config-if-range)# exit

Switch2(config)# interface Port-channel1
Switch2(config-if)# switchport mode trunk
Switch2(config-if)# switchport trunk allowed vlan 10,20,30
Switch2(config-if)# exit

! Verify
Switch# show etherchannel summary
Switch# show etherchannel port-channel
```

**Load Balancing Methods:**

```yaml
Source MAC: Hash based on source MAC address
Destination MAC: Hash based on destination MAC
Source-Dest MAC: Hash based on both (most common)
Source IP: Hash based on source IP
Destination IP: Hash based on destination IP
Source-Dest IP: Hash based on both IPs

Configuration: Switch(config)# port-channel load-balance src-dst-ip
```

---

### Wireless Security

```yaml
Security Standards:

WEP (Wired Equivalent Privacy):
  - Deprecated (crackable in minutes)
  - 40-bit or 104-bit key
  - RC4 encryption (weak)
  - Never use

WPA (Wi-Fi Protected Access):
  - Improvement over WEP
  - TKIP (Temporal Key Integrity Protocol)
  - Still vulnerable (deprecated)

WPA2:
  - Current standard (since 2004)
  - AES encryption (CCMP)
  - Two modes:
    - WPA2-Personal (PSK - Pre-Shared Key)
    - WPA2-Enterprise (802.1X + RADIUS)

WPA3:
  - Latest standard (since 2018)
  - SAE (Simultaneous Authentication of Equals)
  - Forward secrecy
  - Protection against offline dictionary attacks
  - 192-bit security for Enterprise

Authentication Methods:

Open (No Security):
  - No authentication
  - No encryption
  - Public Wi-Fi

PSK (Pre-Shared Key):
  - Single password for all users
  - Use: Home, small office
  - Weakness: Password sharing

802.1X (Enterprise):
  - Per-user authentication
  - RADIUS server
  - EAP methods:
    - EAP-TLS (certificate-based - most secure)
    - PEAP (Protected EAP with password)
    - EAP-TTLS (Tunneled TLS)

RADIUS (Remote Authentication Dial-In User Service):
  - AAA server (Authentication, Authorization, Accounting)
  - Centralized credential management
  - Integrates with: Active Directory, LDAP

  Flow:
    1. Client → AP: Connection request
    2. AP → RADIUS: Access-Request
    3. RADIUS: Check credentials (AD, LDAP)
    4. RADIUS → AP: Access-Accept / Access-Reject
    5. AP → Client: Connection granted / denied
```

**Wireless Attacks:**

```yaml
Evil Twin:
  Attack: Rogue AP with same SSID as legitimate
  Goal: Man-in-the-Middle
  Defense: 802.1X, Certificate validation

Deauthentication Attack:
  Attack: Send deauth frames to disconnect clients
  Goal: Force reconnection (capture handshake)
  Defense: Management Frame Protection (802.11w)

WPS PIN Attack:
  Attack: Brute-force 8-digit WPS PIN
  Tool: Reaver
  Defense: Disable WPS

Krack Attack (WPA2):
  Attack: Key reinstallation attack
  Impact: Decrypt traffic
  Defense: Update firmware, use WPA3
```

---

## 🌍 Conectividade IP

### Roteamento Estático

**Definição:** Rotas configuradas **manualmente** pelo administrador.

```yaml
Types:

Default Route (Gateway of Last Resort):
  - Catches all unmatched traffic
  - 0.0.0.0/0
  - Example: Route to Internet

  Router(config)# ip route 0.0.0.0 0.0.0.0 192.168.1.1

Network Route:
  - Route to specific network

  Router(config)# ip route 10.0.0.0 255.0.0.0 172.16.1.1

Host Route:
  - Route to single host (/32)

  Router(config)# ip route 10.0.0.50 255.255.255.255 172.16.1.1

Floating Static Route (Backup):
  - Higher administrative distance
  - Used only if primary fails

  Router(config)# ip route 0.0.0.0 0.0.0.0 192.168.1.1 1
  Router(config)# ip route 0.0.0.0 0.0.0.0 192.168.2.1 10
  # Second route (AD=10) used only if first (AD=1) fails
```

---

### OSPF (Open Shortest Path First)

**Definição:** Protocolo de roteamento dinâmico **link-state** (conhece topologia completa).

```yaml
Characteristics:
  - IGP (Interior Gateway Protocol)
  - Algorithm: Dijkstra (SPF - Shortest Path First)
  - Metric: Cost (based on bandwidth)
  - Supports VLSM and CIDR
  - Fast convergence
  - Hierarchical (Areas)

OSPF Areas:
  Area 0 (Backbone):
    - Central area
    - All other areas connect to Area 0

  Regular Areas:
    - Area 1, 2, 3, etc.

  Stub Area:
    - No external routes (reduces routing table)

  Totally Stubby Area:
    - No external + no inter-area routes

Cost Calculation:
  Cost = Reference Bandwidth / Interface Bandwidth

  Default Reference Bandwidth = 100 Mbps

  Examples:
    FastEthernet (100 Mbps): 100/100 = 1
    GigabitEthernet (1000 Mbps): 100/1000 = 0.1 → rounds to 1
    10GigabitEthernet: 100/10000 = 0.01 → rounds to 1

  Fix: Increase reference bandwidth
    Router(config-router)# auto-cost reference-bandwidth 10000
    # Now: 10000/10000 = 1 (10GbE), 10000/1000 = 10 (1GbE)
```

**OSPF Configuration:**

```cisco
! Router 1
Router1(config)# router ospf 1
Router1(config-router)# router-id 1.1.1.1
Router1(config-router)# network 10.0.0.0 0.0.0.255 area 0
Router1(config-router)# network 172.16.0.0 0.0.255.255 area 1
Router1(config-router)# passive-interface GigabitEthernet0/0
Router1(config-router)# exit

! Verify
Router1# show ip ospf neighbor
Router1# show ip ospf database
Router1# show ip route ospf
```

**OSPF Neighbor States:**

```yaml
1. Down: No OSPF communication
2. Init: Hello received, but bidirectional not confirmed
3. 2-Way: Bidirectional communication confirmed
  └─ DR/BDR election happens here (on multi-access)
4. ExStart: Master/Slave negotiation for DBD exchange
5. Exchange: Exchange Database Description (DBD) packets
6. Loading: Request and receive LSAs (Link State Advertisements)
7. Full: Databases synchronized (neighbors adjacent)
```

---

### Administrative Distance (AD)

**Definição:** **Trustworthiness** de uma routing source (0-255, lower = better).

```yaml
Administrative Distance Values: 0   = Directly Connected
  1   = Static Route
  5   = EIGRP Summary Route
  20  = External BGP (eBGP)
  90  = Internal EIGRP
  110 = OSPF
  115 = IS-IS
  120 = RIP
  200 = Internal BGP (iBGP)
  255 = Unknown (not installed in routing table)

Example:
  Same destination learned via:
    - OSPF: AD 110
    - RIP: AD 120
    - Static: AD 1

  Winner: Static route (AD 1) installed in routing table
```

---

### First Hop Redundancy Protocols (FHRP)

**Problema:** Single gateway = single point of failure.

**Solução:** Multiple routers share **virtual IP** as gateway.

```yaml
Protocols:

HSRP (Hot Standby Router Protocol):
  - Cisco proprietary
  - Virtual IP + Virtual MAC
  - Active/Standby roles
  - Default priority: 100 (higher wins Active)
  - Preemption: Disabled by default
  - Multicast: 224.0.0.2

VRRP (Virtual Router Redundancy Protocol):
  - Open standard (RFC 5798)
  - Virtual IP (uses real router's MAC)
  - Master/Backup roles
  - Default priority: 100
  - Preemption: Enabled by default
  - Multicast: 224.0.0.18

GLBP (Gateway Load Balancing Protocol):
  - Cisco proprietary
  - Load balancing (active-active)
  - Multiple AVGs (Active Virtual Gateways)
  - Distributes traffic across routers
```

**HSRP Configuration:**

```cisco
! Router 1 (Active)
Router1(config)# interface GigabitEthernet0/0
Router1(config-if)# ip address 192.168.1.2 255.255.255.0
Router1(config-if)# standby 1 ip 192.168.1.1
Router1(config-if)# standby 1 priority 110
Router1(config-if)# standby 1 preempt
Router1(config-if)# exit

! Router 2 (Standby)
Router2(config)# interface GigabitEthernet0/0
Router2(config-if)# ip address 192.168.1.3 255.255.255.0
Router2(config-if)# standby 1 ip 192.168.1.1
Router2(config-if)# standby 1 priority 100
Router2(config-if)# exit

! Clients use 192.168.1.1 as default gateway
! If Router1 fails, Router2 takes over automatically
```

---

## 🔧 Serviços IP

### NAT/PAT

**NAT (Network Address Translation):**

```yaml
Purpose: Translate private IPs to public IP(s)

Private IP Ranges (RFC 1918):
  10.0.0.0/8        (10.0.0.0 - 10.255.255.255)
  172.16.0.0/12     (172.16.0.0 - 172.31.255.255)
  192.168.0.0/16    (192.168.0.0 - 192.168.255.255)

Types:

Static NAT (One-to-One):
  - Private IP ↔ Public IP (1:1 mapping)
  - Use: Servers (web, mail) that need fixed public IP

  Example:
    10.0.0.10 (private) → 200.1.1.10 (public)

Dynamic NAT (Pool):
  - Private IPs → Pool of public IPs
  - First-come, first-served
  - Limitation: Pool can be exhausted

  Example:
    10.0.0.10 → 200.1.1.100
    10.0.0.11 → 200.1.1.101
    10.0.0.12 → 200.1.1.102

PAT (Port Address Translation / NAT Overload):
  - Many private IPs → One public IP
  - Uses different source ports
  - Most common (home routers)

  Example:
    10.0.0.10:54321 → 200.1.1.1:10001
    10.0.0.11:43210 → 200.1.1.1:10002
    10.0.0.12:12345 → 200.1.1.1:10003
```

**NAT Configuration (Cisco):**

```cisco
! Static NAT
Router(config)# ip nat inside source static 10.0.0.10 200.1.1.10

! Dynamic NAT
Router(config)# ip nat pool PUBLIC_POOL 200.1.1.100 200.1.1.110 netmask 255.255.255.0
Router(config)# access-list 1 permit 10.0.0.0 0.0.0.255
Router(config)# ip nat inside source list 1 pool PUBLIC_POOL

! PAT (Overload)
Router(config)# access-list 1 permit 10.0.0.0 0.0.0.255
Router(config)# ip nat inside source list 1 interface GigabitEthernet0/0 overload

! Apply to interfaces
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip nat outside
Router(config-if)# exit

Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip nat inside
Router(config-if)# exit

! Verify
Router# show ip nat translations
Router# show ip nat statistics
```

**Security Implications:**

```yaml
Advantages:
  ✓ Hides internal network structure
  ✓ Single point of logging (NAT device)
  ✓ Conserves public IPv4 addresses

Disadvantages:
  ✗ Breaks end-to-end connectivity
  ✗ Complicates: IPsec, SIP, FTP (need ALG)
  ✗ No inbound connections (unless port forwarding)
  ✗ Logging overhead (track translations)
```

---

### DHCP (Dynamic Host Configuration Protocol)

**Processo DORA:**

```yaml
1. Discover (Client → Broadcast):
  - Client: "I need an IP address!"
  - Destination: 255.255.255.255:67 (DHCP Server)
  - Source: 0.0.0.0:68 (DHCP Client)

2. Offer (Server → Broadcast/Unicast):
  - Server: "You can use 192.168.1.100"
  - Includes: IP, Subnet Mask, Gateway, DNS, Lease Time

3. Request (Client → Broadcast):
  - Client: "I accept 192.168.1.100"
  - Broadcast (in case multiple DHCP servers offered)

4. Acknowledge (Server → Broadcast/Unicast):
  - Server: "192.168.1.100 is now yours for 24 hours"
  - Client configures interface

Lease Renewal:
  - T1 (50% of lease): Unicast renewal request to original server
  - T2 (87.5% of lease): Broadcast renewal (if T1 failed)
  - If T2 fails: Start DORA again
```

**DHCP Configuration (Cisco Router):**

```cisco
! DHCP Pool
Router(config)# ip dhcp pool LAN_POOL
Router(dhcp-config)# network 192.168.1.0 255.255.255.0
Router(dhcp-config)# default-router 192.168.1.1
Router(dhcp-config)# dns-server 8.8.8.8 8.8.4.4
Router(dhcp-config)# lease 7  # 7 days
Router(dhcp-config)# exit

! Exclude addresses (reserved for servers)
Router(config)# ip dhcp excluded-address 192.168.1.1 192.168.1.10

! Verify
Router# show ip dhcp binding
Router# show ip dhcp pool
Router# show ip dhcp conflict
```

**DHCP Attacks:**

```yaml
DHCP Starvation:
  Attack: Request all IPs in DHCP pool
  Tool: Yersinia, DHCPStarv
  Impact: Legitimate clients can't get IP (DoS)
  Defense: DHCP Snooping

Rogue DHCP Server:
  Attack: Attacker runs fake DHCP server
  Impact: Clients get malicious gateway (MitM)
  Defense: DHCP Snooping + Option 82
```

---

### DNS (Domain Name System)

```yaml
Hierarchy:

Root Servers (13 worldwide):
  - a.root-servers.net through m.root-servers.net
  - Top of DNS hierarchy
  - Maintained by ICANN

TLD Servers (Top-Level Domain):
  - .com, .org, .net, .edu
  - Country codes: .br, .uk, .jp

Authoritative Name Servers:
  - Holds DNS records for specific domains
  - Example: ns1.google.com for google.com

Recursive Resolvers:
  - ISP DNS servers
  - Public: 8.8.8.8 (Google), 1.1.1.1 (Cloudflare)
  - Caches responses

Record Types:

A (Address):
  - Domain → IPv4
  - example.com → 192.0.2.1

AAAA (IPv6 Address):
  - Domain → IPv6
  - example.com → 2001:db8::1

CNAME (Canonical Name):
  - Alias → Canonical name
  - www.example.com → example.com

MX (Mail Exchange):
  - Domain → Mail server
  - example.com → mail.example.com (priority 10)

TXT (Text):
  - Arbitrary text
  - Use: SPF, DKIM, domain verification

NS (Name Server):
  - Domain → Authoritative name server
  - example.com → ns1.example.com

PTR (Pointer):
  - Reverse DNS (IP → Domain)
  - 1.2.0.192.in-addr.arpa → example.com
```

**DNS Query Process:**

```yaml
User: Visits www.google.com

1. Browser cache: Not found
2. OS cache: Not found
3. Recursive resolver (ISP):
   a. Checks cache: Not found
   b. Query root server: "Who handles .com?"
   c. Root: "Ask TLD server 192.5.6.30"
   d. Query TLD server: "Who handles google.com?"
   e. TLD: "Ask ns1.google.com (216.239.32.10)"
   f. Query authoritative: "What's www.google.com?"
   g. Authoritative: "142.250.185.46"
   h. Cache response (TTL: 300 sec)
4. Return to browser: 142.250.185.46
5. Browser connects to 142.250.185.46:443
```

**DNS Security:**

```yaml
DNS Cache Poisoning:
  Attack: Inject fake DNS response
  Impact: example.com → attacker's IP
  Defense: DNSSEC (cryptographic signatures)

DNS Tunneling:
  Attack: Exfiltrate data via DNS queries
  Example: stolen-data.attacker.com
  Detection: Unusual query patterns, long domain names
  Defense: DNS firewall, anomaly detection

DDoS Amplification:
  Attack: Spoof victim IP, query open resolvers
  Amplification: 50x-100x (small query → large response)
  Defense: Rate limiting, BCP 38 (block spoofed IPs)
```

**DNS Tools:**

```bash
# nslookup
$ nslookup google.com
Server:  8.8.8.8
Address: 8.8.8.8#53

Non-authoritative answer:
Name:    google.com
Address: 142.250.185.46

# dig (more detailed)
$ dig google.com

; <<>> DiG 9.18.12 <<>> google.com
;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             300     IN      A       142.250.185.46

;; Query time: 12 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)

# Reverse DNS
$ dig -x 142.250.185.46
;; ANSWER SECTION:
46.185.250.142.in-addr.arpa. 300 IN PTR iad30s44-in-f14.1e100.net.

# DNS trace (full resolution path)
$ dig +trace google.com
```

---

### NTP (Network Time Protocol)

**Importância:** Sincronização de tempo é **crítica** para:

- Logs (forensics)
- Certificados SSL/TLS
- Kerberos authentication
- Compliance (SOX, PCI-DSS)

```yaml
NTP Stratum (Distance from reference clock):

Stratum 0: Atomic clock, GPS
Stratum 1: Directly connected to Stratum 0 (< 1ms accuracy)
Stratum 2: Sync from Stratum 1 (< 10ms accuracy)
...
Stratum 15: Lowest usable stratum
Stratum 16: Unsynchronized

NTP Modes:

Server Mode:
  - Provides time to clients

Client Mode:
  - Requests time from server

Peer Mode:
  - Mutually synchronize (backup)

Broadcast Mode:
  - One-way, low accuracy
```

**NTP Configuration:**

```cisco
! Configure NTP server
Router(config)# ntp server 129.6.15.28  # time.nist.gov
Router(config)# ntp server 132.163.96.1  # NIST, Boulder

! Set timezone
Router(config)# clock timezone EST -5
Router(config)# clock summer-time EDT recurring

! Authentication (recommended)
Router(config)# ntp authenticate
Router(config)# ntp authentication-key 1 md5 SecretKey123
Router(config)# ntp trusted-key 1
Router(config)# ntp server 129.6.15.28 key 1

! Verify
Router# show ntp status
Router# show ntp associations
```

**NTP Security:**

```yaml
NTP Amplification Attack:
  Attack: Spoof victim IP, query NTP with monlist command
  Amplification: ~200x (small query → huge response)
  Defense:
    - Disable monlist (ntpd >= 4.2.7)
    - Rate limiting
    - ACLs

NTP Poisoning:
  Attack: Fake NTP responses
  Impact: Incorrect time → broken authentication
  Defense: NTP authentication (symmetric key or Autokey)
```

---

### SNMP (Simple Network Management Protocol)

**Definição:** Protocolo para **monitoramento e gerenciamento** de dispositivos de rede.

```yaml
Components:

SNMP Manager (NMS - Network Management System):
  - Monitoring server (Nagios, PRTG, SolarWinds)
  - Polls agents for data
  - Receives traps (alerts)

SNMP Agent:
  - Software on network device (router, switch)
  - Responds to queries
  - Sends traps

MIB (Management Information Base):
  - Database of manageable objects
  - Hierarchical structure (OID - Object Identifier)
  - Example OID: 1.3.6.1.2.1.1.1.0 (System Description)

Versions:

SNMPv1:
  - Community strings (plaintext passwords)
  - No encryption
  - READ: Read-only access
  - WRITE: Read-write access

SNMPv2c:
  - Improvements over v1
  - Still uses community strings
  - More data types

SNMPv3:
  - Authentication (MD5/SHA)
  - Encryption (DES/AES)
  - RBAC (Role-Based Access Control)
  - RECOMMENDED for production
```

**SNMP Configuration:**

```cisco
! SNMPv2c (simple, not secure)
Router(config)# snmp-server community public RO
Router(config)# snmp-server community private RW
Router(config)# snmp-server host 192.168.1.100 version 2c public

! SNMPv3 (secure)
Router(config)# snmp-server group ADMIN_GROUP v3 priv
Router(config)# snmp-server user admin ADMIN_GROUP v3 auth sha AuthPass123 priv aes 128 PrivPass456
Router(config)# snmp-server host 192.168.1.100 version 3 priv admin

! Enable SNMP traps
Router(config)# snmp-server enable traps cpu threshold
Router(config)# snmp-server enable traps memory bufferpeak
Router(config)# snmp-server enable traps config
```

**Common OIDs:**

```yaml
System Information: 1.3.6.1.2.1.1.1.0  - sysDescr (System Description)
  1.3.6.1.2.1.1.3.0  - sysUpTime (Uptime)
  1.3.6.1.2.1.1.5.0  - sysName (Hostname)

Interfaces: 1.3.6.1.2.1.2.2.1.2  - ifDescr (Interface Description)
  1.3.6.1.2.1.2.2.1.8  - ifOperStatus (1=up, 2=down)
  1.3.6.1.2.1.2.2.1.10 - ifInOctets (Bytes received)
  1.3.6.1.2.1.2.2.1.16 - ifOutOctets (Bytes sent)

CPU/Memory:
  1.3.6.1.4.1.9.9.109.1.1.1.1.7 - cpmCPUTotal5minRev (Cisco CPU 5min avg)
  1.3.6.1.4.1.9.9.48.1.1.1.5    - ciscoMemoryPoolUsed
```

**SNMP Tools:**

```bash
# snmpwalk (enumerate all OIDs)
$ snmpwalk -v2c -c public 192.168.1.1

# snmpget (query specific OID)
$ snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0

# SNMPv3 (authenticated)
$ snmpget -v3 -l authPriv -u admin -a SHA -A AuthPass123 -x AES -X PrivPass456 192.168.1.1 1.3.6.1.2.1.1.5.0
```

---

### Syslog

**Definição:** Protocolo de **logging** centralizado (RFC 5424).

```yaml
Severity Levels (0-7):

  Level  Keyword      Description
  0      Emergency    System unusable
  1      Alert        Immediate action required
  2      Critical     Critical condition
  3      Error        Error condition
  4      Warning      Warning condition
  5      Notice       Normal but significant
  6      Informational Informational message
  7      Debug        Debug message

Facilities (source of message):

  0  - kern (kernel)
  1  - user (user-level)
  3  - daemon (system daemons)
  4  - auth (authentication)
  10 - authpriv (security/authorization private)
  16-23 - local0 through local7 (custom use)

Message Format:

  <Priority>Timestamp Hostname Process[PID]: Message

  Example:
  <134>Feb 10 15:42:33 Router1 %SYS-5-CONFIG_I: Configured from console by admin

  Priority = Facility * 8 + Severity
  134 = 16 * 8 + 6 (local0, Informational)
```

**Syslog Configuration:**

```cisco
! Enable logging
Router(config)# logging on

! Log to buffer (local)
Router(config)# logging buffered 16384  # 16KB buffer
Router(config)# logging buffered informational

! Log to syslog server
Router(config)# logging host 192.168.1.100
Router(config)# logging trap debugging

! Timestamp
Router(config)# service timestamps log datetime msec localtime show-timezone

! Source interface (for consistent source IP)
Router(config)# logging source-interface Loopback0

! Verify
Router# show logging
```

**Syslog Server (rsyslog - Linux):**

```bash
# /etc/rsyslog.conf

# Listen on UDP 514
module(load="imudp")
input(type="imudp" port="514")

# Templates
$template RemoteLogs,"/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log"

# Route by hostname
*.* ?RemoteLogs
& stop

# Restart rsyslog
$ sudo systemctl restart rsyslog
```

---

### SSH (Secure Shell)

**Definição:** Protocolo criptografado para **acesso remoto** seguro (substitui Telnet).

```yaml
SSH vs Telnet:

Telnet (Port 23):
  ✗ Plaintext (no encryption)
  ✗ Credentials visible in packet capture
  ✗ Session hijacking easy
  ✗ Never use in production

SSH (Port 22):
  ✓ Encrypted (RSA, ECDSA, Ed25519)
  ✓ Authentication: Password, Public Key, Certificate
  ✓ Port forwarding / Tunneling
  ✓ SFTP (secure file transfer)
  ✓ Industry standard

SSH Authentication:

Password:
  - User provides password
  - Encrypted over SSH tunnel
  - Weak (vulnerable to brute-force)

Public Key:
  - Asymmetric cryptography
  - Client: Private key (kept secret)
  - Server: Public key (stored in authorized_keys)
  - More secure (no password transmission)

Certificate:
  - CA-signed keys
  - Centralized management
  - Enterprise use
```

**SSH Configuration (Cisco):**

```cisco
! Generate RSA key pair
Router(config)# hostname Router1
Router(config)# ip domain-name company.com
Router(config)# crypto key generate rsa modulus 2048

! Enable SSH
Router(config)# ip ssh version 2
Router(config)# ip ssh time-out 60
Router(config)# ip ssh authentication-retries 3

! Create user
Router(config)# username admin privilege 15 secret StrongPassword123!

! Enable SSH on VTY lines
Router(config)# line vty 0 4
Router(config-line)# transport input ssh
Router(config-line)# login local
Router(config-line)# exec-timeout 10 0
Router(config-line)# exit

! Disable Telnet
Router(config)# line vty 0 4
Router(config-line)# transport input ssh
Router(config-line)# exit

! Verify
Router# show ip ssh
Router# show ssh
```

**SSH Client (Linux):**

```bash
# Connect with password
$ ssh admin@192.168.1.1

# Connect with private key
$ ssh -i ~/.ssh/id_rsa admin@192.168.1.1

# Generate key pair
$ ssh-keygen -t ed25519 -C "admin@company.com"

# Copy public key to server
$ ssh-copy-id -i ~/.ssh/id_ed25519.pub admin@192.168.1.1

# SSH config (~/.ssh/config)
Host router1
    HostName 192.168.1.1
    User admin
    IdentityFile ~/.ssh/id_ed25519
    Port 22

# Now connect with:
$ ssh router1
```

**SSH Tunneling:**

```bash
# Local port forwarding (access remote service locally)
$ ssh -L 8080:internal-server:80 user@jump-host
# Access http://localhost:8080 → reaches internal-server:80

# Remote port forwarding (expose local service remotely)
$ ssh -R 8080:localhost:80 user@remote-server
# remote-server:8080 → reaches localhost:80

# Dynamic port forwarding (SOCKS proxy)
$ ssh -D 1080 user@server
# Configure browser to use SOCKS5 proxy localhost:1080
```

---

## 🔒 Fundamentos de Segurança

### ACLs (Access Control Lists)

**Definição:** Filtros de pacotes aplicados em **interfaces de roteadores** para permitir/negar tráfego.

```yaml
Types:

Standard ACL (1-99, 1300-1999):
  - Filters by source IP only
  - Apply close to destination
  - Example: Block 10.0.0.0/8 from accessing server

Extended ACL (100-199, 2000-2699):
  - Filters by: Source IP, Dest IP, Protocol, Port
  - Apply close to source (more efficient)
  - Example: Block HTTP to 192.168.1.50

Named ACL:
  - Descriptive names
  - Can edit individual lines
  - Recommended for production
```

**ACL Logic:**

```yaml
Processing: 1. Top-down evaluation (sequential)
  2. First match wins (stop processing)
  3. Implicit deny at end (deny all)

Example ACL flow: permit 10.0.0.10 → Match? Yes → Allow, stop
  deny 10.0.0.0/24 → (not evaluated if above matched)
  permit any       → (not evaluated if above matched)
  deny any         → (implicit, always at end)
```

**Standard ACL:**

```cisco
! Create ACL
Router(config)# access-list 10 permit 192.168.1.0 0.0.0.255
Router(config)# access-list 10 deny 10.0.0.0 0.255.255.255
Router(config)# access-list 10 permit any

! Apply to interface
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip access-group 10 in
Router(config-if)# exit

! Verify
Router# show access-lists
Router# show ip interface GigabitEthernet0/0
```

**Extended ACL:**

```cisco
! Named extended ACL (recommended)
Router(config)# ip access-list extended BLOCK_HTTP
Router(config-ext-nacl)# deny tcp any host 192.168.1.50 eq 80
Router(config-ext-nacl)# deny tcp any host 192.168.1.50 eq 443
Router(config-ext-nacl)# permit ip any any
Router(config-ext-nacl)# exit

! Apply to interface
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip access-group BLOCK_HTTP out
Router(config-if)# exit

! Edit ACL (insert line)
Router(config)# ip access-list extended BLOCK_HTTP
Router(config-ext-nacl)# 5 permit tcp host 192.168.1.100 host 192.168.1.50 eq 443
# Line 5 inserted, existing lines renumbered
```

**Extended ACL Examples:**

```cisco
! Block Telnet from specific subnet
access-list 100 deny tcp 10.0.0.0 0.0.0.255 any eq 23
access-list 100 permit ip any any

! Allow only HTTPS to web server
access-list 101 permit tcp any host 192.168.1.50 eq 443
access-list 101 deny ip any host 192.168.1.50
access-list 101 permit ip any any

! Block ICMP (ping)
access-list 102 deny icmp any any
access-list 102 permit ip any any

! Allow established connections (stateful-like)
access-list 103 permit tcp any any established
access-list 103 deny ip any any
```

---

### VPN (Virtual Private Network)

#### Site-to-Site VPN (IPsec)

**Definição:** Túnel criptografado entre **duas redes** (ex: filial ↔ matriz).

```yaml
IPsec Phases:

Phase 1 (IKE - Internet Key Exchange):
  - Establish secure channel for negotiation
  - Authenticate peers (PSK or certificates)
  - Exchange keys (Diffie-Hellman)
  - Modes:
      - Main Mode (6 messages, more secure)
      - Aggressive Mode (3 messages, faster, less secure)

Phase 2 (IPsec):
  - Negotiate security parameters for data
  - Create IPsec SAs (Security Associations)
  - Modes:
      - Tunnel Mode (encrypts entire IP packet - typical)
      - Transport Mode (encrypts only payload - host-to-host)

Encryption/Hashing:
  Encryption: DES (weak), 3DES, AES-128, AES-256
  Hashing: MD5 (weak), SHA-1 (deprecated), SHA-256, SHA-512
  Authentication: PSK (Pre-Shared Key), RSA Signatures, ECDSA

Protocols:
  AH (Authentication Header):
    - IP Protocol 51
    - Authentication only (no encryption)
    - Rarely used

  ESP (Encapsulating Security Payload):
    - IP Protocol 50
    - Authentication + Encryption
    - Standard for IPsec
```

**IPsec Configuration (Simplified):**

```cisco
! Phase 1 (ISAKMP)
Router(config)# crypto isakmp policy 10
Router(config-isakmp)# encryption aes 256
Router(config-isakmp)# hash sha256
Router(config-isakmp)# authentication pre-share
Router(config-isakmp)# group 14
Router(config-isakmp)# lifetime 86400
Router(config-isakmp)# exit

Router(config)# crypto isakmp key SuperSecretKey address 203.0.113.1

! Phase 2 (IPsec)
Router(config)# crypto ipsec transform-set MY_SET esp-aes 256 esp-sha256-hmac
Router(cfg-crypto-trans)# mode tunnel
Router(cfg-crypto-trans)# exit

! Crypto map
Router(config)# crypto map VPN_MAP 10 ipsec-isakmp
Router(config-crypto-map)# set peer 203.0.113.1
Router(config-crypto-map)# set transform-set MY_SET
Router(config-crypto-map)# match address 110
Router(config-crypto-map)# exit

! Define interesting traffic (what to encrypt)
Router(config)# access-list 110 permit ip 10.0.0.0 0.0.0.255 172.16.0.0 0.0.0.255

! Apply to interface
Router(config)# interface GigabitEthernet0/0
Router(config-if)# crypto map VPN_MAP
Router(config-if)# exit

! Verify
Router# show crypto isakmp sa
Router# show crypto ipsec sa
```

---

#### Remote Access VPN (Client-to-Site)

```yaml
Protocols:

SSL VPN (WebVPN):
  - Browser-based or client app
  - Uses TLS (port 443)
  - Easier for users (no special client)
  - Examples: Cisco AnyConnect, OpenVPN

IPsec VPN:
  - Requires VPN client software
  - More complex setup
  - Higher performance
  - Examples: Cisco VPN Client, IKEv2

Split Tunneling:
  - Only corporate traffic through VPN
  - Internet traffic goes direct
  - Pros: Better performance
  - Cons: Security risk (bypasses corporate firewall)

Full Tunneling:
  - All traffic through VPN
  - More secure
  - Slower (extra latency)
```

---

### Layer 2 Security

#### DHCP Snooping

**Problema:** Rogue DHCP server provides malicious gateway (MitM attack).

**Solution:** DHCP Snooping - whitelist trusted DHCP servers.

```cisco
! Enable DHCP Snooping globally
Switch(config)# ip dhcp snooping

! Enable per VLAN
Switch(config)# ip dhcp snooping vlan 10,20,30

! Trust port connected to legitimate DHCP server
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip dhcp snooping trust
Switch(config-if)# exit

! All other ports are untrusted (cannot send DHCP Offers)

! Rate limit DHCP packets (prevent DoS)
Switch(config)# interface range FastEthernet0/1-24
Switch(config-if-range)# ip dhcp snooping limit rate 10
Switch(config-if-range)# exit

! Verify
Switch# show ip dhcp snooping
Switch# show ip dhcp snooping binding
```

**DHCP Snooping Binding Table:**

```
MAC Address       IP Address      Lease(sec)  Type  VLAN  Interface
------------------  ---------------  ----------  ----  ----  --------------------
aa:bb:cc:dd:ee:ff  192.168.1.100   86400       dhcp  10    FastEthernet0/5
11:22:33:44:55:66  192.168.1.101   86400       dhcp  10    FastEthernet0/6
```

---

#### Dynamic ARP Inspection (DAI)

**Problema:** ARP spoofing/poisoning (MitM attack).

**Solution:** Validate ARP packets against DHCP Snooping binding table.

```cisco
! Enable DAI per VLAN
Switch(config)# ip arp inspection vlan 10,20

! Trust uplink ports (don't inspect)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip arp inspection trust
Switch(config-if)# exit

! Rate limit (prevent DoS)
Switch(config)# interface range FastEthernet0/1-24
Switch(config-if-range)# ip arp inspection limit rate 15
Switch(config-if-range)# exit

! Verify
Switch# show ip arp inspection
Switch# show ip arp inspection statistics
```

**DAI Validation:**

```yaml
ARP Request:
  Sender MAC: aa:bb:cc:dd:ee:ff
  Sender IP: 192.168.1.100

  DAI checks DHCP Snooping table: Does aa:bb:cc:dd:ee:ff have 192.168.1.100?
    ✓ Yes → Forward
    ✗ No  → Drop (log violation)
```

---

#### Port Security

**Problema:** Unauthorized devices connecting to network (MAC flooding, CAM table overflow).

**Solution:** Limit MAC addresses allowed on each port.

```cisco
! Configure port security
Switch(config)# interface FastEthernet0/5
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security

! Maximum allowed MAC addresses
Switch(config-if)# switchport port-security maximum 1

! Learn MAC address
Switch(config-if)# switchport port-security mac-address sticky
# First MAC address connected is learned and saved

! Violation mode
Switch(config-if)# switchport port-security violation restrict
# Options:
#   shutdown - Disable port (default, most secure)
#   restrict - Drop frames, log violation, keep port up
#   protect  - Drop frames silently, keep port up

! Verify
Switch# show port-security
Switch# show port-security interface FastEthernet0/5
```

**Port Security Violation:**

```yaml
Scenario:
  - Port configured for 1 MAC address
  - PC-A (aa:bb:cc:dd:ee:ff) connected → Learned
  - Attacker unplugs PC-A, connects PC-B (11:22:33:44:55:66)

Result (violation mode = shutdown):
  - Port enters err-disabled state
  - LED turns amber
  - Log message generated
  - Manual recovery required:

    Switch(config)# interface FastEthernet0/5
    Switch(config-if)# shutdown
    Switch(config-if)# no shutdown

    Or enable auto-recovery:
    Switch(config)# errdisable recovery cause psecure-violation
    Switch(config)# errdisable recovery interval 300
```

---

### Wireless Security

**Enterprise Authentication (802.1X):**

```yaml
Components:

Supplicant (Client):
  - Laptop, smartphone requesting network access

Authenticator (AP or Switch):
  - Forwards authentication to RADIUS server
  - Blocks traffic until authentication succeeds

Authentication Server (RADIUS):
  - Validates credentials
  - Integrates with: Active Directory, LDAP

EAP Methods:

EAP-TLS (most secure):
  - Requires certificates on client and server
  - Mutual authentication
  - No passwords transmitted
  - Use: High-security environments

PEAP (Protected EAP):
  - Server certificate only
  - Client: Username + password
  - Password protected by TLS tunnel
  - Use: Most common in enterprises

EAP-TTLS:
  - Similar to PEAP
  - More flexible inner authentication
  - Supports legacy protocols

LEAP (Cisco proprietary):
  - Deprecated (weak)
  - Do not use
```

**RADIUS Configuration (FreeRADIUS):**

```bash
# /etc/freeradius/3.0/clients.conf
client wireless-controller {
    ipaddr = 192.168.1.10
    secret = SharedSecret123!
    nastype = cisco
}

# /etc/freeradius/3.0/users
bob Cleartext-Password := "BobPassword123!"
    Reply-Message := "Welcome Bob"

alice Cleartext-Password := "AlicePassword456!"
    Reply-Message := "Welcome Alice"

# Test authentication
$ radtest bob BobPassword123! 127.0.0.1 0 testing123

Received Access-Accept Id 123 from 127.0.0.1:1812
```

---

## 🤖 Automação e Programabilidade

### SDN (Software-Defined Networking)

**Definição:** Separação de **control plane** (decisões) e **data plane** (forwarding).

```yaml
Traditional Network:
  - Control plane + data plane on same device
  - CLI configuration (manual, error-prone)
  - Distributed control (each router independent)

SDN:
  - Centralized control plane (SDN controller)
  - Programmable via APIs
  - Network treated as code (Infrastructure as Code)

SDN Architecture:

  ┌──────────────────────────────────────────┐
  │ Application Layer                        │
  │ (Custom Apps, Orchestration)             │
  └────────────────┬─────────────────────────┘
                   │ Northbound API (REST)
  ┌────────────────▼─────────────────────────┐
  │ Control Plane                            │
  │ (SDN Controller: Cisco DNA, OpenDaylight)│
  └────────────────┬─────────────────────────┘
                   │ Southbound API (OpenFlow, NETCONF)
  ┌────────────────▼─────────────────────────┐
  │ Data Plane                               │
  │ (Switches, Routers - hardware forwarding)│
  └──────────────────────────────────────────┘

Southbound Protocols:
  - OpenFlow: Flow table programming
  - NETCONF: Configuration management (XML over SSH)
  - RESTCONF: RESTful API version of NETCONF

Northbound APIs:
  - REST APIs (JSON/XML)
  - Application integration
```

---

### REST APIs

**CRUD Operations:**

```yaml
HTTP Methods:

GET:
  - Read/retrieve data
  - Example: GET /api/devices
  - Idempotent (safe to repeat)

POST:
  - Create new resource
  - Example: POST /api/devices
  - Body: { "name": "Switch1", "ip": "192.168.1.10" }

PUT:
  - Update existing resource (replace)
  - Example: PUT /api/devices/1
  - Body: { "name": "Switch1-Updated", "ip": "192.168.1.11" }

PATCH:
  - Partial update
  - Example: PATCH /api/devices/1
  - Body: { "ip": "192.168.1.11" }

DELETE:
  - Delete resource
  - Example: DELETE /api/devices/1

HTTP Status Codes:
  200 OK: Success
  201 Created: Resource created (POST)
  204 No Content: Success, no body (DELETE)
  400 Bad Request: Invalid syntax
  401 Unauthorized: Authentication required
  403 Forbidden: Insufficient permissions
  404 Not Found: Resource doesn't exist
  500 Internal Server Error: Server error
```

**API Example (Cisco DNA Center):**

```bash
# Authenticate
$ curl -X POST https://dnac.company.com/dna/system/api/v1/auth/token \
  -u "admin:password" \
  -H "Content-Type: application/json"

# Response:
{"Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

# Get devices
$ curl -X GET https://dnac.company.com/dna/intent/api/v1/network-device \
  -H "X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Response (JSON):
{
  "response": [
    {
      "id": "device-uuid-123",
      "hostname": "Switch1",
      "managementIpAddress": "192.168.1.10",
      "platformId": "C9300-48P",
      "softwareVersion": "17.6.3"
    }
  ]
}
```

---

### Python for Network Automation

**Netmiko (SSH library):**

```python
from netmiko import ConnectHandler

# Device parameters
cisco_router = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.1',
    'username': 'admin',
    'password': 'password',
    'secret': 'enable_password'
}

# Connect
connection = ConnectHandler(**cisco_router)

# Enter enable mode
connection.enable()

# Send commands
output = connection.send_command('show ip interface brief')
print(output)

# Configure
config_commands = [
    'interface GigabitEthernet0/1',
    'description Configured by Python',
    'ip address 10.0.0.1 255.255.255.0',
    'no shutdown'
]
output = connection.send_config_set(config_commands)
print(output)

# Save config
connection.send_command('write memory')

# Disconnect
connection.disconnect()
```

**NETCONF/YANG (Cisco IOS XE):**

```python
from ncclient import manager

# Device parameters
device = {
    'host': '192.168.1.1',
    'port': 830,
    'username': 'admin',
    'password': 'password',
    'hostkey_verify': False
}

# Connect
with manager.connect(**device) as m:
    # Get running config
    config = m.get_config(source='running')
    print(config)

    # Configure interface (YANG model)
    config_xml = '''
    <config>
      <interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
        <interface>
          <name>GigabitEthernet1</name>
          <description>Configured via NETCONF</description>
          <enabled>true</enabled>
        </interface>
      </interfaces>
    </config>
    '''

    reply = m.edit_config(target='running', config=config_xml)
    print(reply)
```

---

### Ansible

**Inventory File:**

```ini
# inventory.ini
[routers]
router1 ansible_host=192.168.1.1
router2 ansible_host=192.168.1.2

[switches]
switch1 ansible_host=192.168.1.10
switch2 ansible_host=192.168.1.11

[network:children]
routers
switches

[network:vars]
ansible_network_os=ios
ansible_connection=network_cli
ansible_user=admin
ansible_password=password
ansible_become=yes
ansible_become_method=enable
ansible_become_password=enable_password
```

**Playbook (Configure VLANs):**

```yaml
# configure_vlans.yml
---
- name: Configure VLANs on switches
  hosts: switches
  gather_facts: no

  tasks:
    - name: Create VLANs
      ios_vlan:
        vlan_id: "{{ item.id }}"
        name: "{{ item.name }}"
        state: present
      loop:
        - { id: 10, name: "Sales" }
        - { id: 20, name: "Engineering" }
        - { id: 30, name: "HR" }

    - name: Configure trunk ports
      ios_l2_interface:
        name: "{{ item }}"
        mode: trunk
        trunk_allowed_vlans: 10,20,30
      loop:
        - GigabitEthernet1/0/1
        - GigabitEthernet1/0/2

    - name: Save configuration
      ios_command:
        commands:
          - write memory
```

**Run Playbook:**

```bash
$ ansible-playbook -i inventory.ini configure_vlans.yml

PLAY [Configure VLANs on switches] ************************************

TASK [Create VLANs] ***************************************************
changed: [switch1] => (item={'id': 10, 'name': 'Sales'})
changed: [switch1] => (item={'id': 20, 'name': 'Engineering'})
changed: [switch1] => (item={'id': 30, 'name': 'HR'})
changed: [switch2] => (item={'id': 10, 'name': 'Sales'})
...

PLAY RECAP ************************************************************
switch1: ok=3 changed=2 unreachable=0 failed=0
switch2: ok=3 changed=2 unreachable=0 failed=0
```

---

## 🔧 Troubleshooting e Ferramentas

### Camada 1 (Physical)

```bash
# Show interface status
Switch# show interfaces status

Port      Name               Status       Vlan       Duplex  Speed
Gi1/0/1   Uplink             connected    trunk      a-full  a-1000
Gi1/0/2   PC-Sales-01        connected    10         a-full  a-100
Gi1/0/3                      notconnect   1          auto    auto

# Show interface errors
Switch# show interfaces GigabitEthernet1/0/1

  5 minute input rate 12000 bits/sec, 8 packets/sec
  5 minute output rate 34000 bits/sec, 20 packets/sec

  0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
  0 output errors, 0 collisions, 0 interface resets
```

**Common Issues:**

```yaml
Cable Problems:
  - No link light: Bad cable, wrong cable type
  - CRC errors: EMI interference, damaged cable
  - Collisions: Duplex mismatch

Duplex Mismatch:
  - One side auto, other side fixed
  - Symptoms: Slow performance, errors
  - Fix: Configure both sides manually

  Switch(config-if)# duplex full
  Switch(config-if)# speed 1000
```

---

### Camada 2 (Data Link)

```bash
# Show MAC address table
Switch# show mac address-table

          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5
  10    1111.2222.3333    DYNAMIC     Gi1/0/6
  20    4444.5555.6666    DYNAMIC     Gi1/0/7

# Show VLANs
Switch# show vlan brief

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/1, Gi1/0/2
10   Sales                            active    Gi1/0/5, Gi1/0/6
20   Engineering                      active    Gi1/0/7, Gi1/0/8

# Show spanning tree
Switch# show spanning-tree

VLAN0010
  Spanning tree enabled protocol rstp
  Root ID    Priority    32778
             Address     aaaa.bbbb.cccc
             Cost        4
             Port        1 (GigabitEthernet1/0/1)
```

---

### Camada 3 (Network)

```bash
# Show routing table
Router# show ip route

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

C     10.0.0.0/24 is directly connected, GigabitEthernet0/0
L     10.0.0.1/32 is directly connected, GigabitEthernet0/0
S     172.16.0.0/16 [1/0] via 10.0.0.254
O     192.168.10.0/24 [110/20] via 10.0.0.254, 00:05:23, GigabitEthernet0/0
S*    0.0.0.0/0 [1/0] via 192.168.1.1

# Ping
Router# ping 8.8.8.8

Type escape sequence to abort.
Sending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:
!!!!!
Success rate is 100 percent (5/5), round-trip min/avg/max = 12/15/20 ms

# Traceroute
Router# traceroute 8.8.8.8

Type escape sequence to abort.
Tracing the route to 8.8.8.8

  1 192.168.1.1 4 msec 4 msec 4 msec
  2 10.0.0.1 12 msec 8 msec 8 msec
  3 142.250.1.1 16 msec 12 msec 16 msec
  4 8.8.8.8 20 msec * 16 msec
```

---

### Packet Capture (tcpdump/Wireshark)

```bash
# Capture on interface
$ sudo tcpdump -i eth0

# Capture specific host
$ sudo tcpdump host 192.168.1.100

# Capture specific port
$ sudo tcpdump port 80

# Capture and save to file
$ sudo tcpdump -i eth0 -w capture.pcap

# Read from file
$ tcpdump -r capture.pcap

# Filter by protocol
$ sudo tcpdump icmp
$ sudo tcpdump tcp port 443

# Advanced filter (HTTP GET requests)
$ sudo tcpdump -i eth0 -s 0 -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)'
```

**Wireshark Filters:**

```
# Display filters
ip.addr == 192.168.1.100
tcp.port == 443
http.request.method == "GET"
dns.qry.name contains "google"

# Follow TCP stream
tcp.stream eq 0

# Extract HTTP objects
File → Export Objects → HTTP
```

---

## 📊 Tabelas de Referência

### Common Ports

| Port     | Protocol | Service    | Security Notes                |
| -------- | -------- | ---------- | ----------------------------- |
| 20, 21   | TCP      | FTP        | Plaintext, use SFTP instead   |
| 22       | TCP      | SSH        | Secure, recommended           |
| 23       | TCP      | Telnet     | Plaintext, never use          |
| 25       | TCP      | SMTP       | Email sending                 |
| 53       | UDP/TCP  | DNS        | Vulnerable to amplification   |
| 67, 68   | UDP      | DHCP       | Server (67), Client (68)      |
| 69       | UDP      | TFTP       | Plaintext, no authentication  |
| 80       | TCP      | HTTP       | Plaintext, use HTTPS          |
| 110      | TCP      | POP3       | Email retrieval, use TLS      |
| 123      | UDP      | NTP        | Time sync, use authentication |
| 143      | TCP      | IMAP       | Email, use TLS                |
| 161, 162 | UDP      | SNMP       | Use SNMPv3 only               |
| 443      | TCP      | HTTPS      | Secure HTTP                   |
| 514      | UDP      | Syslog     | Logging                       |
| 3389     | TCP      | RDP        | Windows remote desktop        |
| 3306     | TCP      | MySQL      | Database                      |
| 5432     | TCP      | PostgreSQL | Database                      |
| 6379     | TCP      | Redis      | Database                      |
| 8080     | TCP      | HTTP-Alt   | Web proxy                     |

---

### Subnetting Quick Reference

| CIDR | Mask            | Hosts    | Networks (from /24) |
| ---- | --------------- | -------- | ------------------- |
| /30  | 255.255.255.252 | 2        | 64                  |
| /29  | 255.255.255.248 | 6        | 32                  |
| /28  | 255.255.255.240 | 14       | 16                  |
| /27  | 255.255.255.224 | 30       | 8                   |
| /26  | 255.255.255.192 | 62       | 4                   |
| /25  | 255.255.255.128 | 126      | 2                   |
| /24  | 255.255.255.0   | 254      | 1                   |
| /23  | 255.255.254.0   | 510      | -                   |
| /22  | 255.255.252.0   | 1022     | -                   |
| /21  | 255.255.248.0   | 2046     | -                   |
| /20  | 255.255.240.0   | 4094     | -                   |
| /16  | 255.255.0.0     | 65534    | -                   |
| /8   | 255.0.0.0       | 16777214 | -                   |

---

## 🔗 Links e Referências

**Documentação Oficial:**

- Cisco Learning Network: https://learningnetwork.cisco.com/
- Cisco Command Reference: https://www.cisco.com/c/en/us/support/index.html
- RFC Editor: https://www.rfc-editor.org/

**Ferramentas:**

- Packet Tracer: https://www.netacad.com/courses/packet-tracer
- GNS3: https://www.gns3.com/
- Wireshark: https://www.wireshark.org/

**Aprendizado:**

- Subnet Calculator: https://www.subnet-calculator.com/
- CCNA Study Guide: https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna.html

---

## 📝 Changelog

| Data       | Versão | Alteração                |
| ---------- | ------ | ------------------------ |
| 2024-02-10 | 1.0    | Documento inicial criado |

---

> **💡 Dica final:** Redes é **fundação** para DevSecOps. Sem entender TCP/IP, subnetting e roteamento, você não consegue: configurar firewalls corretamente, interpretar logs de segurança, ou fazer threat hunting efetivo. Invista tempo dominando esses conceitos!

**Ordem de estudo recomendada:**

```
1. Fundamentos (OSI, TCP/UDP, Portas) → 1 semana
2. Subnetting (CIDR, VLSM) → 1 semana
3. Switching (VLANs, STP) → 1 semana
4. Routing (Static, OSPF) → 2 semanas
5. Serviços (DHCP, DNS, NAT) → 1 semana
6. Segurança (ACL, VPN, Layer 2) → 2 semanas
7. Automação (Python, Ansible) → 2 semanas

Total: ~10 semanas para base sólida
```

```

Esta documentação fornece um guia completo e prático sobre Redes, cobrindo desde fundamentos até configurações avançadas de segurança e automação. Use como referência para estudos de CCNA e operações de rede em ambientes DevSecOps! 🌐🔒
```
