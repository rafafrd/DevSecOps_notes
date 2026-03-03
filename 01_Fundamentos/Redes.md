---
title: "Redes — Parte 2: Cloud-Native e DevSecOps"
tags:
  - networking
  - cloud
  - aws
  - azure
  - gcp
  - kubernetes
  - docker
  - zero-trust
  - devsecops
  - service-mesh
  - istio
  - firewall-api
  - ztna
  - microsegmentacao
aliases:
  - "Redes Cloud Native"
  - "Kubernetes Networking"
  - "Zero Trust Networks"
created: 2026-03-02
updated: 2026-03-02
status: ativo
nivel: avancado
parte: 2
prerequisito: "Redes - Fundamentos para DevSecOps e Cybersecurity"
---

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

| **Camada**                         | **Detalhes**                                                                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **7. Application (Aplicação)**     | - Protocolos: HTTP, HTTPS, FTP, SSH, DNS, SMTP<br><br>- Interface com usuário<br><br>- Segurança: WAF, DLP, Email Gateway                        |
| **6. Presentation (Apresentação)** | - Criptografia/Descriptografia<br><br>- Compressão de dados<br><br>- Formatos: ASCII, JPEG, MPEG                                                 |
| **5. Session (Sessão)**            | - Estabelecimento/Encerramento de sessões<br><br>- Sincronização<br><br>- Protocolos: NetBIOS, RPC                                               |
| **4. Transport (Transporte)**      | - Protocolos: TCP, UDP<br><br>- Portas (0-65535)<br><br>- Segmentação e Reassembly<br><br>- Segurança: Firewall Stateful                         |
| **3. Network (Rede)**              | - Protocolos: IP, ICMP, OSPF, BGP<br><br>- Roteamento (path selection)<br><br>- Endereçamento lógico (IP)<br><br>- Segurança: Firewall, ACL, IPS |
| **2. Data Link (Enlace de Dados)** | - Protocolos: Ethernet, Wi-Fi (802.11)<br><br>- MAC Address<br><br>- Switching<br><br>- Segurança: Port Security, DAI, DHCP Snooping             |
| **1. Physical (Física)**           | - Cabos: UTP, Fibra<br><br>- Sinais elétricos/ópticos<br><br>- Hubs, Repeaters<br><br>- Segurança: Acesso físico, Cable locks                    |

---

>	PDU (Protocol Data Unit) = é o termo técnico para definir a unidade básica de dados que é transmitida em uma camada específica do modelo OSI, Conforme os dados descem pelas camadas do modelo OSI (um processo chamado **encapsulamento**), cada camada adiciona suas próprias informações de controle (cabeçalhos) à PDU da camada anterior.

| **Camada OSI**                        | **Nome da PDU**                           | **O que acontece aqui?**                                            |
| ------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------- |
| **Aplicação / Apresentação / Sessão** | **Dados**                                 | A informação bruta gerada pelo software (ex: o texto de um e-mail). |
| **Transporte**                        | **Segmento** (TCP) ou **Datagrama** (UDP) | Adiciona portas de origem/destino e controle de fluxo.              |
| **Rede**                              | **Pacote**                                | Adiciona os endereços IP (origem e destino).                        |
| **Enlace**                            | **Quadro** (ou _Frame_)                   | Adiciona o endereço físico (MAC Address) e detecção de erros.       |
| **Física**                            | **Bits**                                  | Os dados são convertidos em sinais elétricos, ópticos ou rádio.     |

--- 
## Resumo: Pilha (stack) TCP/IP

![TCP/IP model layers diagram, gerada com IA|363](https://encrypted-tbn1.gstatic.com/licensed-image?q=tbn:ANd9GcRE4aeopFoZtWtqozaj9HjEzsCgaVS1ppiwL7BBgjRt0OP_gEul1hu3K-Y3WWm-jtd7kDD7nQwIkQwl-fQ7BGVu5e5IzycldbMCnh0K7FxQkEvjdz8)

O modelo TCP/IP é a arquitetura base da internet, estruturada em **4 camadas**. Ele define como os dados são empacotados, endereçados, transmitidos, roteados e recebidos.

### 4. Camada de Aplicação (Application)

- **Função:** Ponto de interação entre os aplicativos do usuário e a rede. Fornece os serviços de rede diretamente para as aplicações.
    
- **Unidade de Dados (PDU):** Dado / Mensagem.
    
- **Protocolos Principais:** HTTP/HTTPS (web), DNS (resolução de nomes), SMTP/IMAP (email), FTP (arquivos), SSH.
    

### 3. Camada de Transporte (Transport)

- **Função:** Estabelece a comunicação fim-a-fim entre as aplicações host. Gerencia a multiplexação (através de portas), controle de fluxo e, dependendo do protocolo, a confiabilidade.
    
- **Unidade de Dados (PDU):** Segmento (se for TCP) ou Datagrama (se for UDP).
    
- **Endereçamento:** Portas lógicas (ex: porta 80, 443, 53).
    
- **Protocolos Principais:**
    
    - **TCP:** Confiável, orientado a conexão, verifica erros, garante a entrega e a ordem dos dados.
        
    - **UDP:** Rápido, não orientado a conexão, não garante entrega ou ordem (ideal para streaming, VoIP, jogos online).
        

### 2. Camada de Internet (Internet / Rede)

- **Função:** Roteamento de dados. Define o melhor caminho e encaminha os dados através de múltiplas redes até o destino final, independentemente da rota.
    
- **Unidade de Dados (PDU):** Pacote.
    
- **Endereçamento:** Endereço IP (Lógico).
    
- **Protocolos Principais:** IPv4, IPv6, ICMP (usado pelo utilitário `ping`), IPSec.
    

### 1. Camada de Acesso à Rede (Network Access / Link)

- **Função:** Trata da interface física entre o dispositivo e o meio de transmissão (cabo, fibra, rádio). Converte pacotes em quadros e, posteriormente, em sinais elétricos/luminosos/ondas.
    
- **Unidade de Dados (PDU):** Quadro (Frame) no enlace lógico, que é convertido em Bits no meio físico.
    
- **Endereçamento:** Endereço MAC (Físico).
    
- **Tecnologias/Padrões Principais:** Ethernet, Wi-Fi (IEEE 802.11), ARP.
    
| **Camada**           | **Função Principal**      | **Unidade de Dados (PDU)** | **Endereçamento**     | **Exemplos de Protocolos/Padrões** |
| -------------------- | ------------------------- | -------------------------- | --------------------- | ---------------------------------- |
| **4. Aplicação**     | Serviços para aplicativos | Dado / Mensagem            | N/A                   | HTTP, DNS, FTP                     |
| **3. Transporte**    | Comunicação fim-a-fim     | Segmento / Datagrama       | Porta de Serviço      | TCP, UDP                           |
| **2. Internet**      | Roteamento entre redes    | Pacote                     | Endereço IP (Lógico)  | IPv4, IPv6, ICMP                   |
| **1. Acesso à Rede** | Transmissão física local  | Quadro (Frame) / Bits      | Endereço MAC (Físico) | Ethernet, Wi-Fi, ARP               |


---

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

---


# 🌐 Redes — Parte 2: Cloud-Native, Kubernetes e Zero Trust

> [!NOTE] Sobre este documento Esta é a **Parte 2** do guia de redes. Ela pressupõe que você já domina os conceitos da Parte 1 (OSI, TCP/IP, VLANs, Roteamento, ACLs, IPsec e automação básica com Ansible/Netmiko). O foco aqui é o que realmente importa para um engenheiro **Cloud-Native e DevSecOps** moderno.

---

## 📋 Índice

- [[#8. Redes em Cloud AWS / Azure / GCP]]
- [[#9. Redes em Containers e Kubernetes]]
- [[#10. Zero Trust Architecture ZTA]]
- [[#11. Automação de Firewalls e APIs de Segurança]]

---

## 8. Redes em Cloud (AWS / Azure / GCP)

### 8.1 VPC — Virtual Private Cloud

Uma **VPC** é a sua rede privada isolada dentro de um provedor de cloud. Pense nela como o equivalente ao seu datacenter físico, mas inteiramente definido por software (SDN em escala global).

```yaml
Analogia On-Premises → Cloud:

  Datacenter físico   ↔   VPC (Virtual Private Cloud)
  VLAN Corporativa    ↔   Subnet privada
  VLAN DMZ            ↔   Subnet pública
  Firewall de borda   ↔   Security Group / NACL / WAF
  Router de borda     ↔   Internet Gateway (IGW)
  NAT corporativo     ↔   NAT Gateway (gerenciado)
  MPLS / WAN          ↔   VPC Peering / Transit Gateway
  Servidor de DNS     ↔   Route 53 / Azure DNS / Cloud DNS
```

**Arquitetura típica de VPC em produção (3 camadas):**

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  VPC: 10.0.0.0/16  (AWS Region: sa-east-1)              │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Internet Gateway (IGW)                          │   │
│  └────────────────────┬─────────────────────────────┘   │
│                       │                                 │
│  ┌────────────────────▼─────────────────────────────┐   │
│  │  Subnet PÚBLICA  10.0.1.0/24  (AZ-a)             │   │
│  │  Subnet PÚBLICA  10.0.2.0/24  (AZ-b)             │   │
│  │                                                  │   │
│  │  Recursos: ALB, NAT Gateway, Bastion Host        │   │
│  └────────────────────┬─────────────────────────────┘   │
│                       │ (via NAT Gateway)               │
│  ┌────────────────────▼─────────────────────────────┐   │
│  │  Subnet PRIVADA  10.0.10.0/24  (AZ-a)            │   │
│  │  Subnet PRIVADA  10.0.11.0/24  (AZ-b)            │   │
│  │                                                  │   │
│  │  Recursos: EC2 (App), EKS Workers, Lambda (VPC)  │   │
│  └────────────────────┬─────────────────────────────┘   │
│                       │ (sem acesso à internet)         │
│  ┌────────────────────▼─────────────────────────────┐   │
│  │  Subnet ISOLADA  10.0.20.0/24  (AZ-a)            │   │
│  │  Subnet ISOLADA  10.0.21.0/24  (AZ-b)            │   │
│  │                                                  │   │
│  │  Recursos: RDS, ElastiCache, DocumentDB          │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

### 8.2 Tabelas de Roteamento: IGW vs NAT Gateway

|Componente|Direção|Tipo de IP|Use Case|
|---|---|---|---|
|**Internet Gateway (IGW)**|Bidirecional (in/out)|IP Público|Recursos que precisam ser acessíveis da internet (ALB, Bastion)|
|**NAT Gateway**|Saída apenas (outbound)|IP Privado → Elástico|Recursos privados que precisam acesso à internet (atualizações de OS, chamadas de API externas)|
|**VPC Peering**|Interna entre VPCs|IP Privado|Comunicação entre VPCs da mesma ou diferente conta AWS|
|**Transit Gateway**|Hub-and-Spoke entre VPCs|IP Privado|Conectar dezenas de VPCs e VPNs centralizadamente|
|**VPC Endpoint (Gateway)**|Interna para serviços AWS|IP Privado|Acessar S3/DynamoDB sem sair da rede AWS|
|**VPC Endpoint (Interface)**|Interna para serviços AWS|IP Privado (ENI)|Acessar qualquer serviço AWS via PrivateLink|

**Tabela de rotas — Subnet Pública:**

```yaml
# Route Table: rtb-public
# Associada a: subnet-public-a (10.0.1.0/24), subnet-public-b (10.0.2.0/24)

Destination     Target              Description
10.0.0.0/16     local               Comunicação interna da VPC
0.0.0.0/0       igw-xxxxxxxxx       Acesso à internet via IGW
```

**Tabela de rotas — Subnet Privada:**

```yaml
# Route Table: rtb-private-a
# Associada a: subnet-private-a (10.0.10.0/24)

Destination     Target              Description
10.0.0.0/16     local               Comunicação interna da VPC
0.0.0.0/0       nat-xxxxxxxxx       Saída para internet via NAT Gateway (AZ-a)
```

**Tabela de rotas — Subnet Isolada (Banco de Dados):**

```yaml
# Route Table: rtb-isolated
# Associada a: subnet-db-a (10.0.20.0/24), subnet-db-b (10.0.21.0/24)

Destination     Target              Description
10.0.0.0/16     local               APENAS comunicação interna da VPC
# Sem rota default → sem acesso à internet em nenhuma direção
```

---

### 8.3 Security Groups (Stateful) vs NACLs (Stateless)

> [!WARNING] Diferença Crítica **Security Groups** operam no nível da **instância/ENI** e são **stateful** (se você permite saída, a resposta entra automaticamente). **NACLs** operam no nível da **subnet** e são **stateless** (você DEVE criar regras de entrada E saída explicitamente, incluindo portas efêmeras).

|Critério|Security Group|NACL|
|---|---|---|
|**Nível de aplicação**|Instância / ENI|Subnet|
|**Estado (Stateful?)**|✅ Stateful|❌ Stateless|
|**Regras de retorno**|Automáticas|Devem ser explícitas|
|**Tipo de regras**|Apenas ALLOW|ALLOW e DENY|
|**Ordem de avaliação**|Todas as regras (OR)|Numeradas (top-down, first match)|
|**Avaliação de saída**|Regras de saída avaliadas|Regras de saída avaliadas separadamente|
|**Default comportamento**|Nega tudo (sem regras)|Permite tudo (NACL padrão)|
|**Escopo de aplicação**|VMs, RDS, Lambda, etc.|Toda subnet|
|**Uso ideal**|Controle granular por serviço|Defesa em profundidade por subnet|

**Security Group — Exemplo para servidor web:**

```yaml
# Security Group: sg-web-servers
# Aplicado a: instâncias EC2 da camada de aplicação

Inbound Rules:
  Type    Protocol  Port Range  Source            Description
  HTTPS   TCP       443         sg-alb-id         Apenas do ALB (não direto da internet)
  SSH     TCP       22          10.0.1.0/24        Apenas da subnet do Bastion
  Custom  TCP       8080        sg-alb-id          Health checks do ALB

Outbound Rules:
  Type    Protocol  Port Range  Destination       Description
  HTTPS   TCP       443         0.0.0.0/0          Atualizações OS, APIs externas
  TCP     TCP       5432        sg-database-id     Acesso ao RDS PostgreSQL
  DNS     UDP       53          0.0.0.0/0          Resolução DNS
```

**NACL — Exemplo para subnet privada (stateless = precisa de regras de retorno):**

```yaml
# NACL: nacl-private
# Associada a: subnet-private-a (10.0.10.0/24)

Inbound Rules:
  Rule#  Type    Protocol  Port        Source            Action
  100    HTTPS   TCP       443         10.0.1.0/24        ALLOW   # Do ALB
  110    Custom  TCP       8080        10.0.1.0/24        ALLOW   # Health check
  120    TCP     TCP       1024-65535  0.0.0.0/0          ALLOW   # Portas efêmeras (retorno NAT!)
  *      All     All       All         0.0.0.0/0          DENY

Outbound Rules:
  Rule#  Type    Protocol  Port        Destination       Action
  100    TCP     TCP       443         0.0.0.0/0          ALLOW   # Saída para internet (via NAT)
  110    TCP     TCP       5432        10.0.20.0/24       ALLOW   # Para subnet de banco
  120    TCP     TCP       1024-65535  10.0.1.0/24        ALLOW   # Portas efêmeras de retorno!
  *      All     All       All         0.0.0.0/0          DENY
```

> [!NOTE] Portas Efêmeras e NACLs Como NACLs são stateless, o tráfego de **retorno** de conexões TCP usa portas efêmeras (1024-65535). Você **sempre** deve permitir essas portas nas regras de NACL. Esquecer isso é a causa #1 de problemas com NACLs.

---

### 8.4 Load Balancers: L4 (NLB) vs L7 (ALB) vs WAF

```
Internet
    │
    ▼
┌─────────────┐      ┌─────────────────────────────────────┐
│ AWS WAF     │─────▶│ ALB (Application Load Balancer - L7)│
│ (Camada 7)  │      │ Regras: path, host, headers, JWT    │
└─────────────┘      └────────────────┬────────────────────┘
                                      │ Routing inteligente
                       ┌──────────────┼──────────────┐
                       ▼              ▼              ▼
                  /api/*          /auth/*         /static/*
              Target Group 1  Target Group 2  Target Group 3
              (ECS - API)     (Lambda - Auth)  (S3 via endpoint)

                    OU (para TCP/UDP de alta performance)

                     ┌────────────────────────┐
                     │ NLB (Network LB - L4)  │
                     │ TCP/UDP, IP estático   │
                     └────────────┬───────────┘
                                  │ Pass-through (preserva IP origem)
                       ┌──────────┼──────────┐
                       ▼          ▼          ▼
                    EC2-01     EC2-02     EC2-03
```

|Critério|NLB (Layer 4)|ALB (Layer 7)|WAF|
|---|---|---|---|
|**Camada OSI**|Transporte (L4)|Aplicação (L7)|Aplicação (L7)|
|**Protocolos**|TCP, UDP, TLS|HTTP, HTTPS, gRPC, WebSocket|HTTP, HTTPS|
|**Roteamento baseado em**|IP:Porta|Path, Host, Headers, Query String, JWT|Regras de segurança|
|**Performance**|⚡ Extrema (milhões de req/s)|Alta (100k req/s)|Adiciona latência (~1-2ms)|
|**IP Estático**|✅ Sim|❌ Não (DNS dinâmico)|N/A|
|**IP de origem preservado**|✅ Sim|❌ Usa X-Forwarded-For|N/A|
|**SSL Termination**|✅ Opcional (passthrough)|✅ Nativo|N/A|
|**Proteção contra ataques**|Básica (L4)|Básica|SQLi, XSS, OWASP Top 10|
|**Use case típico**|VoIP, Gaming, DBs, Kubernetes NodePort|APIs REST, microserviços web|Proteção de aplicações web|
|**Custo**|Médio|Médio|Alto (por regra + req)|

**Exemplo de regra ALB — roteamento por path e header:**

```yaml
# ALB Listener Rule (prioridade = menor número = maior prioridade)

Rule Priority 1:
  Conditions:
    - Path pattern: /api/v1/*
    - HTTP Header: X-API-Version = "v1"
  Actions:
    - Forward to: tg-api-v1

Rule Priority 2:
  Conditions:
    - Path pattern: /api/*
    - HTTP method: OPTIONS
  Actions:
    - Return fixed response: 200 (CORS preflight)

Rule Priority 3:
  Conditions:
    - Path pattern: /admin/*
    - Source IP: NOT 10.0.0.0/8
  Actions:
    - Return fixed response: 403 (bloqueia acesso externo ao admin)

Rule Priority 4 (Default):
  Actions:
    - Forward to: tg-frontend
```

---

### 8.5 Conectividade Híbrida e Multi-Cloud

```yaml
Opções de Conectividade On-Premises → Cloud:

Site-to-Site VPN:
  - IPsec sobre internet pública
  - Fácil de configurar
  - Bandwidth: até 1.25 Gbps
  - Latência: variável (internet)
  - Custo: baixo
  - Use: Prova de conceito, workloads não críticos

AWS Direct Connect / Azure ExpressRoute / GCP Interconnect:
  - Conexão física dedicada (fibra)
  - Latência: consistente e baixa (< 10ms)
  - Bandwidth: 1 Gbps, 10 Gbps, 100 Gbps
  - Custo: alto (circuito dedicado)
  - Use: Produção crítica, migração de dados em massa

Transit Gateway (AWS) / Virtual WAN (Azure) / Cloud Router (GCP):
  - Hub centralizado para conectar múltiplas VPCs + VPN + Direct Connect
  - Suporta roteamento transitivo (VPC-A → TGW → VPC-B)
  - Simplifica topologia (elimina VPC Peering em malha)
```

---

## 9. Redes em Containers e Kubernetes

### 9.1 Docker Network Drivers

```yaml
Bridge (Padrão):
  Topologia: Container ↔ docker0 bridge ↔ Host NIC ↔ Rede externa
  IP Range: 172.17.0.0/16 (padrão)
  Comunicação entre containers: Via IP ou nome (redes user-defined)
  Acesso externo: Via port mapping (-p hostPort:containerPort)
  Isolamento: Alto (containers em bridges diferentes não se comunicam)
  Use case: Desenvolvimento local, containers no mesmo host

Host:
  Topologia: Container usa diretamente o namespace de rede do host
  IP Range: Mesmo IP do host
  Performance: Máxima (sem overhead de bridge)
  Isolamento: Nenhum (container compartilha stack de rede do host)
  Use case: Alta performance, network tools, monitoramento

Overlay:
  Topologia: Rede virtual sobre múltiplos hosts Docker (Swarm/Kubernetes)
  Encapsulamento: VXLAN (UDP 4789)
  Use case: Container multi-host, Docker Swarm, base para k8s CNI
  Isolamento: Por network namespace

None:
  Container sem nenhuma interface de rede
  Use case: Batch jobs que não precisam de rede, security-sensitive workloads

Macvlan:
  Container recebe MAC address próprio na rede física
  Aparece como dispositivo físico para o switch
  Use case: Migração de VMs, integrações com sistemas legados que usam MAC filtering
```

**Exemplo prático Docker networking:**

```bash
# Criar rede bridge customizada
docker network create --driver bridge \
  --subnet 172.20.0.0/16 \
  --ip-range 172.20.240.0/20 \
  --gateway 172.20.0.1 \
  minha-rede-app

# Rodar containers na mesma rede (comunicam por nome!)
docker run -d --name postgres \
  --network minha-rede-app \
  -e POSTGRES_PASSWORD=secret \
  postgres:15

docker run -d --name api \
  --network minha-rede-app \
  -p 8080:8080 \
  -e DB_HOST=postgres \  # <-- Resolve pelo nome do container!
  minha-api:latest

# Inspecionar rede
docker network inspect minha-rede-app

# Ver IPs atribuídos
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' postgres
# Output: 172.20.240.0
```

---

### 9.2 Kubernetes Networking: O Modelo Fundamental

> [!NOTE] As 4 Regras do Kubernetes Networking O K8s impõe um modelo de rede flat com 4 regras fundamentais:
> 
> 1. Todo Pod pode se comunicar com qualquer outro Pod **sem NAT**
> 2. Todo nó pode se comunicar com qualquer Pod **sem NAT**
> 3. O IP que um Pod vê de si mesmo é o mesmo que outros Pods veem
> 4. Pods têm IPs **efêmeros** — use Services para endereçamento estável

```
┌──────────────────────────────────────────────────────────────────┐
│ Kubernetes Cluster                                               │
│                                                                  │
│  ┌────────── Node 1 (10.0.1.10) ──────────┐                      │
│  │                                        │                      │
│  │  ┌──────────┐  ┌──────────┐            │                      │
│  │  │ Pod A    │  │ Pod B    │            │                      │
│  │  │10.244.1.2│  │10.244.1.3│            │                      │
│  │  └────┬─────┘  └────┬─────┘            │                      │
│  │       └──────┬──────┘                  │                      │
│  │         ┌────▼─────┐                   │                      │
│  │         │ cbr0     │ (Container Bridge)│                      │
│  │         │10.244.1.1│                   │                      │
│  │         └────┬─────┘                   │                      │
│  │              │ eth0 (10.0.1.10)        │                      │
│  └──────────────┼─────────────────────────┘                      │
│                 │                                                │
│         [CNI Plugin: flannel/calico/cilium]                      │
│         VXLAN / BGP / eBPF routing                               │
│                 │                                                │
│  ┌──────────────┼────────────────────────┐                       │
│  │              │ eth0 (10.0.1.11)       │                       │
│  │         ┌────▼─────┐                  │                       │
│  │         │ cbr0     │                  │                       │
│  │         │10.244.2.1│                  │                       │
│  │         └────┬─────┘                  │                       │
│  │  ┌──────────┐│  ┌──────────┐          │                       │
│  │  │ Pod C    ││  │ Pod D    │          │                       │
│  │  │10.244.2.2││  │10.244.2.3│          │                       │
│  │  └──────────┘   └──────────┘          │                       │
│  └────────── Node 2 (10.0.1.11) ─────────┘                       │
└──────────────────────────────────────────────────────────────────┘
```

---

### 9.3 CNI — Container Network Interface

O **CNI** é a especificação que define como plugins de rede configuram interfaces em containers. Quando um Pod é criado, o kubelet chama o plugin CNI para provisionar a rede.

|CNI Plugin|Mecanismo de Roteamento|Network Policy|Performance|Use Case|
|---|---|---|---|---|
|**Flannel**|VXLAN (Overlay)|❌ Não nativo|Boa|Simplicidade, ambientes menores|
|**Calico**|BGP (nativo) ou VXLAN|✅ Nativo (L3)|Excelente|Produção, policy avançada|
|**Cilium**|eBPF (sem iptables)|✅ L3/L4/L7|Excepcional|Cloud-native, observabilidade|
|**Weave**|VXLAN / Criptografado|✅ Básico|Boa|Multi-cloud, criptografia automática|
|**AWS VPC CNI**|ENI nativa (sem overlay)|Via SG para Pods|Máxima (nativa)|EKS em produção|
|**Azure CNI**|VNET nativa|Via NSG|Máxima (nativa)|AKS em produção|

---

### 9.4 Kubernetes Services — Tipos e Casos de Uso

```yaml
ClusterIP (Padrão):
  Escopo: Apenas interno ao cluster
  IP Virtual: Sim (kube-proxy / iptables / ipvs)
  DNS interno: <service>.<namespace>.svc.cluster.local
  Use case: Comunicação entre microserviços
  Exemplo:
    postgres.database.svc.cluster.local:5432

NodePort:
  Escopo: Expõe um port estático em todos os nós
  IP Virtual: ClusterIP + porta do nó (30000-32767)
  Use case: Desenvolvimento, integração com LB externo legado
  Problema: Expõe portas em todos os nós, difícil de gerenciar

LoadBalancer:
  Escopo: Externo (provisionado pelo cloud provider)
  IP Virtual: IP público do cloud LB (NLB/ALB)
  Use case: Expor serviços para internet em cloud
  Desvantagem: 1 IP público por Service = caro em escala

ExternalName:
  Escopo: Alias DNS para serviço externo
  Use case: Integrar serviços externos (ex: RDS, Azure SQL)
  Exemplo: api-externa.svc → meu-rds.amazonaws.com
```

**Manifesto YAML — Service e Deployment:**

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-backend
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-backend
      tier: backend
  template:
    metadata:
      labels:
        app: api-backend
        tier: backend
    spec:
      containers:
        - name: api
          image: empresa/api:v2.1.0
          ports:
            - containerPort: 8080
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
---
# service-clusterip.yaml (comunicação interna)
apiVersion: v1
kind: Service
metadata:
  name: api-backend-svc
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: api-backend
    tier: backend
  ports:
    - protocol: TCP
      port: 80          # Porta que outros Pods usam
      targetPort: 8080  # Porta real do container
```

---

### 9.5 Ingress — O Proxy Reverso do Kubernetes

O **Ingress** consolida múltiplos Services num único ponto de entrada L7, eliminando o problema de criar um LoadBalancer por Service.

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  LoadBalancer Service (1 único IP público)              │
│  (provisionado pelo cloud provider para o Ingress)      │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Ingress Controller (ex: nginx, traefik, AWS ALB)       │
│                                                         │
│  Regras de roteamento:                                  │
│  app.empresa.com/api/*  → Service: api-backend-svc:80   │
│  app.empresa.com/auth/* → Service: auth-svc:80          │
│  app.empresa.com/*      → Service: frontend-svc:80      │
└────────────────────────┬────────────────────────────────┘
                         │ ClusterIP (L4)
             ┌───────────┼───────────┐
             ▼           ▼           ▼
          Pod API    Pod Auth   Pod Frontend
```

**Manifesto Ingress com TLS:**

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/use-regex: "true"
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "100"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - app.empresa.com
      secretName: tls-empresa-cert  # TLS gerenciado pelo cert-manager
  rules:
    - host: app.empresa.com
      http:
        paths:
          - path: /api/(.+)
            pathType: ImplementationSpecific
            backend:
              service:
                name: api-backend-svc
                port:
                  number: 80
          - path: /auth/(.+)
            pathType: ImplementationSpecific
            backend:
              service:
                name: auth-svc
                port:
                  number: 80
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend-svc
                port:
                  number: 80
```

---

### 9.6 Network Policies — Microsegmentação no Kubernetes

Por padrão, **todos os Pods se comunicam com todos**. NetworkPolicies mudam isso:

```yaml
# networkpolicy-api.yaml
# Regra: Pod "api-backend" só recebe tráfego do Ingress Controller
# e só envia para o postgres.

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-backend-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-backend

  policyTypes:
    - Ingress
    - Egress

  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: ingress-nginx  # Apenas do Ingress
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080

  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:                        # Permitir DNS (obrigatório!)
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
```

---

### 9.7 Service Mesh: Istio e mTLS Automático

> [!NOTE] O Problema que o Service Mesh Resolve Em uma arquitetura de microserviços, você tem dezenas de serviços se comunicando. Como garantir que a comunicação entre `service-A → service-B` seja: **autenticada** (é realmente o service-A?), **criptografada** (TLS mútuo), **autorizada** (service-A tem permissão?), **observável** (logs, métricas, traces)? Implementar isso em cada microserviço é inviável. O Service Mesh resolve isso **fora do código**.

```
┌──────────────────────────────────────────────────────────┐
│  Istio Control Plane                                     │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐                   │
│  │ istiod  │  │  Pilot  │  │ Citadel │                   │
│  │(config) │  │(routing)│  │ (certs) │                   │
│  └────┬────┘  └────┬────┘  └────┬────┘                   │
│       └─────────────┼───────────┘                        │
│                     │ xDS API (gRPC)                     │
└─────────────────────┼─────────────────────────────────── ┘
                      │ Distribui configuração e certificados
         ┌────────────┼────────────┐
         ▼            ▼            ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Pod A      │  │   Pod B      │  │   Pod C      │
│  ┌────────┐  │  │  ┌────────┐  │  │  ┌────────┐  │
│  │ app    │  │  │  │ app    │  │  │  │ app    │  │
│  └────────┘  │  │  └────────┘  │  │  └────────┘  │
│  ┌────────┐  │  │  ┌────────┐  │  │  ┌────────┐  │
│  │ Envoy  │  │  │  │ Envoy  │  │  │  │ Envoy  │  │
│  │(sidecar│  │  │  │(sidecar│  │  │  │(sidecar│  │
│  └────────┘  │  │  └────────┘  │  │  └────────┘  │
└──────┬───────┘  └───────┬──────┘  └───────┬──────┘
       │    mTLS (TLS Mútuo automático)     │
       └──────────────────┼─────────────────┘
                Toda comunicação é criptografada e
                autenticada com certificados SPIFFE/X.509
```

**Istio — Habilitando mTLS em um namespace:**

```yaml
# PeerAuthentication: define como o sidecar aceita conexões
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # STRICT = apenas mTLS, recusa plaintext
                  # PERMISSIVE = aceita mTLS e plaintext
                  # DISABLE = sem mTLS

---
# AuthorizationPolicy: controle de acesso granular L7
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: api-backend-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-backend
  action: ALLOW
  rules:
    - from:
        - source:
            # Apenas requests com identidade SPIFFE do frontend
            principals: ["cluster.local/ns/production/sa/frontend-sa"]
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/*"]
```

|Funcionalidade|Sem Service Mesh|Com Istio|
|---|---|---|
|**TLS entre serviços**|Implementar em cada app|Automático via sidecar|
|**Autenticação mútua**|Implementar em cada app|SPIFFE/X.509 automático|
|**Autorização L7**|Lógica na aplicação|Declarativa em YAML|
|**Observabilidade**|Instrumentar cada app|Automático (Kiali, Jaeger, Prometheus)|
|**Traffic shaping**|Não disponível|Canary, A/B, circuit breaking|
|**Retry/timeout**|No código|Declarativo por rota|
|**Overhead**|Nenhum|~5-10ms latência, ~50MB RAM/Pod|

---

## 10. Zero Trust Architecture (ZTA)

### 10.1 Fundamentos — "Never Trust, Always Verify"

> [!WARNING] A Grande Mudança de Paradigma O modelo de segurança tradicional é baseado em **perímetro**: confio em tudo dentro da rede, desconfio do que vem de fora (modelo castelo e fosso). O problema: uma vez que um atacante está **dentro** (via phishing, credencial comprometida, insider), ele tem acesso livre. Zero Trust assume que **a rede já está comprometida**.

```yaml
Modelo Tradicional (Perimeter-Based):
  Premissa: "Tudo dentro da rede é confiável"
  Realidade: Lateral movement irrestrito após comprometimento
  
  Internet → [Firewall] → Rede Interna (tudo liberado)
                               ├─ RH acessa servidor de Pagamentos ✓ (mas não deveria)
                               ├─ Dev acessa banco de Produção ✓ (mas não deveria)
                               └─ Impressora acessa controlador AD ✓ (mas não deveria!)

Modelo Zero Trust:
  Premissa: "Nunca confie, sempre verifique — independente da localização"
  
  Princípios NIST SP 800-207:
    1. Verify Explicitly: Autentique e autorize SEMPRE
       (usuário + dispositivo + contexto + comportamento)
    
    2. Use Least Privilege Access: Acesso mínimo necessário,
       just-in-time, just-enough-access (JIT/JEA)
    
    3. Assume Breach: Minimize blast radius, segmente acesso,
       monitore tudo, criptografe tudo (at rest + in transit)
```

**Arquitetura Zero Trust:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Policy Engine)                │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ Identity     │  │ Device       │  │ Policy Decision      │   │
│  │ Provider     │  │ Trust        │  │ Point (PDP)          │   │
│  │ (Okta, ADFS) │  │ (MDM, EDR)   │  │ "Autoriza ou nega?"  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          │ Sinal de confiança                   │
└──────────────────────────┼──────────────────────────────────────┘
                           │ Decisão de política
┌──────────────────────────▼──────────────────────────────────────┐
│                    DATA PLANE (Policy Enforcement)              │
│                                                                 │
│  [Usuário + Dispositivo] → [PEP: Proxy/Gateway] → [Recurso]     │
│                                                                 │
│  Cada request passa pelo PEP que consulta o PDP antes de        │
│  permitir o acesso. O acesso é por sessão, não por rede.        │
└─────────────────────────────────────────────────────────────────┘
```

---

### 10.2 Microsegmentação — Além de IP/Porta

A microsegmentação em Zero Trust não usa mais **"regra de firewall baseada em IP"** como unidade de controle. A identidade do **workload** é o novo perímetro.

|Critério|Segmentação Tradicional|Microsegmentação ZT|
|---|---|---|
|**Base da regra**|IP de origem/destino + Porta|Identidade de workload (SPIFFE, label, tag)|
|**Granularidade**|Por subnet ou VLAN|Por Pod, container, instância, função|
|**Dinâmica**|Estática (IP muda = regra quebra)|Dinâmica (segue o workload onde quer que rode)|
|**Escopo**|Tráfego Norte-Sul (entrante/sainte)|Inclui tráfego Leste-Oeste (lateral)|
|**Visibilidade**|Limitada (logs de firewall)|Total (flow logs por identidade, L7)|
|**Exemplo de regra**|`ALLOW 10.0.10.0/24:any → 10.0.20.5:5432`|`ALLOW workload:api-backend → workload:postgres, porta 5432`|

**Identidade de Workload — SPIFFE (SPIFFE IDs):**

```yaml
# SPIFFE (Secure Production Identity Framework for Everyone)
# Identificação criptográfica de workloads

SPIFFE ID format:
  spiffe://<trust-domain>/<workload-identifier>

Exemplos:
  spiffe://empresa.com/ns/production/sa/api-backend     # Pod Kubernetes
  spiffe://empresa.com/role/ec2/web-server-role         # EC2 com IAM Role
  spiffe://empresa.com/region/us-east-1/service/payments # AWS Lambda

Vantagem sobre IP:
  - IP 10.0.10.5 pode ser qualquer coisa (ECS task, Lambda, Pod)
  - SPIFFE ID é verificável criptograficamente via certificado X.509
  - Segue o workload independente de onde roda (on-prem, AWS, GCP)
```

**AWS — Exemplo de Microsegmentação por Tag:**

```bash
# Security Group baseado em tag de serviço (não IP)
# Usando referência de Security Group em vez de CIDR

# SG do banco de dados só aceita do SG da API
aws ec2 authorize-security-group-ingress \
  --group-id sg-database-0abc123 \
  --protocol tcp \
  --port 5432 \
  --source-group sg-api-backend-0def456

# Se a API escalar (novos IPs), as regras continuam válidas
# porque referenciam o SG, não o IP

# Listar regras do SG
aws ec2 describe-security-group-rules \
  --filters Name=group-id,Values=sg-database-0abc123 \
  --query 'SecurityGroupRules[*].{From:FromPort,To:ToPort,Source:ReferencedGroupInfo.GroupId}'
```

---

### 10.3 VPN Tradicional vs ZTNA

```yaml
VPN Tradicional (IPsec/SSL):
  Modelo: Usuário → VPN → Acesso à REDE TODA
  
  Problemas:
    1. Uma vez conectado, usuário vê toda a rede interna
    2. Dispositivo comprometido tem acesso irrestrito
    3. Atacante com credencial VPN = acesso de admin
    4. Sem visibilidade de qual app o usuário está acessando
    5. Performance ruim (tudo roteia pelo datacenter)
    6. "Hair-pinning": São Paulo → VPN USA → Internet → app no Brasil

  Cenário de ataque:
    Credencial VPN comprometida via phishing
    → Attacker entra na rede interna
    → Scan de rede revela 2000 hosts
    → Movimento lateral irrestrito
    → Acesso ao AD → Golden Ticket → Game over

ZTNA (Zero Trust Network Access):
  Modelo: Usuário → Identity Broker → Acesso apenas à APLICAÇÃO específica
  
  Fluxo:
    1. Usuário autentica (IdP: Okta, Azure AD) com MFA
    2. Dispositivo é verificado (MDM: postura, patch, antivírus)
    3. Contexto é avaliado (localização, horário, comportamento anômalo)
    4. Acesso concedido APENAS à aplicação específica solicitada
    5. Sessão monitorada continuamente

  Vantagens:
    ✓ Sem acesso à rede — apenas à aplicação
    ✓ App nunca exposta diretamente à internet
    ✓ Sessão por aplicação (não por rede)
    ✓ Dispositivo não gerenciado → acesso negado automaticamente
    ✓ Baseado em identidade, não em IP

  Produtos: Cloudflare Access, Zscaler ZTNA, Palo Alto Prisma Access,
            HashiCorp Boundary, Google BeyondCorp
```

**Diagrama comparativo:**

```
VPN Tradicional:
                     ┌──────────────────────────────┐
  User ──VPN──────▶  │ REDE INTERNA (tudo exposto)  │
  (credencial)       │  RH, Financeiro, Dev, Prod   │
                     │  Banco de Dados, AD, ERP...  │
                     └──────────────────────────────┘

ZTNA:
                     ┌──────────────────────────────┐
  User ──IdP+MFA──▶  │ Identity Broker (ZTNA)       │
  + Device Trust     │  Verifica: quem + dispositivo│
  + Contexto         │  + contexto + hora + local   │
                     └──────────────┬───────────────┘
                                    │ Acesso APENAS
                              ┌─────▼──────┐
                              │ App Jira   │  ← Só isso
                              └────────────┘
                              (não vê RH, não vê DB, não vê AD)
```

---

### 10.4 Identity-Aware Proxy (IAP) — Exemplo Prático

```bash
# Google Cloud IAP — Proteger aplicação interna sem VPN

# Habilitar IAP no backend service
gcloud compute backend-services update meu-backend-service \
  --global \
  --iap=enabled,oauth2-client-id=CLIENT_ID,oauth2-client-secret=SECRET

# Conceder acesso apenas ao usuário específico (não à rede!)
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=meu-backend-service \
  --member=user:dev@empresa.com \
  --role=roles/iap.httpsResourceAccessor

# O app nunca precisa ter IP público
# O acesso é baseado em identidade Google + MFA, não em VPN
```

---

## 11. Automação de Firewalls e APIs de Segurança

### 11.1 Palo Alto Networks — API Overview

Firewalls Next-Gen modernos expõem APIs para automação de regras, bloqueio de IPs e coleta de telemetria. O Palo Alto suporta dois formatos:

```yaml
Palo Alto API Types:

XML API (legado, mas muito usado):
  - Endpoint: https://<firewall>/api/
  - Autenticação: API Key via query param ?key=<API_KEY>
  - Operações: GET config, SET config, COMMIT, OP commands
  - Formato: XML request/response

REST API (moderna, PAN-OS 9.0+):
  - Endpoint: https://<firewall>/restapi/v10.1/
  - Autenticação: X-PAN-KEY header
  - Formato: JSON request/response
  - Mais intuitiva para integração com apps modernas

Geração da API Key (ambas as APIs):
  curl -k 'https://<FW-IP>/api/?type=keygen&user=admin&password=SENHA'

  Response XML:
  <response status='success'>
    <result>
      <key>LUFRPT14MW5...==</key>
    </result>
  </response>
```

---

### 11.2 Exemplos Práticos com `curl`

**Operações comuns na XML API do Palo Alto:**

```bash
export FW_IP="192.168.1.1"
export API_KEY="LUFRPT14MW5xdmVlNkptT..."

# ============================================================
# 1. LISTAR REGRAS DE SEGURANÇA ATIVAS
# ============================================================
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=config" \
  --data-urlencode "action=get" \
  --data-urlencode "xpath=/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules" \
  --data-urlencode "key=${API_KEY}" \
  | python3 -m xml.dom.minidom  # pretty print XML

# ============================================================
# 2. VERIFICAR SE UM IP ESTÁ BLOQUEADO (Address Objects)
# ============================================================
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=config" \
  --data-urlencode "action=get" \
  --data-urlencode "xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address/entry[@name='IP-Malicioso-185.220.101.50']" \
  --data-urlencode "key=${API_KEY}"

# ============================================================
# 3. BLOQUEAR UM IP MALICIOSO DINAMICAMENTE
# ============================================================

# 3a. Criar o Address Object com o IP malicioso
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=config" \
  --data-urlencode "action=set" \
  --data-urlencode "xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address/entry[@name='BLOCK-185.220.101.50']" \
  --data-urlencode "element=<ip-netmask>185.220.101.50/32</ip-netmask><description>Blocked by SOAR - IOC from VirusTotal $(date +%F)</description>" \
  --data-urlencode "key=${API_KEY}"

# 3b. Adicionar o IP ao Address Group de bloqueio
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=config" \
  --data-urlencode "action=set" \
  --data-urlencode "xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address-group/entry[@name='BLOCKLIST-IOC']/static" \
  --data-urlencode "element=<member>BLOCK-185.220.101.50</member>" \
  --data-urlencode "key=${API_KEY}"

# 3c. Commitar as mudanças (aplica ao plano de dados)
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=commit" \
  --data-urlencode "cmd=<commit></commit>" \
  --data-urlencode "key=${API_KEY}"

# Output esperado do commit:
# <response status="success" code="19">
#   <result><job>12345</job></result>
# </response>

# ============================================================
# 4. VERIFICAR STATUS DO COMMIT (JOB)
# ============================================================
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=op" \
  --data-urlencode "cmd=<show><jobs><id>12345</id></jobs></show>" \
  --data-urlencode "key=${API_KEY}"

# ============================================================
# 5. BUSCAR SESSÕES ATIVAS (OPERATIONAL COMMAND)
# ============================================================
curl -sk "https://${FW_IP}/api/" \
  --data-urlencode "type=op" \
  --data-urlencode "cmd=<show><session><all></all></session></show>" \
  --data-urlencode "key=${API_KEY}"

# ============================================================
# 6. BUSCAR REGRAS VIA REST API (JSON - PAN-OS 9.0+)
# ============================================================
curl -sk -X GET \
  "https://${FW_IP}/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1" \
  -H "X-PAN-KEY: ${API_KEY}" \
  -H "Accept: application/json" \
  | python3 -m json.tool

# ============================================================
# 7. BLOQUEAR IP VIA REST API (JSON)
# ============================================================
curl -sk -X POST \
  "https://${FW_IP}/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1&name=BLOCK-45.33.32.156" \
  -H "X-PAN-KEY: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "@name": "BLOCK-45.33.32.156",
    "ip-netmask": "45.33.32.156/32",
    "description": "Blocked by SOAR automation - Shodan IoC"
  }'
```

---

### 11.3 Integração no Dashboard Web com JavaScript (Fetch API)

> [!WARNING] CORS e Segurança Nunca exponha sua API Key de firewall no frontend JavaScript (client-side). O exemplo abaixo representa um **backend Node.js/serverless** que serve como proxy seguro entre o dashboard web e o firewall. A API Key deve estar em variáveis de ambiente server-side.

**Backend — Node.js (Express) como proxy seguro:**

```typescript
// firewall-proxy.ts (Backend — nunca expor no frontend!)
// O dashboard chama este endpoint, não o firewall diretamente.

import express, { Request, Response } from 'express';

const app = express();
app.use(express.json());

const FW_IP     = process.env.FW_IP     || '';
const API_KEY   = process.env.PAN_API_KEY || '';

// --- GET /api/firewall/rules ---
app.get('/api/firewall/rules', async (req: Request, res: Response) => {
  try {
    const params = new URLSearchParams({
      type:   'config',
      action: 'get',
      xpath:  "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security/rules",
      key:    API_KEY,
    });

    const response = await fetch(`https://${FW_IP}/api/`, {
      method: 'POST',
      body: params,
      // Em produção: verificar certificado do firewall
      // Em lab com self-signed: adicionar agent com rejectUnauthorized: false
    });

    const xmlText = await response.text();
    // Converter XML → JSON para o dashboard (usando fast-xml-parser)
    res.json({ raw: xmlText, status: response.status });

  } catch (err) {
    console.error('[Firewall API Error]', err);
    res.status(502).json({ error: 'Erro ao comunicar com o firewall' });
  }
});

// --- POST /api/firewall/block-ip ---
app.post('/api/firewall/block-ip', async (req: Request, res: Response) => {
  const { ip, reason } = req.body as { ip: string; reason: string };

  // Validação básica de IP
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) {
    return res.status(400).json({ error: 'IP inválido' });
  }

  const objectName = `BLOCK-${ip.replace(/\./g, '-')}`;
  const date = new Date().toISOString().split('T')[0];

  try {
    // Step 1: Criar Address Object
    const createParams = new URLSearchParams({
      type:    'config',
      action:  'set',
      xpath:   `/config/devices/entry/vsys/entry[@name='vsys1']/address/entry[@name='${objectName}']`,
      element: `<ip-netmask>${ip}/32</ip-netmask><description>Blocked: ${reason} - ${date}</description>`,
      key:     API_KEY,
    });

    const createResp = await fetch(`https://${FW_IP}/api/`, {
      method: 'POST',
      body: createParams,
    });
    const createXml = await createResp.text();

    // Step 2: Adicionar ao grupo de bloqueio
    const groupParams = new URLSearchParams({
      type:    'config',
      action:  'set',
      xpath:   `/config/devices/entry/vsys/entry[@name='vsys1']/address-group/entry[@name='BLOCKLIST-IOC']/static`,
      element: `<member>${objectName}</member>`,
      key:     API_KEY,
    });

    await fetch(`https://${FW_IP}/api/`, {
      method: 'POST',
      body: groupParams,
    });

    // Step 3: Commit assíncrono
    const commitParams = new URLSearchParams({
      type: 'commit',
      cmd:  '<commit></commit>',
      key:  API_KEY,
    });

    const commitResp  = await fetch(`https://${FW_IP}/api/`, {
      method: 'POST',
      body: commitParams,
    });
    const commitXml   = await commitResp.text();

    // Extrair job ID do commit para acompanhamento
    const jobMatch = commitXml.match(/<job>(\d+)<\/job>/);
    const jobId    = jobMatch ? jobMatch[1] : null;

    return res.json({
      success:    true,
      ip,
      objectName,
      commitJobId: jobId,
      message:    `IP ${ip} enviado para bloqueio. Job ID: ${jobId}`,
    });

  } catch (err) {
    console.error('[Block IP Error]', err);
    return res.status(500).json({ error: 'Falha ao bloquear IP no firewall' });
  }
});

app.listen(3001, () => console.log('Firewall proxy rodando em :3001'));
```

**Frontend — Dashboard Web (Fetch API consumindo o proxy):**

```javascript
// dashboard.js — Frontend do Security Operations Dashboard
// Consome o BACKEND PROXY, nunca o firewall diretamente

const API_BASE = '/api/firewall'; // Proxy backend (mesma origem = sem CORS)

// ============================================================
// Carregar e exibir regras do firewall
// ============================================================
async function carregarRegras() {
  const statusEl = document.getElementById('status-regras');
  statusEl.textContent = '⏳ Carregando regras...';

  try {
    const response = await fetch(`${API_BASE}/rules`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // Cookies de sessão do dashboard
    });

    if (!response.ok) {
      throw new Error(`Erro HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    renderizarRegras(data.raw); // Processar XML/JSON das regras

    statusEl.textContent = `✅ ${data.totalRules || 'N/A'} regras carregadas`;

  } catch (error) {
    console.error('[Dashboard] Erro ao carregar regras:', error);
    statusEl.textContent = `❌ Erro: ${error.message}`;
    mostrarAlerta('Falha ao comunicar com o firewall', 'error');
  }
}

// ============================================================
// Bloquear IP via botão no dashboard (com confirmação)
// ============================================================
async function bloquearIP(ip, reason = 'Bloqueio manual via dashboard') {
  // UX: Confirmação antes de ação destrutiva
  const confirmado = confirm(
    `⚠️ Confirma o bloqueio do IP ${ip} no firewall?\n\nMotivo: ${reason}`
  );
  if (!confirmado) return;

  const btnBloquear = document.getElementById(`btn-block-${ip}`);
  if (btnBloquear) {
    btnBloquear.disabled = true;
    btnBloquear.textContent = '⏳ Bloqueando...';
  }

  try {
    const response = await fetch(`${API_BASE}/block-ip`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ ip, reason }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }

    const result = await response.json();

    // Feedback visual no dashboard
    mostrarAlerta(
      `✅ IP ${ip} bloqueado com sucesso! Job ID: ${result.commitJobId}`,
      'success'
    );

    // Atualizar tabela de IOCs bloqueados
    adicionarEntradaTabela({
      ip,
      reason,
      timestamp: new Date().toISOString(),
      jobId: result.commitJobId,
      status: 'pending_commit',
    });

    // Polling para verificar status do commit
    if (result.commitJobId) {
      await aguardarCommit(result.commitJobId);
    }

  } catch (error) {
    console.error('[Dashboard] Erro ao bloquear IP:', error);
    mostrarAlerta(`❌ Falha ao bloquear ${ip}: ${error.message}`, 'error');
  } finally {
    if (btnBloquear) {
      btnBloquear.disabled = false;
      btnBloquear.textContent = '🚫 Bloquear';
    }
  }
}

// ============================================================
// Verificar status do commit no firewall (polling)
// ============================================================
async function aguardarCommit(jobId, tentativas = 0) {
  const MAX_TENTATIVAS = 10;
  const INTERVALO_MS   = 3000;

  if (tentativas >= MAX_TENTATIVAS) {
    console.warn(`[Commit Job ${jobId}] Timeout aguardando commit`);
    return;
  }

  await new Promise(resolve => setTimeout(resolve, INTERVALO_MS));

  try {
    const response = await fetch(`${API_BASE}/commit-status/${jobId}`, {
      credentials: 'include',
    });
    const data = await response.json();

    if (data.status === 'FIN') {
      atualizarStatusTabela(jobId, 'committed');
      mostrarAlerta(`🔒 Commit ${jobId} aplicado com sucesso!`, 'info');
    } else if (data.status === 'ACT') {
      atualizarStatusTabela(jobId, 'committing');
      await aguardarCommit(jobId, tentativas + 1);
    }
  } catch (err) {
    console.error(`[Commit Polling] Erro no job ${jobId}:`, err);
  }
}

// ============================================================
// Inicializar dashboard
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  carregarRegras();

  // Auto-refresh a cada 60s
  setInterval(carregarRegras, 60_000);

  // Listener para formulário de bloqueio manual
  document.getElementById('form-block-ip')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const ip     = document.getElementById('input-ip').value.trim();
    const reason = document.getElementById('input-reason').value.trim();
    bloquearIP(ip, reason || 'Bloqueio manual via dashboard SOC');
  });
});
```

---

### 11.4 Python — SOAR Integration: VirusTotal + Palo Alto

```python
#!/usr/bin/env python3
"""
soar_ioc_blocker.py — Automação SOAR completa
Fluxo: VirusTotal detecta IOC malicioso → Palo Alto bloqueia automaticamente
"""

import os
import re
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# Configurações via variáveis de ambiente
VT_API_KEY   = os.environ["VT_API_KEY"]
FW_IP        = os.environ["PALOALTO_IP"]
FW_API_KEY   = os.environ["PALOALTO_API_KEY"]
BLOCK_GROUP  = "BLOCKLIST-IOC"
VSYS         = "vsys1"

VT_HEADERS = {"x-apikey": VT_API_KEY}

# -----------------------------------------------------------------------
# 1. Verificar reputação no VirusTotal
# -----------------------------------------------------------------------

def checar_reputacao_vt(ip: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    resp = requests.get(url, headers=VT_HEADERS, timeout=30)
    resp.raise_for_status()
    attrs = resp.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    return {
        "ip": ip,
        "malicious": malicious,
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", "N/A"),
        "as_owner": attrs.get("as_owner", "N/A"),
    }

# -----------------------------------------------------------------------
# 2. Criar Address Object no Palo Alto
# -----------------------------------------------------------------------

def criar_address_object(ip: str, descricao: str) -> bool:
    nome  = f"BLOCK-{ip.replace('.', '-')}"
    xpath = (
        f"/config/devices/entry/vsys/entry[@name='{VSYS}']"
        f"/address/entry[@name='{nome}']"
    )
    element = (
        f"<ip-netmask>{ip}/32</ip-netmask>"
        f"<description>{descricao}</description>"
    )
    params = {"type": "config", "action": "set",
              "xpath": xpath, "element": element, "key": FW_API_KEY}

    resp = requests.post(f"https://{FW_IP}/api/",
                         data=params, verify=False, timeout=30)
    root = ET.fromstring(resp.text)
    return root.attrib.get("status") == "success"

# -----------------------------------------------------------------------
# 3. Adicionar ao grupo de bloqueio
# -----------------------------------------------------------------------

def adicionar_ao_grupo(ip: str) -> bool:
    nome  = f"BLOCK-{ip.replace('.', '-')}"
    xpath = (
        f"/config/devices/entry/vsys/entry[@name='{VSYS}']"
        f"/address-group/entry[@name='{BLOCK_GROUP}']/static"
    )
    params = {"type": "config", "action": "set",
              "xpath": xpath, "element": f"<member>{nome}</member>",
              "key": FW_API_KEY}

    resp = requests.post(f"https://{FW_IP}/api/",
                         data=params, verify=False, timeout=30)
    root = ET.fromstring(resp.text)
    return root.attrib.get("status") == "success"

# -----------------------------------------------------------------------
# 4. Commit das mudanças
# -----------------------------------------------------------------------

def commit_firewall() -> str | None:
    params = {"type": "commit", "cmd": "<commit></commit>", "key": FW_API_KEY}
    resp   = requests.post(f"https://{FW_IP}/api/",
                           data=params, verify=False, timeout=30)
    root   = ET.fromstring(resp.text)
    job_el = root.find(".//job")
    return job_el.text if job_el is not None else None

# -----------------------------------------------------------------------
# 5. Pipeline SOAR principal
# -----------------------------------------------------------------------

def pipeline_bloquear_ioc(ip: str, threshold_malicious: int = 5) -> dict:
    """
    Orquestra a verificação e bloqueio de um IP suspeito.
    Returns dict com resultado da operação.
    """
    resultado = {
        "ip": ip,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "acao": "nenhuma",
        "detalhes": {},
    }

    print(f"[*] Verificando IP: {ip}")
    vt_data = checar_reputacao_vt(ip)
    resultado["detalhes"]["virustotal"] = vt_data

    if vt_data["malicious"] < threshold_malicious:
        resultado["acao"] = "ignorado"
        resultado["motivo"] = (
            f"VT malicious={vt_data['malicious']} abaixo do threshold={threshold_malicious}"
        )
        print(f"[INFO] IP {ip} não atingiu threshold. Ignorando.")
        return resultado

    print(f"[!] IP {ip} malicioso: {vt_data['malicious']} engines. Iniciando bloqueio...")

    descricao = (
        f"SOAR Auto-Block | VT:{vt_data['malicious']} engines | "
        f"AS:{vt_data['as_owner']} | {resultado['timestamp']}"
    )

    # Sanitizar descrição (XML injection prevention)
    descricao = re.sub(r'[<>&"\']', '', descricao)[:255]

    ok_obj   = criar_address_object(ip, descricao)
    ok_group = adicionar_ao_grupo(ip)
    job_id   = commit_firewall() if (ok_obj and ok_group) else None

    resultado["acao"]     = "bloqueado" if job_id else "falha"
    resultado["detalhes"]["address_object_criado"] = ok_obj
    resultado["detalhes"]["adicionado_ao_grupo"]   = ok_group
    resultado["detalhes"]["commit_job_id"]          = job_id

    print(f"[{'✓' if job_id else '✗'}] Resultado: {resultado['acao']} | Job: {job_id}")
    return resultado

# -----------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys

    ips_para_verificar = sys.argv[1:] or ["185.220.101.50", "45.33.32.156"]

    resultados = []
    for ip in ips_para_verificar:
        res = pipeline_bloquear_ioc(ip, threshold_malicious=5)
        resultados.append(res)

    print("\n=== RELATÓRIO FINAL ===")
    print(json.dumps(resultados, indent=2, ensure_ascii=False))
```

---

### 11.5 Pipeline SOAR Integrado ao CI/CD

```yaml
# .github/workflows/ioc-response.yml
# Trigger: Alerta do SIEM (webhook) ou análise manual de IP suspeito

name: "SOAR - IOC Auto-Response"

on:
  workflow_dispatch:
    inputs:
      suspicious_ip:
        description: "IP suspeito para análise e bloqueio"
        required: true
      force_block:
        description: "Forçar bloqueio sem aguardar threshold VT"
        type: boolean
        default: false

jobs:
  analyze-and-block:
    runs-on: ubuntu-latest
    environment: security-prod  # Requer aprovação manual para prod!

    steps:
      - uses: actions/checkout@v4

      - name: "Setup Python"
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: "Instalar dependências"
        run: pip install requests

      - name: "Analisar IOC no VirusTotal"
        id: vt-check
        env:
          VT_API_KEY: ${{ secrets.VT_API_KEY }}
        run: |
          RESULT=$(python3 scripts/check_vt.py ${{ inputs.suspicious_ip }})
          echo "vt_result=$RESULT" >> $GITHUB_OUTPUT
          echo "$RESULT" | python3 -m json.tool

      - name: "Bloquear no Firewall (se malicioso)"
        if: ${{ inputs.force_block || fromJSON(steps.vt-check.outputs.vt_result).malicious >= 5 }}
        env:
          VT_API_KEY:      ${{ secrets.VT_API_KEY }}
          PALOALTO_IP:     ${{ secrets.FIREWALL_IP }}
          PALOALTO_API_KEY: ${{ secrets.FIREWALL_API_KEY }}
        run: |
          python3 scripts/soar_ioc_blocker.py ${{ inputs.suspicious_ip }}

      - name: "Notificar Slack — SOC Team"
        if: always()
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
          text: |
            🛡️ *SOAR Auto-Response*
            IP Analisado: `${{ inputs.suspicious_ip }}`
            VT Result: ${{ steps.vt-check.outputs.vt_result }}
            Ação: ${{ job.status == 'success' && 'Bloqueado no Firewall' || 'Falha - Revisar manualmente' }}
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_SOC_WEBHOOK }}
```

---

### 11.6 Tabela Comparativa: Ferramentas de Automação de Segurança

|Ferramenta|Tipo|Linguagem/Protocolo|Melhor para|Curva de aprendizado|
|---|---|---|---|---|
|**Ansible**|Config Management + Network|YAML + Python|Automação de regras em massa, IaC|Baixa|
|**Terraform**|IaC|HCL|Provisionar Security Groups, NACLs, WAF|Média|
|**Netmiko**|SSH Automation|Python|Dispositivos legados sem API REST|Baixa|
|**NAPALM**|Network Abstraction|Python|Multi-vendor config management|Média|
|**pan-python**|SDK Palo Alto|Python|Automação específica PAN-OS|Baixa|
|**Scapy**|Packet Crafting|Python|Testes de penetração, validação de filtros|Alta|
|**Terraform PAN Provider**|IaC Palo Alto|HCL|GitOps para regras de firewall|Média|
|**Cortex XSOAR**|SOAR Platform|Python Playbooks|Orquestração completa de IR|Alta|

---

> [!NOTE] Próximos Passos Recomendados Com a base desta Parte 2, os tópicos naturais de evolução são:
> 
> - **eBPF e Cilium** — o futuro do networking em Kubernetes (substitui iptables)
> - **BGP em Cloud** — como Transit Gateway e Direct Connect usam BGP internamente
> - **DNSSEC e DoH/DoT** — DNS seguro para arquiteturas Zero Trust
> - **gRPC e HTTP/3 (QUIC)** — protocolos modernos e seus impactos em firewalls e Load Balancers
> - **Service Mesh avançado** — Ambient Mesh (Istio sem sidecar), Linkerd

---

## 🔗 Referências

**Padrões e Frameworks:**

- NIST SP 800-207 — Zero Trust Architecture: https://csrc.nist.gov/publications/detail/sp/800-207/final
- SPIFFE/SPIRE: https://spiffe.io/
- CNI Spec: https://github.com/containernetworking/cni

**Documentação Oficial:**

- AWS VPC: https://docs.aws.amazon.com/vpc/
- Kubernetes Networking: https://kubernetes.io/docs/concepts/cluster-administration/networking/
- Istio: https://istio.io/latest/docs/
- Palo Alto XML API: https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api

**Ferramentas:**

- Cilium: https://cilium.io/
- Calico: https://www.tigera.io/project-calico/
- Cloudflare Access (ZTNA): https://www.cloudflare.com/products/zero-trust/access/

---

## 📝 Changelog

|Data|Versão|Alteração|
|---|---|---|
|2026-03-02|2.0|Parte 2 criada: Cloud, Kubernetes, Zero Trust, Firewall APIs|

---

_Continua em:_ [[Redes - Parte 3: eBPF, BGP Avançado e DNS Seguro]] _(planejado)_