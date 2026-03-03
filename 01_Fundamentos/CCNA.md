---
title: "CCNA 200-301 — Guia Completo de Estudos"
tags:
  - ccna
  - networking
  - cisco
  - ospf
  - vlan
  - switching
  - routing
  - tcp-ip
  - osi
  - wireless
  - security
  - automation
  - ipv6
  - nat
  - dhcp
  - acl
aliases:
  - "CCNA Study Guide"
  - "Cisco CCNA 200-301"
created: 2026-03-02
updated: 2026-03-02
status: ativo
nivel: intermediario
exam: "CCNA 200-301"
relacionado:
  - "[[Redes - Fundamentos para DevSecOps e Cybersecurity]]"
  - "[[Redes - Parte 2 Cloud-Native DevSecOps]]"
---
# 🎓 CCNA 200-301 — Guia Completo de Estudos

> [!INFO] Como usar este guia Documento estruturado na ordem dos domínios do exame **CCNA 200-301**. Cada seção cobre o tema com profundidade técnica, tabelas de referência rápida, exemplos de configuração Cisco IOS e callouts com dicas de prova. Use o índice para navegação rápida no Obsidian.

---

## Distribuição do Exame CCNA 200-301

|Domínio|Tema|Peso|
|---|---|---|
|**1**|Network Fundamentals|20%|
|**2**|Network Access|20%|
|**3**|IP Connectivity|25%|
|**4**|IP Services|10%|
|**5**|Security Fundamentals|15%|
|**6**|Automation & Programmability|10%|

---

## 📋 Índice

- [[#1. Modelo OSI — As 7 Camadas]]
- [[#2. Modelo TCPIP — A Pilha da Internet]]
- [[#3. Ethernet e a Camada de Enlace]]
- [[#4. Endereçamento IPv4 e Subnetting]]
- [[#5. IPv6]]
- [[#6. Switching — VLANs e STP]]
- [[#7. Roteamento — Estático e OSPF]]
- [[#8. Wireless — 802.11 e WLC]]
- [[#9. Serviços IP — DHCP, DNS, NAT, NTP]]
- [[#10. Gerenciamento — SSH, Syslog, SNMP, CDP/LLDP]]
- [[#11. Segurança — ACLs, Layer 2 e VPN]]
- [[#12. Automação — SDN, APIs e Python]]
- [[#Referência Rápida — Comandos Cisco IOS]]

---

## 1. Modelo OSI — As 7 Camadas

### 1.1 Visão Geral

O modelo **OSI (Open Systems Interconnection)** é um framework conceitual de **7 camadas** criado pela ISO para padronizar comunicações em rede. Embora o TCP/IP seja o modelo prático usado na internet, o OSI é a base teórica para entender **onde** um problema ocorre e **qual** equipamento/protocolo é responsável.

```
┌─────────┬────────────────────────────────────────────────────────┐
│ Camada  │ Nome              │ PDU        │ Protocolos/Exemplos    │
├─────────┼───────────────────┼────────────┼────────────────────────┤
│    7    │ Application       │ Data       │ HTTP, HTTPS, FTP, SSH  │
│    6    │ Presentation      │ Data       │ TLS/SSL, JPEG, ASCII   │
│    5    │ Session           │ Data       │ NetBIOS, RPC, SQL*Net  │
│    4    │ Transport         │ Segment    │ TCP, UDP               │
│    3    │ Network           │ Packet     │ IP, ICMP, OSPF, BGP    │
│    2    │ Data Link         │ Frame      │ Ethernet, 802.11, ARP  │
│    1    │ Physical          │ Bits       │ Cabos UTP/Fibra, Wi-Fi │
└─────────┴───────────────────┴────────────┴────────────────────────┘
```

> [!NOTE] Mnemônico para a prova **"All People Seem To Need Data Processing"** (de cima para baixo: Application, Presentation, Session, Transport, Network, Data Link, Physical) Ou de baixo para cima: **"Please Do Not Throw Sausage Pizza Away"**

---

### 1.2 Detalhamento por Camada

#### Camada 7 — Application (Aplicação)

Fornece a **interface** entre aplicativos de usuário e a rede. É onde os protocolos de serviço operam.

```yaml
Função: Interface com o usuário e serviços de rede
PDU: Dado (Data / Message)
Equipamentos: Proxy, Firewall L7, WAF, Load Balancer L7

Protocolos principais:
  HTTP    : TCP 80  — Hypertext Transfer Protocol
  HTTPS   : TCP 443 — HTTP sobre TLS
  FTP     : TCP 20/21 — File Transfer (dados/controle)
  SSH     : TCP 22  — Secure Shell
  Telnet  : TCP 23  — Acesso remoto (inseguro, não usar)
  SMTP    : TCP 25  — Envio de e-mail
  DNS     : UDP/TCP 53 — Resolução de nomes
  DHCP    : UDP 67/68 — Concessão dinâmica de IP
  SNMP    : UDP 161/162 — Monitoramento de rede
  NTP     : UDP 123 — Sincronização de tempo
  TFTP    : UDP 69 — Transferência de arquivos (simples)
  IMAP    : TCP 143 — Leitura de e-mail
  POP3    : TCP 110 — Download de e-mail
  LDAP    : TCP 389 — Diretório (Active Directory)
  RDP     : TCP 3389 — Remote Desktop (Windows)
```

#### Camada 6 — Presentation (Apresentação)

Responsável pela **tradução, criptografia e compressão** de dados.

```yaml
Função: Tradução de formato de dados entre aplicações
PDU: Dado

Responsabilidades:
  Criptografia/Descriptografia : TLS, SSL
  Compressão                   : gzip, deflate
  Tradução de formato          : ASCII ↔ EBCDIC, UTF-8, JPEG, MPEG

Nota CCNA: Na prática, as funções das camadas 5, 6 e 7 são
  frequentemente combinadas na "camada de aplicação" do modelo TCP/IP.
```

#### Camada 5 — Session (Sessão)

Gerencia o **estabelecimento, manutenção e encerramento** de sessões de comunicação.

```yaml
Função: Controle de diálogo e sincronização
PDU: Dado

Responsabilidades:
  Abertura/fechamento de sessões
  Checkpoint e recuperação de sessão
  Controle full-duplex/half-duplex

Protocolos: NetBIOS, RPC, SQL*Net, NFS, PPTP
```

#### Camada 4 — Transport (Transporte)

**Comunicação fim-a-fim** entre processos. Aqui estão as portas lógicas.

```yaml
Função: Comunicação host-to-host, multiplexação por portas
PDU: Segmento (TCP) / Datagrama (UDP)
Equipamentos: Firewall Stateful (inspeciona portas e estado)

TCP vs UDP — Comparação:
  Critério          TCP                     UDP
  Conexão           Orientado (3-way HS)    Sem conexão
  Confiabilidade    Garantida               Best-effort
  Ordenação         Sim (sequence numbers)  Não
  Controle de fluxo Sim (window size)       Não
  Overhead header   20 bytes                8 bytes
  Velocidade        Mais lento              Mais rápido
  Uso típico        HTTP, SSH, FTP, SMTP    DNS, DHCP, VoIP, Streaming

TCP Three-Way Handshake:
  1. SYN      → Cliente inicia (SEQ=X)
  2. SYN-ACK  ← Servidor responde (SEQ=Y, ACK=X+1)
  3. ACK      → Cliente confirma (ACK=Y+1)
  Conexão estabelecida!

TCP Four-Way Termination:
  1. FIN  → Lado que quer encerrar
  2. ACK  ← Confirmação
  3. FIN  ← Outro lado encerra
  4. ACK  → Confirmação final
```

|Flag TCP|Significado|Uso|
|---|---|---|
|**SYN**|Synchronize|Inicia conexão|
|**ACK**|Acknowledge|Confirma recebimento|
|**FIN**|Finish|Encerra conexão graciosamente|
|**RST**|Reset|Encerra conexão abruptamente|
|**PSH**|Push|Envia dados imediatamente (sem buffer)|
|**URG**|Urgent|Dados urgentes (prioridade)|

#### Camada 3 — Network (Rede)

**Roteamento** entre redes distintas usando endereços lógicos (IP).

```yaml
Função: Path selection, endereçamento lógico, roteamento
PDU: Pacote (Packet)
Equipamentos: Roteador, Switch Layer 3, Firewall

Protocolos:
  IPv4, IPv6  : Endereçamento lógico
  ICMP        : Mensagens de controle (ping, traceroute)
  OSPF, EIGRP : Roteamento dinâmico (IGPs)
  BGP         : Roteamento entre ASes (internet)

Processo de roteamento:
  1. Pacote chega com IP destino
  2. Router consulta tabela de roteamento
  3. Longest Prefix Match (mais específico vence)
  4. Decrementa TTL (Time To Live)
  5. Se TTL = 0 → descarta + envia ICMP "Time Exceeded"
  6. Encaminha para next-hop ou interface diretamente conectada
```

#### Camada 2 — Data Link (Enlace de Dados)

**Comunicação dentro de uma mesma rede** usando endereços físicos (MAC).

```yaml
Função: Entrega de frame hop-by-hop, endereçamento MAC
PDU: Frame (Quadro)
Equipamentos: Switch L2, Bridge, AP (acesso à rede sem fio)

Subcamadas IEEE:
  LLC (Logical Link Control)  : Interface com camada 3
  MAC (Media Access Control)  : Endereço físico, acesso ao meio

Protocolos: Ethernet, 802.11 (Wi-Fi), PPP, HDLC

MAC Address:
  Formato: XX:XX:XX:XX:XX:XX (48 bits = 6 octetos hex)
  OUI (3 bytes): Identifica o fabricante
  NIC (3 bytes): Identifica a interface específica

  Tipos de endereços MAC:
    Unicast  : Destino único (bit 0 do 1º octeto = 0)
    Multicast: Grupo de destinos (bit 0 do 1º octeto = 1)
    Broadcast: Todos (FF:FF:FF:FF:FF:FF)
```

#### Camada 1 — Physical (Física)

**Transmissão de bits** no meio físico (cabos, fibra, ondas de rádio).

```yaml
Função: Transmissão de bits no meio de comunicação
PDU: Bits
Equipamentos: Hub, Repeater, Modem, Placa de rede (NIC)

Tipos de meio:
  UTP (Unshielded Twisted Pair):
    Cat5e: 1 Gbps, 100m
    Cat6:  1-10 Gbps, 55m (10G) / 100m (1G)
    Cat6a: 10 Gbps, 100m

  Fibra Ótica:
    Monomodo (SMF): Longas distâncias (até 40km+), laser
    Multimodo (MMF): Curtas distâncias (até 550m), LED

  Wireless: Ondas de rádio (2.4 GHz, 5 GHz, 6 GHz)

Padrões Ethernet:
  10BASE-T    : 10 Mbps, UTP, 100m
  100BASE-TX  : 100 Mbps (Fast Ethernet), UTP, 100m
  1000BASE-T  : 1 Gbps (Gigabit), UTP Cat5e, 100m
  1000BASE-LX : 1 Gbps, Fibra Monomodo, 5km
  10GBASE-T   : 10 Gbps, UTP Cat6a, 100m
```

---

### 1.3 Encapsulamento e Desencapsulamento

```
TRANSMISSÃO (Encapsulamento — Top-Down):

  Aplicação   │ DATA                                              │
              ↓ Adiciona portas TCP/UDP
  Transporte  │ TCP/UDP HDR  │ DATA                              │
              ↓ Adiciona IPs de origem/destino
  Rede        │ IP HDR │ TCP/UDP HDR │ DATA                      │
              ↓ Adiciona MACs (hop-by-hop)
  Enlace      │ ETH HDR │ IP HDR │ TCP/UDP HDR │ DATA │ FCS      │
              ↓ Converte em sinais
  Física      │ 101010110011010101010...                         │

RECEPÇÃO (Desencapsulamento — Bottom-Up):
  Cada camada remove seu cabeçalho e entrega para a camada acima.
  MACs são trocados a cada hop; IPs permanecem iguais fim-a-fim.
```

> [!WARNING] MAC vs IP em cada hop Em uma comunicação entre PC-A e Servidor-Web (passando por 3 roteadores):
> 
> - O **IP de origem** (PC-A) e o **IP de destino** (Servidor) **nunca mudam** durante toda a jornada
> - O **MAC de origem** e o **MAC de destino** **mudam a cada hop** (de roteador para roteador)

---

## 2. Modelo TCP/IP — A Pilha da Internet

### 2.1 Comparativo OSI vs TCP/IP

```
Modelo OSI          Modelo TCP/IP        Protocolos
────────────────    ─────────────────    ─────────────────────
7. Application  ┐
8. Presentation ├── Application         HTTP, FTP, SSH, DNS
9. Session      ┘
10. Transport    ─── Transport           TCP, UDP
11. Network      ─── Internet            IPv4, IPv6, ICMP
12. Data Link    ┐
13. Physical     ┴── Network Access      Ethernet, Wi-Fi, ARP
```

|Camada TCP/IP|Equiv. OSI|PDU|Função|
|---|---|---|---|
|**Application**|5, 6, 7|Data|Serviços para aplicações|
|**Transport**|4|Segmento / Datagrama|Comunicação fim-a-fim|
|**Internet**|3|Pacote|Roteamento entre redes|
|**Network Access**|1, 2|Frame / Bits|Transmissão local|

---

### 2.2 Portas Well-Known — Referência Rápida

|Porta|Protocolo|Serviço|Seguro?|
|---|---|---|---|
|20/21|TCP|FTP (dados/controle)|❌ Plaintext|
|22|TCP|SSH|✅ Criptografado|
|23|TCP|Telnet|❌ Plaintext|
|25|TCP|SMTP|⚠️ Opcional TLS|
|53|UDP/TCP|DNS|⚠️ Sem autenticação|
|67/68|UDP|DHCP (server/client)|⚠️ Sem autenticação|
|69|UDP|TFTP|❌ Sem autenticação|
|80|TCP|HTTP|❌ Plaintext|
|110|TCP|POP3|⚠️ Opcional TLS|
|123|UDP|NTP|⚠️ Opcional auth|
|143|TCP|IMAP|⚠️ Opcional TLS|
|161/162|UDP|SNMP (agent/trap)|⚠️ v3 obrigatório|
|443|TCP|HTTPS|✅ TLS|
|514|UDP|Syslog|❌ Plaintext|
|3389|TCP|RDP|⚠️ Expor com cuidado|

---

## 3. Ethernet e a Camada de Enlace

### 3.1 Estrutura do Frame Ethernet

```
┌────────────┬───────────┬──────────┬───────────────────┬─────┐
│ Preâmbulo  │ Dest MAC  │ Src MAC  │ EtherType/Tamanho │ FCS │
│ 8 bytes    │ 6 bytes   │ 6 bytes  │ 2 bytes           │ 4 b │
└────────────┴───────────┴──────────┴───────────────────┴─────┘

Preâmbulo: 7 bytes (10101010...) + 1 byte SFD (Start Frame Delimiter)
  → Sincronização de clock
Destination MAC: Endereço físico do próximo hop
Source MAC: Endereço físico da interface que transmite
EtherType: 0x0800 (IPv4), 0x0806 (ARP), 0x86DD (IPv6), 0x8100 (802.1Q VLAN)
FCS (Frame Check Sequence): CRC-32 para detecção de erros
```

> [!NOTE] Tamanho do Frame Ethernet **Mínimo**: 64 bytes | **Máximo**: 1518 bytes (1522 com tag 802.1Q) Frame menor que 64 bytes = **Runt** (colisão detectada) Frame maior que 1518 bytes = **Giant** / **Jumbo Frame** (configuração especial)

---

### 3.2 ARP — Address Resolution Protocol

O ARP resolve **endereços IP → MAC** dentro do mesmo segmento de rede.

```
Cenário: PC-A (192.168.1.10) quer enviar para PC-B (192.168.1.20)

1. PC-A verifica cache ARP: 192.168.1.20 presente?
   - Sim → usa o MAC direto
   - Não → dispara ARP Request

2. ARP Request (Broadcast):
   Src IP:  192.168.1.10
   Src MAC: aa:bb:cc:11:22:33
   Dst IP:  192.168.1.20
   Dst MAC: FF:FF:FF:FF:FF:FF  ← Broadcast (todos recebem)

3. Apenas PC-B responde (ARP Reply — Unicast):
   Src IP:  192.168.1.20
   Src MAC: dd:ee:ff:44:55:66
   Dst IP:  192.168.1.10
   Dst MAC: aa:bb:cc:11:22:33

4. PC-A armazena no ARP cache (timeout padrão: 4 horas Windows, 20min Linux)
```

```bash
# Visualizar tabela ARP
# Linux/Mac:
arp -n
ip neigh show

# Windows:
arp -a

# Cisco IOS:
Router# show arp
Protocol  Address          Age  Hardware Addr   Type  Interface
Internet  192.168.1.1        -  aa:bb:cc:11:22:33  ARPA  GigEth0/0
Internet  192.168.1.10      14  dd:ee:ff:44:55:66  ARPA  GigEth0/0
```

> [!WARNING] ARP Spoofing / ARP Poisoning Um atacante pode enviar ARP Replies falsos associando seu MAC ao IP do gateway, interceptando todo o tráfego (**Man-in-the-Middle**). Defesas: **Dynamic ARP Inspection (DAI)** no switch, ou usar IPv6 com SLAAC + ND Protection.

---

### 3.3 Switch — Operação e Tabela CAM

```yaml
Processo de decisão do switch:

1. Frame chega na porta X
2. Switch aprende: "MAC de origem está na porta X" → registra na CAM table
3. Verifica MAC de destino na tabela:

   a) MAC destino ENCONTRADO na tabela:
      → Encaminha SOMENTE para a porta associada (unicast)

   b) MAC destino NÃO encontrado (Unknown Unicast):
      → FLOOD: copia o frame para TODAS as portas (exceto a de origem)
      → Quando o destino responder, aprende a porta correta

   c) MAC destino é FF:FF:FF:FF:FF:FF (Broadcast):
      → FLOOD para TODAS as portas (exceto origem)

   d) MAC destino é Multicast:
      → FLOOD (por padrão) ou entrega seletiva com IGMP Snooping

CAM Table (Content Addressable Memory):
  - Armazenada em hardware TCAM (ultra-rápido)
  - Timeout padrão: 300 segundos (5 min) de inatividade
  - MAC Flooding attack: encher a CAM table com MACs falsos
    → Switch entra em modo "hub" → forward tudo para todas as portas
    → Defesa: Port Security
```

```cisco
! Visualizar MAC address table
Switch# show mac address-table
! Filtrar por VLAN
Switch# show mac address-table vlan 10
! Filtrar por interface
Switch# show mac address-table interface GigabitEthernet0/1
! Filtrar por MAC
Switch# show mac address-table address aaaa.bbbb.cccc

! Limpar tabela manualmente
Switch# clear mac address-table dynamic

! Configurar aging time
Switch(config)# mac address-table aging-time 600
```

---

### 3.4 Duplex e Speed

```yaml
Duplex:
  Half-Duplex: Transmite OU recebe (não simultaneamente)
    - Usa CSMA/CD para detectar colisões
    - Domínio de colisão = todos compartilhando o mesmo meio
    - Use: Hubs (obsoleto)

  Full-Duplex: Transmite E recebe simultaneamente
    - SEM colisões (sem CSMA/CD)
    - Cada porta do switch = domínio de colisão próprio
    - Use: Todos os switches modernos

Duplex Mismatch (problema clássico na prova!):
  - Um lado: Full-Duplex
  - Outro lado: Half-Duplex
  - Resultado: Alto número de late collisions e FCS errors
  - Fix: Configurar manualmente ambos os lados

Auto-negotiation:
  - Padrão atual (IEEE 802.3u)
  - Negocia automaticamente: speed e duplex
  - Problema: Se um lado está fixo e o outro em auto
    → O lado auto não consegue negociar duplex → cai para half-duplex
```

```cisco
! Configurar speed e duplex manualmente (recomendado em uplinks)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# speed 1000
Switch(config-if)# duplex full
Switch(config-if)# no shutdown

! Verificar status
Switch# show interfaces GigabitEthernet0/1
  GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is aaaa.bbbb.0001
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
```

---

## 4. Endereçamento IPv4 e Subnetting

### 4.1 Classes de Endereços IPv4

```yaml
Classes IPv4 (para entender RFC 1918):

Classe A:
  Range: 1.0.0.0 – 126.255.255.255
  Máscara padrão: /8 (255.0.0.0)
  Privado: 10.0.0.0/8
  Hosts por rede: ~16,7 milhões

Classe B:
  Range: 128.0.0.0 – 191.255.255.255
  Máscara padrão: /16 (255.255.0.0)
  Privado: 172.16.0.0 – 172.31.255.255 (172.16.0.0/12)
  Hosts por rede: ~65.534

Classe C:
  Range: 192.0.0.0 – 223.255.255.255
  Máscara padrão: /24 (255.255.255.0)
  Privado: 192.168.0.0/16
  Hosts por rede: 254

Especiais:
  127.0.0.0/8   : Loopback (127.0.0.1 = localhost)
  169.254.0.0/16: APIPA (Automatic Private IP Assignment — DHCP falhou)
  0.0.0.0/0     : Rota default (toda a internet)
  255.255.255.255: Limited broadcast (não roteável)
```

---

### 4.2 Subnetting — Método Rápido

> [!NOTE] Fórmulas Essenciais para a Prova
> 
> - **Hosts válidos** = 2^(bits de host) - 2
> - **Subnets** = 2^(bits emprestados)
> - **Incremento de bloco** = 256 - valor do octeto da máscara naquele octeto

**Tabela de referência rápida /24 a /30:**

|CIDR|Máscara|Hosts|Subnets (de /24)|Bloco|Uso típico|
|---|---|---|---|---|---|
|**/30**|255.255.255.252|**2**|64|4|Links ponto-a-ponto|
|**/29**|255.255.255.248|**6**|32|8|Pequenos segmentos|
|**/28**|255.255.255.240|**14**|16|16|DMZ pequena|
|**/27**|255.255.255.224|**30**|8|32|Escritório pequeno|
|**/26**|255.255.255.192|**62**|4|64|Dept. médio|
|**/25**|255.255.255.128|**126**|2|128|Subnet grande|
|**/24**|255.255.255.0|**254**|1|—|LAN padrão|
|**/23**|255.255.254.0|**510**|—|—|LAN maior|
|**/22**|255.255.252.0|**1022**|—|—|Campus|
|**/16**|255.255.0.0|**65534**|—|—|Classe B|
|**/8**|255.0.0.0|**16M+**|—|—|Classe A|

**Exemplo de cálculo rápido:**

```yaml
Problema: Dividir 192.168.10.0/24 em subnets de pelo menos 50 hosts

Passo 1: Quantos bits de host precisamos?
  2^6 - 2 = 62 hosts → /26 é suficiente (62 ≥ 50)

Passo 2: Máscara = /26 → 255.255.255.192
  Último octeto: 192 → incremento = 256 - 192 = 64

Passo 3: Listar as subnets:
  Subnet 1: 192.168.10.0/26
    Rede:      192.168.10.0
    1ª utilizável: 192.168.10.1
    Última:    192.168.10.62
    Broadcast: 192.168.10.63

  Subnet 2: 192.168.10.64/26
    Rede:      192.168.10.64
    1ª utilizável: 192.168.10.65
    Última:    192.168.10.126
    Broadcast: 192.168.10.127

  Subnet 3: 192.168.10.128/26
    Rede:      192.168.10.128
    Broadcast: 192.168.10.191

  Subnet 4: 192.168.10.192/26
    Rede:      192.168.10.192
    Broadcast: 192.168.10.255

Resultado: 4 subnets com 62 hosts cada ✓
```

---

### 4.3 VLSM — Variable Length Subnet Mask

O VLSM permite usar **máscaras diferentes** para cada subnet, otimizando o espaço de endereçamento.

```yaml
Cenário: Empresa com 10.0.0.0/24
  - Rede A: 100 hosts (departamento de vendas)
  - Rede B: 50 hosts  (departamento de TI)
  - Rede C: 25 hosts  (RH)
  - Link 1: ponto-a-ponto roteador R1-R2
  - Link 2: ponto-a-ponto roteador R2-R3

Regra VLSM: Sempre alocar da MAIOR para a MENOR necessidade

Rede A (100 hosts):
  Precisa: 2^7 - 2 = 126 → /25
  Rede:    10.0.0.0/25
  Range:   10.0.0.1 – 10.0.0.126
  Próxima: 10.0.0.128

Rede B (50 hosts):
  Precisa: 2^6 - 2 = 62 → /26
  Rede:    10.0.0.128/26
  Range:   10.0.0.129 – 10.0.0.190
  Próxima: 10.0.0.192

Rede C (25 hosts):
  Precisa: 2^5 - 2 = 30 → /27
  Rede:    10.0.0.192/27
  Range:   10.0.0.193 – 10.0.0.222
  Próxima: 10.0.0.224

Link 1 (2 hosts):
  Precisa: 2^2 - 2 = 2 → /30
  Rede:    10.0.0.224/30
  Range:   10.0.0.225 – 10.0.0.226
  Próxima: 10.0.0.228

Link 2 (2 hosts):
  Rede:    10.0.0.228/30
  Range:   10.0.0.229 – 10.0.0.230

Espaço total: Apenas 1 rede /24 para tudo! Zero desperdício.
```

---

### 4.4 Wildcard Masks

Utilizadas em **OSPF** e **ACLs**. É o inverso da subnet mask.

```yaml
Cálculo: Wildcard = 255.255.255.255 - Subnet Mask

Exemplos:
  /24 → 255.255.255.0   → Wildcard: 0.0.0.255
  /25 → 255.255.255.128 → Wildcard: 0.0.0.127
  /26 → 255.255.255.192 → Wildcard: 0.0.0.63
  /27 → 255.255.255.224 → Wildcard: 0.0.0.31
  /28 → 255.255.255.240 → Wildcard: 0.0.0.15
  /30 → 255.255.255.252 → Wildcard: 0.0.0.3
  /32 → 255.255.255.255 → Wildcard: 0.0.0.0  (host único)

Lógica do bit:
  0 = bit DEVE corresponder (fixo)
  1 = bit pode ser qualquer coisa (indiferente)

Exemplo OSPF:
  network 10.0.0.0 0.0.0.255 area 0
  → Anuncia todas as interfaces com IP 10.0.0.x na área 0

  network 192.168.1.5 0.0.0.0 area 0
  → Anuncia APENAS a interface com IP exato 192.168.1.5
```

---

## 5. IPv6

### 5.1 Por que IPv6?

```yaml
Problema IPv4: 32 bits = ~4,3 bilhões de endereços
  → Exaustão em 2011 (IANA) / 2022 (LACNIC para América Latina)

Solução IPv6: 128 bits = 340 undecilhões de endereços
  (340.282.366.920.938.463.463.374.607.431.768.211.456)
  → Endereço para cada grão de areia da Terra, milhões de vezes

Melhorias sobre IPv4:
  ✓ Espaço de endereços praticamente ilimitado
  ✓ Sem broadcast (substituído por multicast)
  ✓ IPsec integrado (nativo, não opcional)
  ✓ SLAAC: Autoconfiguração sem DHCP
  ✓ Cabeçalho simplificado (mais rápido para processar)
  ✓ Sem fragmentação em routers intermediários
  ✓ Sem NAT necessário (cada dispositivo tem IP público)
```

### 5.2 Formato e Abreviação

```yaml
Formato completo: 2001:0DB8:0000:0001:0000:0000:0000:0001

Regras de abreviação:

Regra 1: Remover zeros à esquerda de cada grupo
  2001:DB8:0:1:0:0:0:1

Regra 2: Substituir CONSECUTIVOS grupos de zeros por ::
  (Pode usar :: APENAS UMA VEZ no endereço!)
  2001:DB8:0:1::1

Exemplos:
  Loopback IPv6:    ::1        (equiv. 127.0.0.1 IPv4)
  Default route:    ::/0       (equiv. 0.0.0.0/0 IPv4)
  All nodes:        FF02::1    (equiv. broadcast — todos os hosts)
  All routers:      FF02::2    (todos os routers no link)
```

### 5.3 Tipos de Endereços IPv6

|Tipo|Prefixo|Escopo|Equiv. IPv4|Descrição|
|---|---|---|---|---|
|**Global Unicast**|2000::/3|Global (internet)|IP Público|Roteável na internet|
|**Link-Local**|FE80::/10|Apenas no link local|169.254.x.x|Auto-gerado, não roteável|
|**Unique Local**|FC00::/7|Interna|10/172/192.168|Privado, não na internet|
|**Loopback**|::1/128|Host local|127.0.0.1|Só no próprio host|
|**Multicast**|FF00::/8|Variado|Broadcast IPv4|Um-para-muitos|
|**Unspecified**|::/128|—|0.0.0.0|Endereço não definido|
|**Anycast**|De unicast|Global|N/A|Roteado ao mais próximo|

> [!NOTE] Link-Local é OBRIGATÓRIO Toda interface IPv6 **sempre** tem um endereço Link-Local (FE80::/10), gerado automaticamente a partir do MAC (EUI-64) ou aleatoriamente. É usado para comunicação na mesma rede e para protocolos como NDP e OSPF.

---

### 5.4 SLAAC e DHCPv6

```yaml
SLAAC (Stateless Address Autoconfiguration):
  1. Interface gera Link-Local automaticamente (FE80::...)
  2. Envia RS (Router Solicitation) → FF02::2 (todos os routers)
  3. Router responde com RA (Router Advertisement):
     - Prefixo da rede (ex: 2001:DB8:1::/64)
     - Default gateway (próprio IP link-local do router)
     - Flags M e O (M=0, O=0 → full SLAAC)
  4. Host cria endereço: Prefixo + Interface ID (EUI-64 ou random)

EUI-64 (Extended Unique Identifier):
  MAC: aa:bb:cc:dd:ee:ff
  → Inserir FF:FE no meio: aa:bb:cc:FF:FE:dd:ee:ff
  → Inverter bit 7 do 1º octeto: aa ↔ aa (0xaa = 10101010, bit 7 → 10101000 = 0xa8)
  → Interface ID: A8BB:CCFF:FEDD:EEFF

DHCPv6 Stateful (M=1):
  → Host usa DHCP para obter TUDO (IP, DNS, domínio, etc.)
  → Similar ao DHCPv4

DHCPv6 Stateless (O=1, M=0):
  → Host autoconfigura o IP via SLAAC
  → Usa DHCP APENAS para obter DNS, NTP, domínio, etc.
```

---

### 5.5 Configuração IPv6 Cisco

```cisco
! Habilitar roteamento IPv6
Router(config)# ipv6 unicast-routing

! Configurar endereço IPv6 na interface
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ipv6 address 2001:DB8:1::1/64
Router(config-if)# ipv6 address FE80::1 link-local
Router(config-if)# no shutdown

! Endereço via EUI-64
Router(config-if)# ipv6 address 2001:DB8:1::/64 eui-64

! Rota estática IPv6
Router(config)# ipv6 route 2001:DB8:2::/64 2001:DB8:1::2

! Default route IPv6
Router(config)# ipv6 route ::/0 2001:DB8:1::254

! Verificação
Router# show ipv6 interface brief
Router# show ipv6 route
Router# show ipv6 neighbors        ! Tabela NDP (equiv. ARP IPv4)

! Ping IPv6
Router# ping 2001:DB8:2::1
Router# ping FE80::2 %GigabitEthernet0/0   ! Link-local precisa de interface
```

---

## 6. Switching — VLANs e STP

### 6.1 VLANs — Segmentação Lógica

```yaml
O que é uma VLAN:
  - Domínio de broadcast lógico dentro de um switch físico
  - Isolamento de tráfego sem hardware separado
  - Identificador: número de 1 a 4094

Tipos de VLAN:
  Data VLAN: Tráfego de usuários (VLAN 10, 20, 30...)
  Voice VLAN: Tráfego VoIP com QoS separado
  Native VLAN: Tráfego sem tag no trunk (padrão: VLAN 1)
  Management VLAN: Acesso gerencial ao switch (SVI)
  Default VLAN: VLAN 1 (todas as portas aqui por padrão)

  ⚠️ Boa prática: NUNCA use a VLAN 1 como VLAN de usuário ou gerência
     Mude a native VLAN para um valor não utilizado (ex: VLAN 999)

Modos de porta:
  Access: Membro de UMA VLAN, tráfego sem tag 802.1Q
  Trunk:  Carrega MÚLTIPLAS VLANs, tráfego com tag 802.1Q
  Dynamic (DTP): Negocia automaticamente access/trunk (desabilitar em produção!)
```

**802.1Q — Frame com tag VLAN:**

```
Ethernet Frame:
┌──────────┬──────────┬────────────────────────┬──────────────┬─────┐
│ Dst MAC  │ Src MAC  │ 802.1Q Tag (4 bytes)   │ EtherType    │ FCS │
│ 6 bytes  │ 6 bytes  │ TPID│PCP│DEI│VLAN ID  │ / Length     │ 4b  │
│          │          │8100 │3b │1b │12 bits  │              │     │
└──────────┴──────────┴────────────────────────┴──────────────┴─────┘

TPID: 0x8100 (identifica que é um frame 802.1Q)
PCP: Priority Code Point (0-7, QoS)
DEI: Drop Eligible Indicator
VLAN ID: 0-4095 (0 e 4095 reservados = 1-4094 usáveis)
```

**Configuração completa de VLANs:**

```cisco
! ============================================================
! Criação de VLANs
! ============================================================
Switch(config)# vlan 10
Switch(config-vlan)# name VENDAS
Switch(config-vlan)# exit

Switch(config)# vlan 20
Switch(config-vlan)# name ENGENHARIA
Switch(config-vlan)# exit

Switch(config)# vlan 30
Switch(config-vlan)# name RH
Switch(config-vlan)# exit

Switch(config)# vlan 99
Switch(config-vlan)# name GERENCIA
Switch(config-vlan)# exit

Switch(config)# vlan 999
Switch(config-vlan)# name NATIVE-UNUSED
Switch(config-vlan)# exit

! ============================================================
! Porta Access (conecta ao end device)
! ============================================================
Switch(config)# interface GigabitEthernet0/5
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# spanning-tree portfast       ! Ativa imediatamente
Switch(config-if)# spanning-tree bpduguard enable ! Bloqueia se receber BPDU
Switch(config-if)# no shutdown

! ============================================================
! Porta Voice (IP Phone + PC atrás do phone)
! ============================================================
Switch(config)# interface GigabitEthernet0/6
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10    ! PC na VLAN de dados
Switch(config-if)# switchport voice vlan 100    ! Phone na VLAN de voz
Switch(config-if)# mls qos trust cos            ! Confia no CoS do phone

! ============================================================
! Porta Trunk (conecta a outro switch ou router)
! ============================================================
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# switchport trunk encapsulation dot1q   ! (apenas em switches que precisam)
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk native vlan 999       ! Mudar native da VLAN 1
Switch(config-if)# switchport trunk allowed vlan 10,20,30,99
Switch(config-if)# no shutdown

! ============================================================
! SVI — Switch Virtual Interface (Interface de gerência)
! ============================================================
Switch(config)# interface Vlan99
Switch(config-if)# ip address 10.0.99.10 255.255.255.0
Switch(config-if)# no shutdown
Switch(config)# ip default-gateway 10.0.99.1

! ============================================================
! Verificação
! ============================================================
Switch# show vlan brief
Switch# show interfaces trunk
Switch# show interfaces GigabitEthernet0/5 switchport
Switch# show interfaces GigabitEthernet0/1 trunk
```

---

### 6.2 Inter-VLAN Routing

Para que VLANs diferentes se comuniquem, é necessário um **roteador** ou **switch Layer 3**.

```yaml
Opções de Inter-VLAN Routing:

1. Router-on-a-Stick (ROAS):
   - Um único link físico trunk entre switch e router
   - Router usa subinterfaces (uma por VLAN)
   - Simples, mas cria bottleneck no link
   - Use: Lab, redes pequenas

2. Switch Layer 3 (SVI):
   - O próprio switch tem IPs nas interfaces virtuais (SVIs)
   - Performance muito superior (routing em hardware)
   - Use: Produção (recomendado)

3. Routing separado por interface física:
   - Um cabo físico por VLAN entre switch e router
   - Ineficiente (usa muitas interfaces)
   - Obsoleto
```

**Router-on-a-Stick:**

```cisco
! Configuração no ROUTER
Router(config)# interface GigabitEthernet0/0
Router(config-if)# no shutdown
Router(config-if)# exit

! Subinterfaces (uma por VLAN)
Router(config)# interface GigabitEthernet0/0.10
Router(config-subif)# encapsulation dot1Q 10
Router(config-subif)# ip address 192.168.10.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.20
Router(config-subif)# encapsulation dot1Q 20
Router(config-subif)# ip address 192.168.20.1 255.255.255.0

Router(config)# interface GigabitEthernet0/0.99
Router(config-subif)# encapsulation dot1Q 99 native   ! Native VLAN
Router(config-subif)# ip address 10.0.99.1 255.255.255.0
```

**Switch Layer 3 (SVIs) — Recomendado:**

```cisco
! Habilitar IP routing no switch L3
Switch(config)# ip routing

! Criar SVIs (uma por VLAN)
Switch(config)# interface Vlan10
Switch(config-if)# ip address 192.168.10.1 255.255.255.0
Switch(config-if)# no shutdown

Switch(config)# interface Vlan20
Switch(config-if)# ip address 192.168.20.1 255.255.255.0
Switch(config-if)# no shutdown

! Configurar uplink para router externo
Switch(config)# interface GigabitEthernet1/0/24
Switch(config-if)# no switchport               ! Modo routed (L3)
Switch(config-if)# ip address 10.0.0.2 255.255.255.252
Switch(config-if)# no shutdown

Switch(config)# ip route 0.0.0.0 0.0.0.0 10.0.0.1   ! Default route
```

---

### 6.3 STP — Spanning Tree Protocol

**Problema:** Switches redundantes criam loops de Camada 2 → **Broadcast Storm** → Colapso da rede.

**Solução:** STP elege um Root Bridge e bloqueia portas redundantes, mantendo topologia loop-free.

```yaml
Processo de eleição STP:

Step 1 — Eleger Root Bridge:
  Critério: Menor Bridge ID (Priority + MAC)
  Bridge ID = Priority (2 bytes) + MAC Address (6 bytes)
  Priority padrão: 32768 + VLAN ID
  
  Dica de prova: Para tornar um switch Root Bridge:
    Switch(config)# spanning-tree vlan 10 priority 0    ! Mínimo = 0
    Switch(config)# spanning-tree vlan 10 root primary  ! Configura auto

Step 2 — Eleger Root Ports (em cada switch não-root):
  Critério: Porta com menor custo para o Root Bridge
  Cost por bandwidth:
    10 Mbps  = 100
    100 Mbps = 19
    1 Gbps   = 4
    10 Gbps  = 2
  
  Desempate (mais importante primeiro):
    1. Menor Root Path Cost
    2. Menor Sender Bridge ID
    3. Menor Sender Port ID (priority + number)

Step 3 — Eleger Designated Ports (em cada segmento):
  Em cada segmento: porta do switch mais próximo do Root = Designated Port

Step 4 — Bloquear portas restantes (Alternate/Blocked):
  Portas que criariam loops entram em estado Blocking
```

**Estados STP:**

```yaml
Blocking    (MAX_AGE=20s):  Recebe BPDUs, não aprende MACs, não encaminha
Listening   (15s):          Processa BPDUs, não aprende MACs, não encaminha
Learning    (15s):          Não encaminha, MAS aprende MACs → popula CAM table
Forwarding  :               Operação normal — aprende MACs e encaminha frames
Disabled    :               Porta desligada administrativamente

Convergência total STP: 20 + 15 + 15 = 50 segundos ← MUITO LENTO!
```

**RSTP (802.1w) — Rapid Spanning Tree:**

```yaml
Melhoria principal: Convergência em 1–2 segundos (vs 50s do STP)

Port roles no RSTP:
  Root Port    : Melhor caminho para o Root Bridge (idêntico ao STP)
  Designated   : Melhor porta no segmento (idêntico ao STP)
  Alternate    : Backup do Root Port (era Blocked no STP clássico)
  Backup       : Backup do Designated Port no mesmo segmento
  Disabled     : Desabilitado

Port states RSTP (simplificado):
  Discarding   : Equivale a Blocking + Listening do STP
  Learning     : Aprende MACs, não encaminha
  Forwarding   : Operação normal

Convergência rápida via Proposal/Agreement:
  Switches negociam diretamente sem esperar timers
```

```cisco
! Configurar RSTP (Cisco usa PVST+ por padrão, RPVST+ é o Rapid)
Switch(config)# spanning-tree mode rapid-pvst

! PortFast — para portas de access (end devices, não switches!)
Switch(config)# interface GigabitEthernet0/5
Switch(config-if)# spanning-tree portfast
! Ou globalmente para todas as access ports:
Switch(config)# spanning-tree portfast default

! BPDU Guard — protege PortFast de receber BPDUs (previne loops)
Switch(config-if)# spanning-tree bpduguard enable
! Ou globalmente:
Switch(config)# spanning-tree portfast bpduguard default

! BPDU Filter — ignora BPDUs (cuidado! pode criar loops)
Switch(config-if)# spanning-tree bpdufilter enable

! Root Guard — previne que outras switches se tornem Root
Switch(config-if)# spanning-tree guard root

! Definir prioridade de Root Bridge
Switch(config)# spanning-tree vlan 10 priority 4096
! Ou usar macro:
Switch(config)# spanning-tree vlan 10 root primary
Switch(config)# spanning-tree vlan 10 root secondary

! Verificação
Switch# show spanning-tree
Switch# show spanning-tree vlan 10
Switch# show spanning-tree interface GigabitEthernet0/1 detail
```

---

### 6.4 EtherChannel / LACP

```yaml
Problema: Single link = bottleneck e single point of failure
Solução: Agrupar múltiplos links físicos em um único link lógico

Protocolos:
  LACP (IEEE 802.3ad): Padrão aberto — USAR ESTE
    active  : Inicia negociação LACP
    passive : Aguarda negociação (pelo menos um lado deve ser active)

  PAgP (Cisco proprietário): Legado
    desirable: Inicia negociação
    auto     : Aguarda

  Static (mode on): Sem negociação — RISCO de loop se mal configurado

Regras importantes para a prova:
  ✓ Velocidade e duplex IDÊNTICOS em todos os membros
  ✓ Tipo de porta IDÊNTICO (access ou trunk)
  ✓ VLAN(s) IDÊNTICAS em todos os membros
  ✗ Se uma dessas diferir, o EtherChannel não forma

Modos compatíveis:
  active  + active   → ✓ LACP funciona
  active  + passive  → ✓ LACP funciona
  passive + passive  → ✗ LACP não forma (nenhum inicia)
  on      + on       → ✓ Static (sem protocolo)
  on      + active   → ✗ Não funciona (modos incompatíveis)
```

```cisco
! Configurar EtherChannel LACP
Switch(config)# interface range GigabitEthernet0/1-2
Switch(config-if-range)# channel-group 1 mode active
Switch(config-if-range)# exit

! Configurar o Port-Channel (interface lógica)
Switch(config)# interface Port-channel1
Switch(config-if)# switchport trunk encapsulation dot1q
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20,30

! Load balancing
Switch(config)# port-channel load-balance src-dst-ip

! Verificação
Switch# show etherchannel summary
Switch# show etherchannel 1 detail
Switch# show interfaces Port-channel1

! Output esperado do show etherchannel summary:
! Group  Port-channel  Protocol    Ports
! ------+-------------+-----------+-------
! 1      Po1(SU)         LACP      Gi0/1(P) Gi0/2(P)
! S = Layer2, U = in use, P = bundled in port-channel
```

---

## 7. Roteamento — Estático e OSPF

### 7.1 Tabela de Roteamento e Longest Prefix Match

```yaml
Como ler a tabela de roteamento:
  Router# show ip route

  Codes: C - connected, L - local, S - static, O - OSPF
         R - RIP, B - BGP, D - EIGRP, * - candidate default

  C  192.168.1.0/24 is directly connected, GigabitEthernet0/0
  L  192.168.1.1/32 is directly connected, GigabitEthernet0/0
  S  10.0.0.0/8 [1/0] via 192.168.1.254
  O  172.16.0.0/16 [110/20] via 192.168.1.254, 00:01:23
  S* 0.0.0.0/0 [1/0] via 192.168.1.1    ← Gateway of last resort

Formato: [Administrative Distance / Metric]

Longest Prefix Match (regra mais importante do roteamento):
  Pacote para 172.16.10.5
  Tabela:
    0.0.0.0/0       via 192.168.1.1     ← /0  (menos específico)
    172.16.0.0/16   via 192.168.1.254   ← /16
    172.16.10.0/24  via 10.0.0.1        ← /24 (mais específico = VENCE)
  
  Resultado: Usa 172.16.10.0/24 (maior prefixo que combina)
```

**Administrative Distance — Trustworthiness:**

|Fonte da Rota|AD|Confiabilidade|
|---|---|---|
|Directly Connected|0|Máxima|
|Static Route|1|Altíssima|
|EIGRP Summary|5|—|
|External BGP|20|—|
|Internal EIGRP|90|—|
|**OSPF**|**110**|Alta|
|IS-IS|115|—|
|RIP|120|Baixa|
|External EIGRP|170|—|
|Internal BGP|200|Baixa|
|Unknown / Not used|255|Nenhuma|

> [!NOTE] AD na prova Quando a mesma rede é aprendida por dois protocolos diferentes, **menor AD vence**. Uma rota estática (AD=1) sempre sobrepõe OSPF (AD=110). Para criar uma rota de backup (floating static), use AD > 110: `ip route 0.0.0.0 0.0.0.0 <next-hop> 120`

---

### 7.2 Roteamento Estático

```cisco
! Tipos de rota estática:

! 1. Rota de rede (Network route)
Router(config)# ip route 10.0.0.0 255.0.0.0 192.168.1.254
Router(config)# ip route 10.0.0.0 255.0.0.0 GigabitEthernet0/0   ! Pelo interface

! 2. Default route (gateway of last resort)
Router(config)# ip route 0.0.0.0 0.0.0.0 192.168.1.1

! 3. Host route (/32)
Router(config)# ip route 10.0.0.50 255.255.255.255 192.168.1.254

! 4. Floating static (backup — AD maior que OSPF)
Router(config)# ip route 0.0.0.0 0.0.0.0 10.0.1.1 130
! Só usada se a rota principal (AD < 130) desaparecer

! IPv6 static
Router(config)# ipv6 route 2001:DB8:2::/64 2001:DB8:1::2
Router(config)# ipv6 route ::/0 2001:DB8:1::1     ! IPv6 default

! Verificar
Router# show ip route static
Router# show ip route 10.0.0.0
```

---

### 7.3 OSPF — Open Shortest Path First

```yaml
Características principais do OSPF:
  Tipo      : Link-State (conhece a topologia completa)
  Algoritmo : Dijkstra (SPF — Shortest Path First)
  Métrica   : Cost = 100 Mbps / Bandwidth da interface
  AD        : 110
  Multicast : 224.0.0.5 (todos os routers OSPF)
              224.0.0.6 (DR e BDR)
  Tipo IGP  : Interior Gateway Protocol (dentro de um AS)
  Suporte   : VLSM, CIDR, autenticação, IPv6 (OSPFv3)
```

**Áreas OSPF:**

```yaml
Area 0 (Backbone):
  - Obrigatória
  - Todas as outras áreas devem conectar ao Area 0
  - Routers dentro: Internal Routers

Area Não-Zero (Regular Area):
  - Conecta ao backbone via ABR (Area Border Router)
  - ABR tem interfaces em DUAS áreas

Stub Area:
  - Não recebe rotas externas (Tipo 5 LSAs)
  - Usa default route do ABR para sair da área
  - Reduz tamanho da tabela de roteamento

Totally Stubby Area (Cisco):
  - Não recebe nem rotas externas NEM inter-área
  - Apenas: rotas internas + default route do ABR

NSSA (Not So Stubby Area):
  - Stub area que permite redistribuição de rotas externas
  - Usa LSA Tipo 7 (convertido em Tipo 5 pelo ABR)

Tipos de Routers OSPF:
  Internal Router    : Todas as interfaces na mesma área
  Backbone Router    : Pelo menos uma interface no Area 0
  ABR (Area Border)  : Interfaces em múltiplas áreas
  ASBR (AS Boundary) : Conecta OSPF a outro protocolo de roteamento
```

**Processo de vizinhança OSPF (Adjacência):**

```yaml
Estados de adjacência:

Down      → Nenhuma comunicação
Init      → Hello recebido, mas ainda não bidirec.
2-Way     → Hello bidirecional confirmado
            ↓ Eleição DR/BDR acontece aqui
ExStart   → Negociação Master/Slave para DBD exchange
Exchange  → Troca de DBDs (Database Description)
Loading   → Troca de LSAs (LSRequest / LSUpdate / LSAck)
Full      → Bancos de dados sincronizados (adjacência completa!)

Em redes Broadcast (Ethernet):
  Apenas o DR e BDR formam Full adjacency com todos
  Outros formam 2-Way entre si

Eleição DR/BDR:
  Critério 1: Maior OSPF Priority (padrão: 1, range 0-255)
    Priority 0 = nunca será DR/BDR
  Critério 2: Maior Router ID (desempate)

Router ID (ordem de escolha):
  1. Configurado manualmente: router-id X.X.X.X
  2. IP da loopback mais alta
  3. IP da interface ativa mais alta
```

**Hello Timer e Dead Timer:**

```yaml
Timers OSPF:
  Rede ponto-a-ponto : Hello 10s / Dead 40s
  Rede Broadcast (LAN): Hello 10s / Dead 40s
  NBMA (Frame Relay) : Hello 30s / Dead 120s

Regra: Dead interval = 4 × Hello interval (padrão)
Requisito: Hello e Dead timers DEVEM ser iguais entre vizinhos para formarem adjacência!
```

**Configuração OSPF:**

```cisco
! Processo OSPF (process ID é local, não precisa coincidir entre routers)
Router(config)# router ospf 1
Router(config-router)# router-id 1.1.1.1       ! Sempre configurar manualmente!

! Anunciar redes (usar wildcard mask)
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
Router(config-router)# network 10.0.0.0 0.0.0.3 area 0
Router(config-router)# network 172.16.0.0 0.0.255.255 area 1

! Modo alternativo: configurar por interface (mais moderno)
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip ospf 1 area 0              ! Mais preciso

! Passive interface (não envia Hellos — para interfaces sem vizinhos OSPF)
Router(config-router)# passive-interface GigabitEthernet0/2
Router(config-router)# passive-interface default         ! Todas passivas
Router(config-router)# no passive-interface GigabitEthernet0/0  ! Exceção

! Default route via OSPF
Router(config-router)# default-information originate         ! Precisa ter default route
Router(config-router)# default-information originate always  ! Anuncia mesmo sem default route

! Ajustar custo do link (para corrigir custo com GigabitEthernet)
Router(config-router)# auto-cost reference-bandwidth 10000   ! Para redes 10GbE
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip ospf cost 10                          ! Manual

! Prioridade DR/BDR
Router(config-if)# ip ospf priority 255   ! Garante que será DR
Router(config-if)# ip ospf priority 0    ! Nunca será DR/BDR

! Timers (devem ser iguais no vizinho!)
Router(config-if)# ip ospf hello-interval 5
Router(config-if)# ip ospf dead-interval 20

! Autenticação MD5
Router(config-if)# ip ospf authentication message-digest
Router(config-if)# ip ospf message-digest-key 1 md5 SenhaOSPF

! Verificação
Router# show ip ospf
Router# show ip ospf neighbor
Router# show ip ospf neighbor detail
Router# show ip ospf database
Router# show ip ospf interface GigabitEthernet0/0
Router# show ip route ospf
Router# debug ip ospf events      ! Debug (cuidado em produção!)
```

---

### 7.4 FHRP — First Hop Redundancy Protocol

```yaml
Problema: Default gateway único = single point of failure
Solução: Múltiplos routers compartilham um Virtual IP (VIP)

HSRP (Hot Standby Router Protocol):
  Proprietário Cisco
  Roles: Active / Standby
  Virtual MAC: 0000.0C07.ACXX (XX = group number hex)
  Multicast: 224.0.0.2 (v1) / 224.0.0.102 (v2)
  Hello timer: 3s / Hold timer: 10s
  Preempt: Desabilitado por padrão (habilitar com standby X preempt)

VRRP (Virtual Router Redundancy Protocol):
  Padrão aberto IEEE RFC 5798
  Roles: Master / Backup
  Virtual MAC: 0000.5E00.01XX
  Multicast: 224.0.0.18
  Preempt: Habilitado por padrão (diferente do HSRP!)

GLBP (Gateway Load Balancing Protocol):
  Proprietário Cisco
  Diferencial: Load balancing ativo-ativo (múltiplos gateways)
  AVG: Active Virtual Gateway (responde ARP requests com MACs diferentes)
  AVF: Active Virtual Forwarder (roteia o tráfego)

Comparação:
  Critério          HSRP         VRRP         GLBP
  Padrão            Cisco        IEEE         Cisco
  Roles             Ativo/Standb Master/Backup AVG/AVF
  Load Balancing    Não          Não          Sim (round-robin)
  Preempt padrão    Desabilitado Habilitado   Habilitado
  Versões           v1 e v2      v2 e v3      v1
```

```cisco
! HSRP v2 (recomendado)
Router1(config)# interface GigabitEthernet0/0
Router1(config-if)# ip address 192.168.1.2 255.255.255.0
Router1(config-if)# standby version 2
Router1(config-if)# standby 10 ip 192.168.1.1         ! VIP no grupo 10
Router1(config-if)# standby 10 priority 110           ! Padrão é 100, maior = Active
Router1(config-if)# standby 10 preempt               ! Reassume o role Active se voltar
Router1(config-if)# standby 10 authentication md5 key-string SenhaHSRP

Router2(config)# interface GigabitEthernet0/0
Router2(config-if)# ip address 192.168.1.3 255.255.255.0
Router2(config-if)# standby version 2
Router2(config-if)# standby 10 ip 192.168.1.1         ! Mesmo VIP
Router2(config-if)# standby 10 priority 100           ! Será Standby
Router2(config-if)# standby 10 preempt

! Clientes usam 192.168.1.1 como gateway
! Se Router1 falhar, Router2 assume automaticamente

! Verificação
Router# show standby
Router# show standby brief
```

---

## 8. Wireless — 802.11 e WLC

### 8.1 Padrões 802.11

|Padrão|Frequência|Max Speed|Range|Geração|
|---|---|---|---|---|
|**802.11b**|2.4 GHz|11 Mbps|~35m indoor|Wi-Fi 1 (1999)|
|**802.11g**|2.4 GHz|54 Mbps|~38m indoor|Wi-Fi 3 (2003)|
|**802.11a**|5 GHz|54 Mbps|~35m indoor|Wi-Fi 2 (1999)|
|**802.11n**|2.4 / 5 GHz|600 Mbps|~70m indoor|Wi-Fi 4 (2009)|
|**802.11ac**|5 GHz|6.9 Gbps|~35m indoor|Wi-Fi 5 (2013)|
|**802.11ax**|2.4 / 5 / 6 GHz|9.6 Gbps|~30m indoor|Wi-Fi 6 (2019)|

> [!NOTE] Canais 2.4 GHz Somente **3 canais não sobrepostos** em 2.4 GHz: **1, 6, 11**. Em ambientes com múltiplos APs, configure esses canais para evitar interferência co-canal (CCI). Na faixa de 5 GHz há muito mais canais disponíveis sem sobreposição.

---

### 8.2 Segurança Wireless

|Protocolo|Criptografia|Autenticação|Seguro?|
|---|---|---|---|
|**Open**|Nenhuma|Nenhuma|❌ Nunca usar|
|**WEP**|RC4 (40/104-bit)|Senha compartilhada|❌ Quebrado em minutos|
|**WPA**|TKIP (RC4 melhorado)|PSK / 802.1X|❌ Depreciado|
|**WPA2-Personal**|AES (CCMP)|PSK (senha)|✅ Aceitável para uso pessoal|
|**WPA2-Enterprise**|AES (CCMP)|802.1X + RADIUS|✅ Produção corporativa|
|**WPA3-Personal**|AES / SAE|SAE (sem PSK)|✅ Melhor proteção offline|
|**WPA3-Enterprise**|192-bit Suite-B|802.1X + RADIUS|✅ Mais seguro|

```yaml
802.1X Enterprise — Fluxo de autenticação:

Componentes:
  Supplicant  : Dispositivo do usuário (laptop, phone)
  Authenticator: AP ou Switch (reencaminha para RADIUS)
  Auth Server : RADIUS (verifica credenciais no AD/LDAP)

Fluxo:
  1. Usuário conecta ao AP
  2. AP bloqueia todo tráfego (exceto EAP)
  3. AP encaminha credenciais para RADIUS (via EAP over RADIUS)
  4. RADIUS verifica no Active Directory
  5. RADIUS → AP: Access-Accept (com VLAN assignment, etc.)
  6. AP libera o tráfego do usuário

EAP Methods (da mais para menos segura):
  EAP-TLS: Certificado no cliente E servidor (mais seguro)
  PEAP-MSCHAPv2: Certificado só no servidor + usuário/senha
  EAP-FAST: Cisco, usa PAC (Protected Access Credential)
```

---

### 8.3 Arquitetura WLC (Controller-Based)

```yaml
Componentes:

WLC (Wireless LAN Controller):
  - Gerencia todos os APs centralizadamente
  - Configuração, autenticação, RF management
  - Detecção de Rogue APs
  - Roaming entre APs sem re-autenticação

LAP (Lightweight Access Point):
  - Zero configuração local (plug-and-play)
  - Descobre o WLC via CAPWAP (Control And Provisioning of WAPs)
  - Opções de descoberta: Broadcast, DHCP option 43, DNS (CISCO-CAPWAP-CONTROLLER)

CAPWAP (RFC 5415):
  Túnel de controle: UDP 5246 (criptografado com DTLS)
  Túnel de dados:    UDP 5247 (opcional criptografia)

Modos de operação do LAP:
  Local Mode: Dados passam pelo WLC (recomendado para campus)
  FlexConnect: AP pode comutar tráfego localmente (branches sem WAN)
  Monitor: Apenas captura de pacotes (IDS wireless)
  Sniffer: Captura e envia para Wireshark
  Rogue Detector: Detecta APs não autorizados
  Bridge: WAN sem fio entre prédios

SSID → VLAN mapping (no WLC):
  SSID "Corporativo" → VLAN 10 (funcionários)
  SSID "Visitantes"  → VLAN 50 (isolada, internet only)
  SSID "IoT"         → VLAN 70 (dispositivos IoT)
```

---

## 9. Serviços IP — DHCP, DNS, NAT, NTP

### 9.1 DHCP

```yaml
Processo DORA:
  D — Discover : Cliente broadcast (255.255.255.255:67), "Alguém tem um IP para mim?"
  O — Offer    : Servidor responde com oferta (IP, máscara, gateway, DNS, lease time)
  R — Request  : Cliente aceita a oferta (ainda em broadcast — informa outros servidores)
  A — ACK      : Servidor confirma a atribuição

Mensagem Discover:
  Source IP  : 0.0.0.0 (ainda sem IP)
  Source MAC : MAC do cliente
  Dest IP    : 255.255.255.255 (broadcast)
  Dest MAC   : FF:FF:FF:FF:FF:FF

Renovação (Lease Renewal):
  T1 (50% do lease): Cliente tenta renovar com o servidor original (unicast)
  T2 (87.5%):        Se falhou no T1, broadcast para qualquer servidor DHCP
  Expirado:          Start DORA novamente, IP liberado
```

```cisco
! DHCP Server no Cisco IOS
Router(config)# ip dhcp excluded-address 192.168.1.1 192.168.1.20   ! Reservar para infra
Router(config)# ip dhcp excluded-address 192.168.1.200 192.168.1.255 ! Reservar para servidores

Router(config)# ip dhcp pool LAN-POOL
Router(dhcp-config)# network 192.168.1.0 255.255.255.0
Router(dhcp-config)# default-router 192.168.1.1
Router(dhcp-config)# dns-server 8.8.8.8 1.1.1.1
Router(dhcp-config)# domain-name empresa.com.br
Router(dhcp-config)# lease 7                   ! 7 dias (padrão é 1 dia)

! DHCP Relay Agent (quando o servidor DHCP está em outra sub-rede)
Router(config)# interface GigabitEthernet0/1    ! Interface voltada para os clientes
Router(config-if)# ip helper-address 10.0.0.10  ! IP do servidor DHCP centralizado

! Verificação
Router# show ip dhcp binding          ! Tabela de concessões
Router# show ip dhcp pool             ! Estatísticas dos pools
Router# show ip dhcp conflict         ! IPs com conflito detectado
Router# clear ip dhcp binding *       ! Limpar todas as concessões (lab apenas!)

! DHCP Snooping (proteção contra Rogue DHCP server)
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 10,20,30
Switch(config)# interface GigabitEthernet0/1       ! Porta do servidor DHCP legítimo
Switch(config-if)# ip dhcp snooping trust
! Todas as outras portas são "untrusted" (não podem enviar DHCP Offers)
Switch(config)# ip dhcp snooping limit rate 10     ! Max 10 pkts/s por porta
```

---

### 9.2 DNS

```yaml
Hierarquia DNS:
  Root (.)           → "Quem cuida de .com?"
  TLD (.com, .br)    → "Quem cuida de google.com?"
  Authoritative      → "Qual o IP de www.google.com?" → 142.250.x.x
  Recursive Resolver → Coordena a resolução completa (cache)

Tipos de registros:
  A     : Nome → IPv4 (www.empresa.com → 192.0.2.1)
  AAAA  : Nome → IPv6
  CNAME : Alias → Nome canônico (www → empresa.com)
  MX    : Domínio → Servidor de e-mail (com priority)
  NS    : Domínio → Name Server autoritativo
  PTR   : IP → Nome (DNS reverso, 1.2.168.192.in-addr.arpa)
  TXT   : Texto livre (SPF, DKIM, validações de domínio)
  SOA   : Start of Authority (informações da zona)

TTL (Time To Live): Tempo que o registro fica em cache (segundos)
  Baixo TTL (60s):  Mudanças propagam rápido, mais queries
  Alto TTL (86400): Menos queries, mudanças demoram a propagar
```

---

### 9.3 NAT / PAT

```yaml
Por que NAT?
  → Conserva endereços IPv4 públicos (esvaimento)
  → Oculta estrutura interna (segurança básica)
  → Permite uso de RFC 1918 internamente

Terminologia NAT:
  Inside Local  : IP privado do host interno (192.168.1.10)
  Inside Global : IP público que representa o host interno (200.1.1.1:10001)
  Outside Local : IP que o host interno vê do servidor externo (normalmente = Outside Global)
  Outside Global: IP real do servidor externo (8.8.8.8)
```

```cisco
! PAT (NAT Overload) — o mais comum, todos os hosts → 1 IP público
Router(config)# access-list 1 permit 192.168.0.0 0.0.255.255

! Opção 1: Usar IP da interface WAN (dinâmico, IP muda)
Router(config)# ip nat inside source list 1 interface GigabitEthernet0/0 overload

! Opção 2: Usar IP estático público
Router(config)# ip nat inside source list 1 pool NAT-POOL overload
Router(config)# ip nat pool NAT-POOL 200.1.1.1 200.1.1.1 netmask 255.255.255.0

! Marcar interfaces
Router(config)# interface GigabitEthernet0/0    ! WAN
Router(config-if)# ip nat outside

Router(config)# interface GigabitEthernet0/1    ! LAN
Router(config-if)# ip nat inside

! NAT Estático (para servidores internos)
Router(config)# ip nat inside source static 192.168.1.100 200.1.1.10

! Port Forwarding (Static PAT)
Router(config)# ip nat inside source static tcp 192.168.1.100 80 200.1.1.1 80

! Verificação
Router# show ip nat translations
Router# show ip nat statistics
Router# debug ip nat          ! (cuidado em produção!)
Router# clear ip nat translation *  ! Limpar tabela (lab)
```

---

### 9.4 NTP

```yaml
Importância crítica:
  → Logs de auditoria com timestamps precisos (forensics)
  → Certificados SSL/TLS (validação de datas)
  → Kerberos (tolerância máxima: 5 minutos)
  → Compliance (PCI-DSS, SOX, LGPD)

Stratum:
  0  : Fonte de referência (GPS, relógio atômico)
  1  : Servidor NTP primário (conectado ao stratum 0)
  2  : Servidor NTP secundário (sincronizado com stratum 1)
  ... : Cada hop adiciona 1 ao stratum
  16 : Unsynchronized (erro)
```

```cisco
! Configurar cliente NTP
Router(config)# ntp server 129.6.15.28 prefer     ! time.nist.gov
Router(config)# ntp server 200.160.7.186           ! NTP.br

! Configurar timezone
Router(config)# clock timezone BRT -3
Router(config)# clock summer-time BRST recurring

! NTP com autenticação (recomendado)
Router(config)# ntp authenticate
Router(config)# ntp authentication-key 1 md5 NTPSenhaSegura
Router(config)# ntp trusted-key 1
Router(config)# ntp server 129.6.15.28 key 1

! Verificação
Router# show ntp status
Router# show ntp associations
Router# show clock detail
```

---

## 10. Gerenciamento — SSH, Syslog, SNMP, CDP/LLDP

### 10.1 SSH — Acesso Seguro

```cisco
! Pré-requisitos para SSH
Router(config)# hostname SW-CORE-01         ! Hostname configurado
Router(config)# ip domain-name empresa.com.br
Router(config)# crypto key generate rsa modulus 2048  ! Gera par de chaves RSA

! SSH configuração
Router(config)# ip ssh version 2            ! Apenas SSHv2 (v1 é inseguro)
Router(config)# ip ssh time-out 60          ! Timeout de autenticação (segundos)
Router(config)# ip ssh authentication-retries 3

! Usuário local para autenticação
Router(config)# username admin privilege 15 algorithm-type scrypt secret SenhaForte123!

! VTY lines — aceitar apenas SSH (nunca Telnet!)
Router(config)# line vty 0 15
Router(config-line)# transport input ssh    ! Bloqueia Telnet
Router(config-line)# login local            ! Usa banco local de usuários
Router(config-line)# exec-timeout 10 0     ! Logout automático: 10 minutos
Router(config-line)# logging synchronous

! Console line
Router(config)# line console 0
Router(config-line)# exec-timeout 5 0
Router(config-line)# login local
Router(config-line)# logging synchronous

! Verificação
Router# show ip ssh
Router# show ssh
```

---

### 10.2 Syslog

```yaml
Níveis de severidade (memorize para a prova):

Nível  Keyword      Descrição
  0    Emergency    Sistema inoperante (raro em routers)
  1    Alert        Ação imediata necessária
  2    Critical     Condição crítica
  3    Error        Condição de erro
  4    Warning      Aviso (potencial problema)
  5    Notice       Normal, mas significativo
  6    Informational Informação de operação normal
  7    Debug        Debug (NUNCA em produção!)

Mnemônico: "Every Awful Cisco Engineer Will Never Debug"
  (Emergency, Alert, Critical, Error, Warning, Notice, Debug)

Nota: configurar "logging trap X" = envia até o nível X ao servidor
  Exemplo: logging trap 5 → envia Emergency, Alert, Critical, Error, Warning, Notice
  (do nível 0 ao 5, incluindo o 5)
```

```cisco
! Logging local (buffer)
Router(config)# logging buffered 64000 informational

! Logging para servidor Syslog externo
Router(config)# logging host 10.0.0.100
Router(config)# logging trap warnings     ! Envia nível 0-4 ao servidor
Router(config)# logging source-interface Loopback0  ! IP de origem consistente

! Timestamps nos logs
Router(config)# service timestamps log datetime msec localtime show-timezone

! Console e Monitor
Router(config)# logging console warnings    ! O que aparece no console
Router(config)# logging monitor debugging   ! Para "terminal monitor"

! Ativar logs no terminal SSH ativo
Router# terminal monitor

! Verificação
Router# show logging
```

---

### 10.3 SNMP

```yaml
Componentes:
  NMS (Network Management System): Servidor de monitoramento (Zabbix, PRTG, LibreNMS)
  Agent: Processo no dispositivo gerenciado
  MIB (Management Information Base): Banco de objetos gerenciáveis
  OID (Object Identifier): Identificador único de cada objeto na MIB

Operações:
  Get     : NMS lê um valor do agent
  GetNext : NMS lê o próximo OID (walk)
  GetBulk : NMS lê múltiplos OIDs de uma vez (v2c/v3)
  Set     : NMS escreve um valor no agent (cuidado!)
  Trap    : Agent envia alerta proativamente para o NMS
  Inform  : Trap com confirmação de recebimento (v2c/v3)

Versões:
  v1  : Community strings plaintext, sem segurança
  v2c : Melhora performance (GetBulk), ainda community strings
  v3  : Autenticação (MD5/SHA) + Criptografia (DES/AES) — OBRIGATÓRIO em produção
```

```cisco
! SNMPv3 (único recomendado para produção)
Router(config)# snmp-server group MONIT-GROUP v3 priv
Router(config)# snmp-server user zabbix MONIT-GROUP v3 \
  auth sha SenhaAuth123 priv aes 128 SenhaPriv456

! Configurar NMS que pode fazer queries
Router(config)# snmp-server host 10.0.0.100 version 3 priv zabbix

! Traps úteis
Router(config)# snmp-server enable traps bgp
Router(config)# snmp-server enable traps ospf
Router(config)# snmp-server enable traps config
Router(config)# snmp-server enable traps cpu threshold

! SNMPv2c (apenas para compatibilidade legada)
Router(config)# snmp-server community SOMENTE-LEITURA RO 10   ! ACL 10 limita quem pode
Router(config)# access-list 10 permit 10.0.0.100

! Verificação
Router# show snmp
Router# show snmp user
Router# show snmp group
```

---

### 10.4 CDP e LLDP

```yaml
CDP (Cisco Discovery Protocol):
  - Proprietário Cisco, Camada 2 (não roteável)
  - Anúncios multicast: 01:00:0C:CC:CC:CC
  - Timer: 60s (hello) / 180s (holdtime)
  - Informações trocadas: Device ID, Platform, Capabilities,
    IP Address, Interface, VTP Domain, Native VLAN

  Segurança: Desabilitar em interfaces voltadas para a internet/usuários!
    (vaza informações de topologia)

LLDP (Link Layer Discovery Protocol):
  - Padrão aberto IEEE 802.1AB
  - Funciona com qualquer vendor
  - Necessário habilitar manualmente no Cisco
```

```cisco
! CDP
Router# show cdp neighbors             ! Lista vizinhos resumido
Router# show cdp neighbors detail      ! Detalhes completos (IP, plataforma)
Router# show cdp entry SW-CORE-01     ! Informações de um vizinho específico

! Desabilitar CDP globalmente (recomendado em produção)
Router(config)# no cdp run
! Desabilitar por interface (melhor opção — manter em uplinks, desabilitar em edge)
Router(config)# interface GigabitEthernet0/0
Router(config-if)# no cdp enable

! LLDP (desabilitado por padrão no Cisco)
Router(config)# lldp run
Router(config)# interface GigabitEthernet0/0
Router(config-if)# lldp transmit
Router(config-if)# lldp receive

Router# show lldp neighbors
Router# show lldp neighbors detail
```

---

## 11. Segurança — ACLs, Layer 2 e VPN

### 11.1 ACLs — Access Control Lists

```yaml
Tipos:
  Standard (1-99, 1300-1999): Filtra apenas por SOURCE IP
    → Aplicar PERTO DO DESTINO (para não bloquear outros caminhos)

  Extended (100-199, 2000-2699): Filtra por Src IP, Dst IP, Protocolo, Portas
    → Aplicar PERTO DA ORIGEM (bloqueia o tráfego antes de cruzar a rede)

  Named: Mesmo comportamento, nome descritivo, permite editar linhas

Regras de processamento:
  1. Avaliação TOP-DOWN (primeira regra que casa = ação tomada)
  2. Implicit deny all ao final (deny any any invisível)
  3. Uma ACL por interface por direção (in ou out)
  4. Direção "in" = tráfego CHEGANDO na interface do router
  5. Direção "out" = tráfego SAINDO pela interface do router
```

```cisco
! ============================================================
! ACL Standard — filtrar por origem
! ============================================================
Router(config)# access-list 10 remark "Permite apenas rede corporativa"
Router(config)# access-list 10 permit 10.0.0.0 0.0.255.255
Router(config)# access-list 10 deny any log          ! Log das negações

! Aplicar na interface (próximo ao destino)
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip access-group 10 out

! ============================================================
! ACL Extended Named — filtrar com granularidade máxima
! ============================================================
Router(config)# ip access-list extended POLITICA-WEB

! Permite HTTPS de qualquer lugar para o servidor web
Router(config-ext-nacl)# 10 permit tcp any host 192.168.1.100 eq 443

! Permite HTTP apenas da rede interna
Router(config-ext-nacl)# 20 permit tcp 10.0.0.0 0.0.255.255 host 192.168.1.100 eq 80

! Bloqueia tudo mais para o servidor
Router(config-ext-nacl)# 30 deny ip any host 192.168.1.100 log

! Permite todo o resto
Router(config-ext-nacl)# 40 permit ip any any

! Aplicar (próximo à origem)
Router(config)# interface GigabitEthernet0/0
Router(config-if)# ip access-group POLITICA-WEB in

! ============================================================
! Editar ACL Named (adicionar/remover linhas)
! ============================================================
Router(config)# ip access-list extended POLITICA-WEB
Router(config-ext-nacl)# 15 permit tcp host 172.16.1.5 host 192.168.1.100 eq 443
Router(config-ext-nacl)# no 30     ! Remove a linha 30

! ============================================================
! Verificação
! ============================================================
Router# show access-lists
Router# show access-lists POLITICA-WEB
Router# show ip interface GigabitEthernet0/0      ! Mostra ACL aplicada
Router# clear ip access-list counters             ! Zera contadores de match
```

---

### 11.2 Layer 2 Security

**DAI — Dynamic ARP Inspection:**

```cisco
! Protege contra ARP spoofing/poisoning
! Depende da tabela do DHCP Snooping para validar

Switch(config)# ip arp inspection vlan 10,20,30

! Trust na porta do router/uplink (que não usa DHCP Snooping)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip arp inspection trust

! Rate limit (previne ARP flood)
Switch(config)# interface range FastEthernet0/1-24
Switch(config-if-range)# ip arp inspection limit rate 15 burst interval 1

! Verificação
Switch# show ip arp inspection
Switch# show ip arp inspection statistics
Switch# show ip arp inspection vlan 10
```

**Port Security:**

```cisco
! Limitar MACs permitidos por porta
Switch(config)# interface FastEthernet0/5
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# switchport port-security                  ! Habilita port security
Switch(config-if)# switchport port-security maximum 2        ! Máx 2 MACs
Switch(config-if)# switchport port-security mac-address sticky ! Aprende automaticamente

! Violation actions:
!   shutdown : Desabilita a porta (err-disabled) — MAIS SEGURO
!   restrict : Descarta frames, incrementa contador, mantém porta UP
!   protect  : Descarta frames silenciosamente, mantém porta UP

Switch(config-if)# switchport port-security violation restrict

! Recuperar porta err-disabled automaticamente
Switch(config)# errdisable recovery cause psecure-violation
Switch(config)# errdisable recovery interval 300     ! Tenta reativar após 300s

! Verificação
Switch# show port-security
Switch# show port-security interface FastEthernet0/5
Switch# show port-security address
```

---

### 11.3 VPN e IPsec — Conceitos CCNA

```yaml
VPN Types no CCNA:

Site-to-Site VPN:
  → Conecta duas redes permanentemente
  → Configurado nos gateways (routers/firewalls)
  → Transparente para os usuários
  → Protocolo: IPsec

Remote Access VPN:
  → Usuário individual conecta à rede corporativa
  → Requer cliente VPN no dispositivo do usuário
  → Protocols: IPsec, SSL/TLS (AnyConnect)

IPsec — Building Blocks:

  IKE Phase 1 (ISAKMP SA):
    → Cria canal seguro para negociação
    → Autentica os peers (PSK ou certificados)
    → Parâmetros: Encryption (AES), Hash (SHA), DH Group, Lifetime

  IKE Phase 2 (IPsec SA):
    → Negocia parâmetros de proteção dos dados
    → Cria os SAs (Security Associations) bidirecionais
    → Define: Transform set (AH ou ESP), modo (Tunnel/Transport)

  Protocolos:
    AH (Authentication Header, protocol 51):
      → Autenticação + integridade, SEM criptografia
      → Problemas com NAT (inclui IP no hash)

    ESP (Encapsulating Security Payload, protocol 50):
      → Autenticação + integridade + CRIPTOGRAFIA
      → Padrão atual — SEMPRE usar ESP

  Modos:
    Tunnel Mode : Encapsula o pacote IP inteiro (site-to-site)
    Transport Mode: Protege apenas o payload (host-to-host)
```

---

## 12. Automação — SDN, APIs e Python

### 12.1 SDN — Software Defined Networking

```yaml
Tradicional vs SDN:

  Plano de Controle (decisões de roteamento):
    Tradicional: Cada dispositivo tem seu próprio controle
    SDN:         Centralizado no Controller

  Plano de Dados (forwarding):
    Ambos: Nos dispositivos físicos (hardware)

  Plano de Gerência:
    Tradicional: CLI por dispositivo
    SDN:         API centralizada no Controller

Camadas SDN:
  Application Layer : Apps de rede (customizações, orchestration)
       ↕ Northbound API (REST — entre Controller e apps)
  Control Layer     : SDN Controller (OpenDaylight, Cisco DNA Center, ONOS)
       ↕ Southbound API (OpenFlow, NETCONF/YANG, RESTCONF)
  Infrastructure Layer: Switches e routers físicos

Cisco DNA Center:
  - Controller SDN da Cisco
  - Northbound: REST API (JSON)
  - Southbound: NETCONF/YANG para IOS XE
  - Features: Intent-based networking, automation, assurance
```

---

### 12.2 Formatos de Dados — JSON, XML, YAML

```json
// JSON (JavaScript Object Notation) — mais usado em APIs REST
{
  "device": {
    "hostname": "SW-CORE-01",
    "ip": "10.0.99.10",
    "platform": "Cisco Catalyst 9300",
    "interfaces": [
      {
        "name": "GigabitEthernet1/0/1",
        "status": "connected",
        "vlan": 10
      },
      {
        "name": "GigabitEthernet1/0/2",
        "status": "notconnect",
        "vlan": 20
      }
    ]
  }
}
```

```xml
<!-- XML (eXtensible Markup Language) — usado no NETCONF -->
<device>
  <hostname>SW-CORE-01</hostname>
  <ip>10.0.99.10</ip>
  <interfaces>
    <interface>
      <name>GigabitEthernet1/0/1</name>
      <status>connected</status>
      <vlan>10</vlan>
    </interface>
  </interfaces>
</device>
```

```yaml
# YAML — usado no Ansible, Kubernetes, etc.
device:
  hostname: SW-CORE-01
  ip: 10.0.99.10
  interfaces:
    - name: GigabitEthernet1/0/1
      status: connected
      vlan: 10
    - name: GigabitEthernet1/0/2
      status: notconnect
      vlan: 20
```

---

### 12.3 REST API — Interagindo com Cisco DNA Center

```bash
# Autenticar e obter token
curl -X POST "https://dnac.empresa.com/dna/system/api/v1/auth/token" \
  -u "admin:SenhaDNA" \
  -H "Content-Type: application/json" \
  -k | python3 -m json.tool

# Listar dispositivos
TOKEN="eyJhbGci..."
curl -X GET "https://dnac.empresa.com/dna/intent/api/v1/network-device" \
  -H "X-Auth-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -k | python3 -m json.tool

# Resposta JSON:
# {
#   "response": [
#     {
#       "hostname": "SW-CORE-01",
#       "managementIpAddress": "10.0.99.10",
#       "platformId": "C9300-48P",
#       "softwareVersion": "17.9.3"
#     }
#   ]
# }
```

---

### 12.4 Netmiko — Automação SSH em Python

```python
#!/usr/bin/env python3
"""
network_audit.py — Coleta informações de múltiplos switches via SSH
"""

from netmiko import ConnectHandler
import json

DISPOSITIVOS = [
    {"device_type": "cisco_ios", "host": "10.0.99.10",
     "username": "admin", "password": "SenhaForte!", "secret": "Enable123!"},
    {"device_type": "cisco_ios", "host": "10.0.99.11",
     "username": "admin", "password": "SenhaForte!", "secret": "Enable123!"},
]

COMANDOS = [
    "show version | include Version",
    "show ip interface brief",
    "show vlan brief",
    "show spanning-tree summary",
]

resultados = {}

for dispositivo in DISPOSITIVOS:
    host = dispositivo["host"]
    print(f"[*] Conectando em {host}...")
    try:
        conn = ConnectHandler(**dispositivo)
        conn.enable()

        resultados[host] = {}
        for cmd in COMANDOS:
            output = conn.send_command(cmd)
            resultados[host][cmd] = output
            print(f"  ✓ {cmd}")

        conn.disconnect()
        print(f"[+] {host} coletado com sucesso\n")

    except Exception as e:
        resultados[host] = {"error": str(e)}
        print(f"[!] Erro em {host}: {e}\n")

# Salvar resultados
with open("auditoria_rede.json", "w") as f:
    json.dump(resultados, f, indent=2, ensure_ascii=False)

print("[✓] Auditoria concluída! Resultados salvos em auditoria_rede.json")
```

---

### 12.5 Ansible para Automação de Rede

```yaml
# inventory.ini
[core_switches]
sw-core-01  ansible_host=10.0.99.10
sw-core-02  ansible_host=10.0.99.11

[distribution]
sw-dist-01  ansible_host=10.0.10.10
sw-dist-02  ansible_host=10.0.10.11

[all:vars]
ansible_network_os=ios
ansible_connection=network_cli
ansible_user=admin
ansible_password="{{ vault_switch_password }}"    # Usar Ansible Vault!
ansible_become=yes
ansible_become_method=enable
ansible_become_password="{{ vault_enable_password }}"
```

```yaml
# playbook-configurar-vlans.yml
---
- name: Configurar VLANs e trunks nos switches
  hosts: core_switches
  gather_facts: no

  vars:
    vlans:
      - { id: 10, name: VENDAS }
      - { id: 20, name: ENGENHARIA }
      - { id: 30, name: RH }
      - { id: 99, name: GERENCIA }
      - { id: 999, name: NATIVE-UNUSED }

  tasks:
    - name: "Criar VLANs"
      cisco.ios.ios_vlans:
        config:
          - vlan_id: "{{ item.id }}"
            name: "{{ item.name }}"
        state: merged
      loop: "{{ vlans }}"

    - name: "Configurar trunk nos uplinks"
      cisco.ios.ios_l2_interfaces:
        config:
          - name: GigabitEthernet1/0/24
            mode: trunk
            trunk:
              native_vlan: 999
              allowed_vlans: "10,20,30,99"
        state: merged

    - name: "Habilitar Rapid PVST+"
      cisco.ios.ios_config:
        lines:
          - spanning-tree mode rapid-pvst

    - name: "Salvar configuração"
      cisco.ios.ios_command:
        commands:
          - write memory
```

```bash
# Executar o playbook
ansible-playbook -i inventory.ini playbook-configurar-vlans.yml

# Dry-run (ver o que seria feito sem aplicar)
ansible-playbook -i inventory.ini playbook-configurar-vlans.yml --check --diff

# Com Ansible Vault para senhas
ansible-playbook -i inventory.ini playbook-configurar-vlans.yml \
  --vault-password-file ~/.vault_pass
```

---

## Referência Rápida — Comandos Cisco IOS

### Comandos Essenciais por Categoria

```cisco
! ============================================================
! MODO PRIVILEGIADO (enable)
! ============================================================
Switch# show version                   ! IOS version, uptime, hardware
Switch# show running-config            ! Config ativa na RAM
Switch# show startup-config            ! Config salva na NVRAM
Switch# show interfaces                ! Status e counters de todas as interfaces
Switch# show interfaces status         ! Resumo rápido de todas as portas
Switch# show ip interface brief        ! Status e IP de todas as interfaces
Switch# show ip route                  ! Tabela de roteamento
Switch# show arp                       ! Tabela ARP
Switch# copy running-config startup-config  ! Salvar config (= write memory)
Switch# erase startup-config           ! Apagar config (factory reset)
Switch# reload                         ! Reiniciar o dispositivo

! ============================================================
! VERIFICAÇÃO DE SWITCHING
! ============================================================
Switch# show mac address-table
Switch# show vlan brief
Switch# show interfaces trunk
Switch# show interfaces GigabitEthernet0/1 switchport
Switch# show spanning-tree
Switch# show spanning-tree vlan 10
Switch# show etherchannel summary
Switch# show port-security

! ============================================================
! VERIFICAÇÃO DE ROTEAMENTO
! ============================================================
Router# show ip route
Router# show ip route ospf
Router# show ip ospf neighbor
Router# show ip ospf database
Router# show ip ospf interface brief
Router# show ip protocols
Router# show ip nat translations
Router# show ip dhcp binding
Router# show standby brief             ! HSRP status

! ============================================================
! DIAGNÓSTICO
! ============================================================
Router# ping 8.8.8.8
Router# ping 8.8.8.8 source GigabitEthernet0/0  ! Ping com origem específica
Router# traceroute 8.8.8.8
Router# telnet 192.168.1.1 80         ! Testar porta TCP
Router# debug ip packet               ! CUIDADO: sobrecarga em produção!
Router# undebug all                   ! Desabilitar todos os debugs
Router# terminal monitor              ! Ver logs no terminal SSH

! ============================================================
! CONFIGURAÇÃO BÁSICA DE SEGURANÇA
! ============================================================
Switch(config)# no ip http server              ! Desabilitar HTTP
Switch(config)# no ip http secure-server       ! Desabilitar HTTPS GUI
Switch(config)# no service finger
Switch(config)# no service pad
Switch(config)# no ip source-route
Switch(config)# service password-encryption    ! Criptografa senhas no config
Switch(config)# security passwords min-length 12
Switch(config)# login block-for 120 attempts 3 within 60  ! Lockout após 3 falhas

! Banner de aviso (obrigatório em empresas — evidência legal)
Switch(config)# banner motd ^
  *** AVISO: Acesso restrito a pessoal autorizado. ***
  *** Todas as atividades são monitoradas e registradas. ***
  ^
```

---

## 📊 Tabelas de Referência Final

### Administrative Distance

|Protocolo|AD|
|---|---|
|Connected|0|
|Static|1|
|eBGP|20|
|EIGRP (interno)|90|
|**OSPF**|**110**|
|IS-IS|115|
|RIP|120|
|iBGP|200|

### Custo OSPF por Bandwidth

|Interface|Bandwidth|Custo (ref 100M)|Custo (ref 10G)|
|---|---|---|---|
|Serial (T1)|1.544 Mbps|64|6476|
|FastEthernet|100 Mbps|**1**|100|
|GigabitEthernet|1 Gbps|**1** (incorreto)|**10**|
|10 GigabitEthernet|10 Gbps|**1** (incorreto)|**1**|

> [!WARNING] Auto-cost Reference Bandwidth Sempre configure `auto-cost reference-bandwidth 10000` em ambientes com links GigabitEthernet ou superiores! O padrão de 100Mbps atribui custo 1 para FastEthernet, GigabitEthernet E 10GigabitEthernet — impossível distinguir.

### STP Port States e Timers

|Estado|Aprende MAC|Encaminha|Duração|
|---|---|---|---|
|Blocking|❌|❌|20s (Max Age)|
|Listening|❌|❌|15s (Forward Delay)|
|Learning|✅|❌|15s (Forward Delay)|
|Forwarding|✅|✅|Indefinido|

### Protocolos e Portas — Prova CCNA

|Protocolo|Porta|Transport|Notas|
|---|---|---|---|
|FTP Control|21|TCP|Controle de sessão|
|FTP Data|20|TCP|Transferência de dados|
|SSH|22|TCP|**Usar sempre no lugar do Telnet**|
|Telnet|23|TCP|**NUNCA usar em produção**|
|SMTP|25|TCP|Envio de e-mail|
|DNS|53|**UDP** (queries) / TCP (transfers)|UDP para respostas < 512 bytes|
|DHCP Server|67|UDP|DHCP server escuta aqui|
|DHCP Client|68|UDP|DHCP client recebe aqui|
|TFTP|69|UDP|Sem autenticação!|
|HTTP|80|TCP||
|POP3|110|TCP||
|NTP|123|UDP||
|IMAP|143|TCP||
|SNMP|161/162|UDP|161=queries, 162=traps|
|LDAP|389|TCP|Active Directory|
|HTTPS|443|TCP||
|Syslog|514|UDP||
|LDAPS|636|TCP|LDAP sobre TLS|
|RDP|3389|TCP||

---

## 🔗 Recursos para o Exame

**Cisco Official:**

- Exam Topics: https://www.cisco.com/c/en/us/training-events/training-certifications/certifications/associate/ccna.html
- Packet Tracer: https://www.netacad.com/courses/packet-tracer
- Learning Network: https://learningnetwork.cisco.com/

**Prática:**

- GNS3: https://www.gns3.com/ (simulador completo)
- EVE-NG: https://www.eve-ng.net/ (profissional)
- Cisco Modeling Labs: https://developer.cisco.com/modeling-labs/

**Referência:**

- Subnet Calculator: https://www.subnet-calculator.com/
- IPv6 Subnet Calculator: https://www.ultratools.com/tools/ipv6CIDRToRange
- Cisco Command Reference: https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-command-reference-list.html

---

## 📝 Changelog

|Data|Versão|Alteração|
|---|---|---|
|2026-03-02|1.0|Documento criado — CCNA 200-301 completo|

---

> [!INFO] Ordem de Estudo Recomendada
> 
> 1. **Semana 1-2**: Seções 1-3 (OSI, TCP/IP, Ethernet + Subnetting intenso)
> 2. **Semana 3**: Seção 4-5 (IPv4 completo + IPv6)
> 3. **Semana 4-5**: Seção 6 (Switching, VLANs, STP — maior peso da prova)
> 4. **Semana 6-7**: Seção 7 (Roteamento — OSPF é obrigatório dominar)
> 5. **Semana 8**: Seções 8-10 (Wireless, Serviços IP, Gerenciamento)
> 6. **Semana 9**: Seções 11-12 (Segurança, Automação)
> 7. **Semana 10**: Revisão + Simulados (mínimo 3 simulados completos antes da prova)