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
prerequisito: "[[01_Fundamentos/Redes]]"
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