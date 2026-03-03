---
title: "DevSecOps Knowledge Base — Dashboard"
tags:
  - dashboard
  - index
  - devsecops
  - navegacao
aliases:
  - "Home"
  - "Index"
  - "Dashboard"
created: 2026-03-02
updated: 2026-03-02
tipo: dashboard
---

# 🛡️ DevSecOps Knowledge Base

> Base de conhecimento pessoal sobre **DevSecOps** e **Cybersecurity** — estruturada para consulta rápida, aprendizado progressivo e referência técnica no dia a dia da squad.

---

## 🗺️ Onde Estou?

```mermaid
mindmap
  root((🛡️ DevSecOps KB))
    🏗️ Fundamentos
      🐧 Linux & Hardening
      🌐 Redes CCNA
      🌐 Redes Cloud-Native
      🐳 Containers
      🌿 Git & GitOps
    🛠️ Ferramentas da Squad
      🔍 SonarQube
      🎯 Tenable
      🧠 OpenCTI
      🛣️ XM Cyber
      🔧 BigFix
    📚 Referências
      📖 Glossário de Siglas
      📥 Inbox
```

---

## ⚡ Navegação Rápida

|🏗️ Fundamentos|🛠️ Stack da Squad|📚 Referências|
|---|---|---|
|[[01_Fundamentos/Linux\|🐧 Linux & Hardening]]|[[02_Ferramentas_Stack/SonarCube\|🔍 SonarQube]]|[[03_Glossarios/Siglas\|📖 Glossário de Siglas]]|
|[[01_Fundamentos/CCNA\|🎓 CCNA 200-301]]|[[02_Ferramentas_Stack/Tenable\|🎯 Tenable]]|[[99_Inbox/\|📥 Capturas Rápidas]]|
|[[01_Fundamentos/Redes\|🌐 Redes Cloud-Native]]|[[02_Ferramentas_Stack/OpenCTI\|🧠 OpenCTI]]||
|[[01_Fundamentos/Conteiners\|🐳 Docker & Containers]]|[[02_Ferramentas_Stack/XM Cyber\|🛣️ XM Cyber]]||
|[[01_Fundamentos/Git\|🌿 Git & GitOps]]|[[02_Ferramentas_Stack/BigFix Compliance\|🔧 BigFix]]||

---

## 🏢 Contexto da Squad

> As cinco ferramentas abaixo compõem o arsenal operacional da squad. Cada uma atua em uma camada distinta do ciclo de segurança.

```mermaid
flowchart LR
    A(["👨‍💻 Dev\nEscreve código"]) --> B["🔍 SonarQube\nSAST — analisa o código"]
    B --> C["🚀 Deploy\nInfraestrutura"]
    C --> D["🎯 Tenable\nScan de vulnerabilidades"]
    D --> E{"Vulnerável?"}
    E -->|"Sim — contexto"| F["🧠 OpenCTI\nThreat Intelligence"]
    E -->|"Sim — caminho"| G["🛣️ XM Cyber\nAtack Path"]
    F --> H["🔧 BigFix\nPatching em escala"]
    G --> H
    H --> C

    style A fill:#4A5568,color:#fff
    style B fill:#2B6CB0,color:#fff
    style D fill:#276749,color:#fff
    style F fill:#744210,color:#fff
    style G fill:#702459,color:#fff
    style H fill:#1A365D,color:#fff
    style E fill:#2D3748,color:#fff
```

---

## 🛠️ Ferramentas — Resumo Operacional

```yaml
squad_tools:

  sonarqube:
    categoria: "SAST / Code Quality"
    camada: "Código (Build)"
    pergunta: "Meu código tem brechas de segurança ou dívida técnica?"
    analogia: "Corretor ortográfico — não deixa publicar o livro com erros"
    quando_usar:
      - Pull Request aberto
      - Antes de merge na branch principal
      - Review de qualidade de novo serviço
    link: "[[02_Ferramentas_Stack/SonarCube]]"

  tenable:
    categoria: "Vulnerability Management"
    camada: "Infraestrutura (Runtime)"
    pergunta: "Quais hosts têm CVEs críticos abertos na minha rede?"
    analogia: "Inspetor predial — checa janelas, trancas e muros"
    quando_usar:
      - Scan periódico de infra
      - Após deploy em produção
      - Triagem de CVEs com VPR score
    link: "[[02_Ferramentas_Stack/Tenable]]"

  opencti:
    categoria: "Cyber Threat Intelligence (CTI)"
    camada: "Inteligência"
    pergunta: "Esse CVE está sendo explorado ativamente? Por quem?"
    analogia: "Quadro do detetive — conecta pistas, mapeia adversários"
    quando_usar:
      - Contextualizar um CVE encontrado pelo Tenable
      - Investigar IOCs de um incidente
      - Alimentar playbooks de resposta
    link: "[[02_Ferramentas_Stack/OpenCTI]]"

  xm_cyber:
    categoria: "Attack Path Management"
    camada: "Estratégia / Priorização"
    pergunta: "Como um atacante chegaria nos meus ativos críticos?"
    analogia: "GPS do ladrão — mostra a rota exata da entrada até o cofre"
    quando_usar:
      - Priorizar qual vuln corrigir primeiro
      - Avaliar blast radius de um ativo comprometido
      - Relatório executivo de exposição
    link: "[[02_Ferramentas_Stack/XM Cyber]]"

  bigfix:
    categoria: "Patching & Compliance"
    camada: "Operação / Remediação"
    pergunta: "Como aplico esse patch em 1.000 máquinas ao mesmo tempo?"
    analogia: "Equipe de manutenção mágica — troca 1000 lâmpadas com um clique"
    quando_usar:
      - Remediação de CVEs identificados pelo Tenable
      - Ciclo mensal de patch management
      - Verificação de conformidade (compliance scan)
    link: "[[02_Ferramentas_Stack/BigFix Compliance]]"
```

---

## 🔄 Fluxo de Operação da Squad

> Como as ferramentas se conectam em um ciclo real de trabalho:

```mermaid
sequenceDiagram
    autonumber
    participant Dev as 👨‍💻 Developer
    participant SQ as 🔍 SonarQube
    participant Ten as 🎯 Tenable
    participant CTI as 🧠 OpenCTI
    participant XM as 🛣️ XM Cyber
    participant BF as 🔧 BigFix

    Dev->>SQ: Abre Pull Request
    SQ-->>Dev: ❌ Quality Gate falhou — SQLi detectado
    Dev->>SQ: Corrige e reabre PR
    SQ-->>Dev: ✅ Quality Gate passou

    Note over Ten: Scan semanal automático
    Ten-->>Ten: CVE-2024-XXXX (VPR 9.1) encontrado em 47 hosts

    Ten->>CTI: Consulta: esse CVE tem exploit ativo?
    CTI-->>Ten: ⚠️ Sim — grupo APT-29 explorando ativamente

    Ten->>XM: Consulta: esse host é caminho para ativos críticos?
    XM-->>Ten: 🚨 Sim — 3 hops até o banco de produção

    Note over BF: Prioridade CRÍTICA definida
    Ten->>BF: Cria tarefa de remediação (47 hosts, SLA 24h)
    BF-->>BF: Deploy do patch em todos os hosts
    BF-->>Ten: ✅ Confirmação de conformidade — rescan limpo
```

---

## 🎯 Ciclo de Operação — Visão de Camadas

```mermaid
graph TD
    subgraph "🏗️ FUNDAMENTOS"
        L["🐧 Linux"] 
        R["🌐 Redes"]
        C["🐳 Containers"]
        G["🌿 Git"]
    end

    subgraph "🔐 SHIFT-LEFT — Segurança no Código"
        SQ["🔍 SonarQube\nSAST · Quality Gates · CI/CD"]
    end

    subgraph "🏢 RUNTIME — Segurança na Infra"
        TEN["🎯 Tenable\nVulnerability Management · VPR · CVE"]
        BF["🔧 BigFix\nPatch · Compliance · Remediação"]
    end

    subgraph "🧠 INTELIGÊNCIA — Contexto e Priorização"
        CTI["🧠 OpenCTI\nThreat Intel · IOCs · ATT&CK"]
        XM["🛣️ XM Cyber\nAttack Path · Blast Radius · Scoring"]
    end

    L & R & C & G --> SQ
    L & R --> TEN
    TEN --> CTI
    TEN --> XM
    CTI & XM --> BF
    BF --> TEN

    style SQ fill:#2B6CB0,color:#fff
    style TEN fill:#276749,color:#fff
    style BF fill:#1A365D,color:#fff
    style CTI fill:#744210,color:#fff
    style XM fill:#702459,color:#fff
```

---

## 📐 Fundamentos — Mapa de Dependências

> O que estudar antes do quê:

```mermaid
graph LR
    R["🌐 Redes\n(CCNA)"]
    RC["🌐 Redes\n(Cloud-Native)"]
    L["🐧 Linux"]
    C["🐳 Containers"]
    G["🌿 Git"]

    SQ["🔍 SonarQube"]
    TEN["🎯 Tenable"]
    CTI["🧠 OpenCTI"]
    XM["🛣️ XM Cyber"]
    BF["🔧 BigFix"]

    R -->|"base para"| RC
    R -->|"base para"| TEN
    R -->|"base para"| XM
    L -->|"base para"| TEN
    L -->|"base para"| BF
    L -->|"base para"| C
    G -->|"base para"| SQ
    C -->|"base para"| SQ
    C -->|"base para"| TEN
    RC -->|"contexto para"| TEN
    RC -->|"contexto para"| XM
    TEN -->|"alimenta"| CTI
    TEN -->|"alimenta"| XM
    CTI -->|"prioriza"| BF
    XM -->|"prioriza"| BF

    style R fill:#2D3748,color:#fff
    style RC fill:#2D3748,color:#fff
    style L fill:#2D3748,color:#fff
    style C fill:#2D3748,color:#fff
    style G fill:#2D3748,color:#fff
```

---

## 📊 Comparativo das Ferramentas da Squad

|Ferramenta|Camada|Tipo de Scan|O que protege|Quando aciona|Output principal|
|---|---|---|---|---|---|
|**SonarQube**|Código|Estático (SAST)|Aplicação|No commit/PR|Quality Gate pass/fail|
|**Tenable**|Infra|Ativo/Autenticado|Rede + Hosts|Periódico + on-demand|CVE com VPR score|
|**OpenCTI**|Inteligência|Passivo/Correlação|Contexto de ameaça|Investigação|IOCs + TTPs + Grupos|
|**XM Cyber**|Estratégia|Simulação|Caminhos críticos|Contínuo|Choke points + Score|
|**BigFix**|Operação|Compliance check|Endpoints|Pós-priorização|Patch deployed / compliant|

---

## 🗂️ Índice Completo do Vault

```yaml
vault_index:

  fundamentos:
    descricao: "Base técnica transversal — leia antes das ferramentas"
    arquivos:
      - titulo: "CCNA 200-301"
        link: "[[01_Fundamentos/CCNA]]"
        topicos: ["OSI", "TCP/IP", "VLANs", "OSPF", "STP", "ACLs", "Subnetting", "Wireless"]
        nivel: intermediario

      - titulo: "Redes Cloud-Native & DevSecOps"
        link: "[[01_Fundamentos/Redes]]"
        topicos: ["VPC", "Kubernetes CNI", "Service Mesh", "Zero Trust", "ZTNA", "Firewall APIs"]
        nivel: avancado

      - titulo: "Linux & Hardening"
        link: "[[01_Fundamentos/Linux]]"
        topicos: ["Administração", "Permissões", "Hardening", "Bash scripting", "Systemd"]
        nivel: intermediario

      - titulo: "Docker & Containers"
        link: "[[01_Fundamentos/Conteiners]]"
        topicos: ["Docker", "Kubernetes", "Segurança de containers", "Registries", "CIS Benchmark"]
        nivel: intermediario

      - titulo: "Git & GitOps"
        link: "[[01_Fundamentos/Git]]"
        topicos: ["Branching", "CI/CD", "Hooks de segurança", "GitOps", "Integração com SAST"]
        nivel: basico-intermediario

  ferramentas_stack:
    descricao: "Documentação técnica das ferramentas da squad"
    arquivos:
      - titulo: "CTI, ASM & Vulnerability Management"
        link: "[[02_Ferramentas_Stack/CTI, ASM & Vulnerability Management]]"
        topicos: ["Shodan", "Censys", "VirusTotal", "Tenable VPR", "SOAR", "Automação de IOCs"]
        nivel: avancado

      - titulo: "Tenable"
        link: "[[02_Ferramentas_Stack/Tenable]]"
        topicos: ["Nessus Plugins", "VPR vs CVSS", "Scan policies", "Remediação", "API"]
        nivel: intermediario

      - titulo: "BigFix Compliance"
        link: "[[02_Ferramentas_Stack/BigFix Compliance]]"
        topicos: ["Patch management", "Compliance scan", "Fixlets", "Relevance language"]
        nivel: intermediario

      - titulo: "OpenCTI"
        link: "[[02_Ferramentas_Stack/OpenCTI]]"
        topicos: ["STIX/TAXII", "Conectores", "MITRE ATT&CK", "Threat actors", "IOCs"]
        nivel: intermediario

      - titulo: "XM Cyber"
        link: "[[02_Ferramentas_Stack/XM Cyber]]"
        topicos: ["Attack path", "Choke points", "Blast radius", "Entity scoring", "Relatórios"]
        nivel: intermediario

      - titulo: "SonarQube"
        link: "[[02_Ferramentas_Stack/SonarCube]]"
        topicos: ["SAST", "Quality Gates", "Rules", "CI/CD integration", "Security Hotspots"]
        nivel: basico-intermediario

  referencias:
    arquivos:
      - titulo: "Glossário de Siglas"
        link: "[[03_Glossarios/Siglas]]"
        descricao: "Dicionário de termos e siglas do ecossistema de segurança"

      - titulo: "Inbox"
        link: "[[99_Inbox/kwords]]"
        descricao: "Notas rápidas pendentes de refinamento"
```

---

## 📈 Frameworks de Referência

|Framework|Aplicação no dia a dia|Link|
|---|---|---|
|**MITRE ATT&CK**|Contextualizar TTPs no OpenCTI, mapear caminhos no XM Cyber|[attack.mitre.org](https://attack.mitre.org/)|
|**CVSS v3**|Score base de vulnerabilidades no Tenable|[first.org/cvss](https://www.first.org/cvss/)|
|**VPR (Tenable)**|Score de priorização com contexto de exploração ativa|[[02_Ferramentas_Stack/Tenable]]|
|**OWASP Top 10**|Categorias de falhas que o SonarQube detecta|[owasp.org](https://owasp.org/www-project-top-ten/)|
|**CIS Benchmarks**|Base para compliance checks no BigFix|[cisecurity.org](https://www.cisecurity.org/cis-benchmarks)|
|**NIST CSF**|Framework macro de gestão de segurança|[nist.gov/cyberframework](https://www.nist.gov/cyberframework)|
|**NIST SP 800-207**|Zero Trust — base conceitual para Redes Cloud-Native|[csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-207/final)|

---

## 🔁 Fluxo de Captura de Conhecimento

```mermaid
flowchart TD
    A["💡 Nova informação\n(artigo, curso, incidente real)"] --> B["📥 99_Inbox\nCaptura rápida sem estrutura"]
    B --> C{Tipo de conteúdo?}
    C -->|"Conceito base\nprotocolo, tecnologia"| D["📁 01_Fundamentos"]
    C -->|"Ferramenta\nda squad"| E["📁 02_Ferramentas_Stack"]
    C -->|"Sigla ou\nnovo termo"| F["📁 03_Glossarios"]
    D & E & F --> G["🔗 Adicionar links\nno Dashboard"]
    G --> H["📊 00_Dashboard\nÍndice atualizado"]

    style A fill:#2D3748,color:#fff
    style B fill:#744210,color:#fff
    style H fill:#276749,color:#fff
```

---

_Atualizado em: 2026-03-02 · [[README|→ Ver README do repositório]]_