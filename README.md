# 🛡️ DevSecOps Knowledge Base

<div align="center">

![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
![Obsidian](https://img.shields.io/badge/built%20with-Obsidian-7C3AED?style=flat-square&logo=obsidian&logoColor=white)
![Markdown](https://img.shields.io/badge/format-Markdown-1e90ff?style=flat-square&logo=markdown)
![Focus](https://img.shields.io/badge/focus-DevSecOps-red?style=flat-square)
![License](https://img.shields.io/badge/license-personal-lightgrey?style=flat-square)

</div>

---

Base de conhecimento pessoal em constante evolução, estruturada como um vault [Obsidian](https://obsidian.md/). Consolida anotações técnicas, documentações de ferramentas e estudos focados no ecossistema **DevSecOps** e **Cybersecurity** — desde fundamentos de redes e Linux até ferramentas de Vulnerability Management, Threat Intelligence e Attack Surface Management.

---

## 📂 Estrutura

```
devsecops-kb/
│
├── 📁 01_Fundamentos/              # Base técnica transversal
│   ├── CCNA.md                     # Redes — CCNA 200-301 completo
│   ├── Redes.md                    # Redes cloud-native, K8s, Zero Trust
│   ├── Linux.md                    # Administração, hardening e scripting
│   ├── Containers.md               # Docker, Kubernetes e segurança de containers
│   └── Git.md                      # Controle de versão e práticas DevSecOps
│
├── 📁 02_Ferramentas_Stack/        # Ferramentas do ecossistema de segurança
│   ├── CTI, ASM & Vulnerability Management.md   # Shodan, Censys, VirusTotal, Tenable
│   ├── Tenable.md                  # Vulnerability Management — Tenable.io / Nessus
│   ├── BigFix Compliance.md        # Compliance e patch management
│   ├── OpenCTI.md                  # Plataforma de Cyber Threat Intelligence
│   ├── XM Cyber.md                 # Attack Path Management
│   └── SonarQube.md                # SAST e qualidade de código
│
├── 📁 03_Glossarios/               # Referências terminológicas
│   └── Siglas.md                   # Dicionário de siglas e termos do ecossistema
│
├── 📁 99_Inbox/                    # Captura rápida — notas pendentes de refinamento
│   └── kwords.md
│
├── 00_Dashboard.md                 # Índice de navegação principal (Obsidian)
└── README.md
```

---

## 🗺️ Mapa de Conteúdo

### 01 · Fundamentos

| Arquivo | Conteúdo | Nível |
|---|---|---|
| `CCNA.md` | Modelo OSI, TCP/IP, Ethernet, Subnetting, VLANs, STP, OSPF, ACLs, Wireless, Automação | Intermediário |
| `Redes.md` | VPC/Cloud Networking, Kubernetes CNI, Service Mesh, Zero Trust, ZTNA, Firewall APIs | Avançado |
| `Linux.md` | Administração de sistemas, permissões, hardening, scripting Bash | Intermediário |
| `Containers.md` | Docker, Kubernetes, segurança de containers, imagens e registries | Intermediário |
| `Git.md` | Versionamento, branching, integração com pipelines CI/CD | Básico–Intermediário |

### 02 · Ferramentas & Stack

| Arquivo | Categoria | Descrição |
|---|---|---|
| `CTI, ASM & Vulnerability Management.md` | ASM · CTI · VM | Shodan dorks, Censys queries, VirusTotal API, Tenable VPR, scripts de automação SOAR |
| `Tenable.md` | Vulnerability Management | Tenable.io, Nessus plugins, VPR scoring, pipelines de remediação |
| `BigFix Compliance.md` | Patch & Compliance | Gestão de conformidade e patch management em escala |
| `OpenCTI.md` | Threat Intelligence | Plataforma open-source de CTI, STIX/TAXII, conectores |
| `XM Cyber.md` | Attack Path Management | Simulação de ataque, mapeamento de caminhos críticos, exposição de ativos |
| `SonarQube.md` | SAST / Code Quality | Análise estática, quality gates, integração em CI/CD |

---

## 🧱 Stack Técnico Documentado

<table>
  <tr>
    <th>Domínio</th>
    <th>Tecnologias e Ferramentas</th>
  </tr>
  <tr>
    <td><b>Redes & Infra</b></td>
    <td>TCP/IP · IPv4/IPv6 · VLANs · OSPF · VPC · Zero Trust · ZTNA</td>
  </tr>
  <tr>
    <td><b>Sistemas</b></td>
    <td>Linux (Debian/RHEL) · Bash · Docker · Kubernetes</td>
  </tr>
  <tr>
    <td><b>Vulnerability Management</b></td>
    <td>Tenable.io · Nessus · BigFix · CVE · CVSS · VPR</td>
  </tr>
  <tr>
    <td><b>Threat Intelligence</b></td>
    <td>OpenCTI · VirusTotal · STIX/TAXII · MITRE ATT&CK</td>
  </tr>
  <tr>
    <td><b>Attack Surface Management</b></td>
    <td>Shodan · Censys · XM Cyber</td>
  </tr>
  <tr>
    <td><b>Code Security (SAST)</b></td>
    <td>SonarQube · Quality Gates · CI/CD Integration</td>
  </tr>
  <tr>
    <td><b>Automação & DevSecOps</b></td>
    <td>Python · Ansible · REST APIs · GitHub Actions · SOAR</td>
  </tr>
</table>

---

## 🔄 Fluxo de Trabalho

Este repositório segue um fluxo de captura → processamento → consolidação:

```
Nova informação / estudo
        │
        ▼
  📥 99_Inbox/          ← Captura rápida, sem estrutura
        │
        │  refinar, padronizar, categorizar
        ▼
  📁 01_Fundamentos/    ← Conceitos base e tecnologias core
  📁 02_Ferramentas_Stack/ ← Documentação técnica de ferramentas
  📁 03_Glossarios/     ← Termos, siglas e referências rápidas
        │
        ▼
  📊 00_Dashboard.md    ← Índice de navegação (Obsidian)
```

---

## 📐 Padrão de Documentação

Todos os arquivos seguem um padrão consistente de formatação Markdown otimizado para Obsidian:

- **Frontmatter YAML** com `tags`, `aliases`, `nivel` e `status`
- **Diagramas Mermaid** para arquiteturas e fluxos
- **Tabelas comparativas** para análise de ferramentas e protocolos
- **Blocos de código** com sintaxe específica (`bash`, `python`, `cisco`, `yaml`, `json`)
- **Callouts nativos** do Obsidian (`[!NOTE]`, `[!WARNING]`, `[!INFO]`) para destaques críticos
- **Links internos** `[[]]` para navegação entre notas relacionadas

---

## 🔗 Frameworks de Referência

| Framework | Descrição | Link |
|---|---|---|
| **MITRE ATT&CK** | Táticas e técnicas de adversários | [attack.mitre.org](https://attack.mitre.org/) |
| **NIST CSF** | Cybersecurity Framework | [nist.gov/cyberframework](https://www.nist.gov/cyberframework) |
| **OWASP Top 10** | Riscos críticos em aplicações web | [owasp.org](https://owasp.org/www-project-top-ten/) |
| **CIS Benchmarks** | Hardening de sistemas e configurações | [cisecurity.org](https://www.cisecurity.org/cis-benchmarks) |
| **NIST SP 800-207** | Zero Trust Architecture | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-207/final) |
| **CVE / NVD** | Base de vulnerabilidades conhecidas | [nvd.nist.gov](https://nvd.nist.gov/) |

---

## ⚠️ Aviso

Este é um repositório de **estudos e referência pessoal**. O conteúdo reflete entendimento técnico em desenvolvimento contínuo e pode conter imprecisões. Não substitui documentação oficial das ferramentas ou treinamentos certificados.

---

<div align="center">

*"Security is not a product, but a process."*
— **Bruce Schneier**

</div>
