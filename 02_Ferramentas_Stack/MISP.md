---
title: "MISP"
tags: [ferramenta, cti, misp, ioc, threat-sharing]
status: backlog
categoria: Threat Intelligence
---

# 🧬 MISP (Malware Information Sharing Platform)

**Relacionado:** [[02_Ferramentas_Stack/OpenCTI]] · [[04_Dominios/Threat Intel & Exploit Feed]]

## 🎯 O que é
Plataforma open source para **armazenar, correlacionar e compartilhar** indicadores de ameaça (IOCs) entre organizações e comunidades.

## 🧠 Conceitos-chave
| Conceito | O que é |
|---|---|
| **Event** | Agrupador (ex.: "Campanha phishing X") |
| **Attribute** | Um IOC: IP, domínio, hash, URL |
| **Object** | Atributos agrupados por template (ex.: `file` = nome + hashes) |
| **Galaxy / Cluster** | Contexto: atores, ATT&CK, malware |
| **Taxonomy / Tag** | Classificação (TLP, PAP, confiança) |
| **Feed** | Fontes externas importadas automaticamente |
| **Sharing group / Sync** | Troca entre instâncias |

## 🧪 Lab
- docker-compose oficial: github.com/MISP/misp-docker
- Habilitar os feeds padrão (CIRCL OSINT, Botvrij) e ver as correlações surgirem

## 🔗 Integração
- PyMISP (API Python) para automação
- Conector MISP no [[02_Ferramentas_Stack/OpenCTI]]
- Exportar IOCs para SIEM/firewall (ex.: listas de bloqueio)

```python
from pymisp import PyMISP
misp = PyMISP("https://misp.local", "<API_KEY>", ssl=False)  # ssl=False só no lab
res = misp.search(controller="attributes", value="8.8.8.8")
```
