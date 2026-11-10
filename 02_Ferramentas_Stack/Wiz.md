---
title: "Wiz"
tags: [ferramenta, cnapp, cloud-security, ai-spm]
status: estudando
categoria: CNAPP
---

# 🔮 Wiz

**Relacionado:** [[04_Dominios/Cloud Security]] · [[05_IA/AI Security]] · [[04_Dominios/Vuln Management & Métricas]]

## 🎯 O que é
**CNAPP** agentless: conecta-se às contas cloud via API/snapshots e monta um **Security Graph** ligando recursos, identidades, vulnerabilidades, dados e exposição.

## 🧠 Conceitos-chave
| Conceito | O que é |
|---|---|
| **Security Graph** | Grafo consultável de tudo o que existe na cloud e de como se conecta |
| **Toxic combinations / Issues** | Combinação de riscos (ex.: VM exposta + CVE crítica + role admin) |
| **CSPM / CIEM / DSPM** | Postura, permissões efetivas, dados sensíveis |
| **Vulnerability scan agentless** | Scan via snapshot de disco |
| **AI-SPM** | Inventário de IA (modelos, SDKs, serviços de IA) e riscos de IA |
| **Wiz Code / Defend** | Shift-left (IaC/código) e detecção em runtime |

## 🤖 IA: inventário e vulnerabilidades
- Descobrir onde há uso de IA: Bedrock, Azure OpenAI, Vertex, SDKs em imagens, Databricks
- Riscos típicos: endpoint de modelo exposto, dados de treino em bucket público, chave de API em código
- **MCP do Wiz**: consultar o Security Graph a partir de um assistente de IA (anotado no Inbox)
- Ver [[05_IA/AI Security]]

## ⌨️ A documentar (trabalho)
- [ ] Queries do Security Graph mais usadas
- [ ] Como o inventário de IA é gerado e revisado
- [ ] Fluxo Issue → ticket → correção → MTTR
