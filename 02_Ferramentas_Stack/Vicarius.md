---
title: "Vicarius (vRx)"
tags: [ferramenta, vuln-management, patch-management, remediation]
status: estudando
categoria: Vulnerability Remediation
---

# 🩹 Vicarius (vRx)

**Relacionado:** [[04_Dominios/Vuln Management & Métricas]] · [[02_Ferramentas_Stack/Tenable]] · [[02_Ferramentas_Stack/BigFix Compliance]]

## 🎯 O que é
Plataforma de **remediação de vulnerabilidades** baseada em agente: descobre, prioriza e **corrige** (patch de SO e de aplicações de terceiros). Diferencial: **patchless protection** (proteção em memória para apps sem patch disponível) e execução de scripts de remediação.

## 🔄 Onde entra no fluxo da squad
`Tenable (detecta) → priorização (VPR/EPSS/KEV) → Vicarius ou BigFix (corrige) → Tenable (valida)`

| | Vicarius | BigFix |
|---|---|---|
| Foco | Remediação de vulns, apps de terceiros, patchless | Patch + compliance em escala corporativa |
| Automação | Políticas automáticas, scripts | Fixlets, Relevance |

## ⌨️ A documentar (trabalho)
- [ ] Como funciona a priorização interna e se ela bate com Tenable/EPSS
- [ ] Políticas de patch automático: janelas, grupos, rollback
- [ ] Uso de scripts (PowerShell/Bash) para mitigação
- [ ] Integrações (API, ticketing) e como extrair métricas de MTTR
- [ ] Usar o [[Templates/Caso de Trabalho]] para cada caso real

## 🔗 Referências
- docs.vicarius.io · comunidade vsociety (scripts e research de CVEs)
