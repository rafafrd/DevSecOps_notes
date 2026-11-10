---
title: "Vulnerability Management & Métricas"
tags: [vuln-management, mttr, epss, kev, cvss, metricas]
status: estudando
---

# 📉 Vulnerability Management & Métricas

**Relacionado:** [[02_Ferramentas_Stack/Tenable]] · [[02_Ferramentas_Stack/Vicarius]] · [[02_Ferramentas_Stack/BigFix Compliance]] · [[02_Ferramentas_Stack/XM Cyber]] · [[04_Dominios/Threat Intel & Exploit Feed]] · [[04_Dominios/Gestão de Risco]]

## 🔄 Ciclo
`Descobrir → Priorizar → Remediar/Mitigar → Validar → Medir`

| Etapa | Ferramenta da squad |
|---|---|
| Descobrir | Tenable, Wiz (cloud), SonarQube (código) |
| Priorizar | VPR, EPSS, KEV, XM Cyber (attack path) |
| Remediar | BigFix, Vicarius (patch / patchless) |
| Validar | Rescan Tenable, re-simulação XM Cyber |

## 🎯 Priorização além do CVSS

| Sinal | Pergunta que responde | Fonte |
|---|---|---|
| **CVSS v4** | Quão grave é tecnicamente? | NVD / FIRST |
| **EPSS** | Qual a probabilidade de exploração em 30 dias? | api.first.org/data/v1/epss |
| **CISA KEV** | Já está sendo explorada? | cisa.gov/known-exploited-vulnerabilities-catalog |
| **VPR** | Visão Tenable de ameaça + idade | Tenable |
| **SSVC** | Qual a decisão (Track / Track* / Attend / Act)? | CISA |
| **Contexto do ativo** | Exposto à internet? Crítico ao negócio? | CMDB, XM Cyber |

Regra prática: **KEV ou EPSS alto + ativo exposto = prioridade máxima**, independentemente do CVSS.

## 📊 Métricas

| Métrica | Fórmula | Para quê |
|---|---|---|
| **MTTR** | Σ(data correção − data detecção) / nº de vulns corrigidas | Velocidade de remediação |
| **SLA compliance** | % corrigidas dentro do prazo, por severidade | Cobrar o acordo com os times |
| **Vulnerability age** | Idade média das vulns abertas | Mostra o backlog envelhecendo |
| **Backlog burn-down** | Abertas vs. fechadas por período | Tendência |
| **Cobertura de scan** | Ativos escaneados / ativos inventariados | Pontos cegos |
| **MTTD** | Tempo entre publicação da CVE e detecção no ambiente | Eficiência de detecção |
| **Recorrência** | % de vulns que reabrem | Qualidade da correção |

> [!TIP] Segmente o MTTR por **severidade** e por **time/BU**. Um MTTR global esconde tudo.

Exemplo de SLA (ajustar à política interna): Crítica 7d · Alta 30d · Média 90d · Baixa 180d.

## ✅ Próximos passos
- [ ] Script que cruza o export do Tenable com EPSS + KEV
- [ ] Dashboard de MTTR por severidade (Grafana ou planilha)
- [ ] Avaliar DefectDojo como agregador de findings (ASPM open source)
