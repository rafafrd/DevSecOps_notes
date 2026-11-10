---
title: "AppSec — Application Security"
tags: [appsec, owasp, sast, dast, sca, api-security]
status: estudando
---

# 🧩 AppSec — Application Security

**Relacionado:** [[02_Ferramentas_Stack/SonarQube]] · [[04_Dominios/CI-CD]] · [[04_Dominios/Supply Chain Security]] · [[04_Dominios/Secrets Management]] · [[05_IA/AI Security]]

## 🗺️ Mapa de testes (AST)

| Tipo | Quando | O que pega | Ferramentas |
|---|---|---|---|
| **SAST** | Código-fonte, no PR | Injeção, crypto fraca, hotspots | SonarQube, Semgrep, Fortify, Veracode |
| **SCA** | Dependências | CVEs em libs, licenças | Trivy, Dependabot, Black Duck, Dependency-Track |
| **Secrets** | Commit / histórico | Credenciais vazadas | gitleaks, trufflehog |
| **DAST** | App rodando | Falhas de runtime, headers, authz | OWASP ZAP, Burp, Nuclei |
| **IAST** | App instrumentada em teste | Fluxo real de dados | Contrast |
| **IaC** | Terraform/K8s | Misconfig | Checkov, Trivy config |

## 🎯 Threat Modeling
- **STRIDE**: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege
- Ferramentas: OWASP Threat Dragon, threat modeling as code (pytm)
- Entregável mínimo: diagrama de fluxo de dados (DFD) + fronteiras de confiança + lista de ameaças priorizadas

## 🔓 IDOR / BOLA (OWASP API1:2023)
**O que é:** o servidor confia no ID enviado pelo cliente sem checar se o objeto pertence ao usuário.

```http
GET /api/v1/invoices/1043   ← meu
GET /api/v1/invoices/1044   ← de outro cliente, e a API devolve 😱
```

**Como testar:** duas contas (A e B) → capturar requests de A → repetir com o token de B. A extensão *Autorize* do Burp automatiza isso.

**Correção:** autorização no nível do objeto em toda rota (`WHERE id = ? AND owner_id = ?`). IDs não sequenciais (UUID) são só defesa extra, nunca o controle principal.

## 🕷️ DAST no pipeline
- **Baseline scan** (passivo, rápido) em todo PR: `zap-baseline.py -t https://staging`
- **Full scan** (ativo) agendado em staging, nunca em produção sem aprovação
- Autenticação é o ponto difícil: usar contexto/script de login do ZAP
- [ ] Documentar o fluxo de DAST usado no trabalho (ver [[07_Casos_Trabalho/README|Casos]])

## 📚 Referências obrigatórias
- OWASP Top 10, **OWASP API Security Top 10 (2023)**, OWASP ASVS, OWASP LLM Top 10
- Ferramentas comerciais citadas no trabalho: Veracode, Black Duck, Fortify

## ✅ Próximos passos
- [ ] Lab de BOLA com crAPI ou OWASP Juice Shop
- [ ] Rodar ZAP baseline no pipeline do [[06_Labs/Homelab K3S]]
- [ ] Security Champions: como escalar AppSec com devs
