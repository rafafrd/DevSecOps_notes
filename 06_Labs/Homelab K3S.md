---
title: "Homelab K3S — Plataforma DevSecOps ponta a ponta"
tags: [lab, k3s, argocd, openbao, pipeline, portfolio]
status: backlog
---

# 🧪 Homelab K3S: Plataforma DevSecOps ponta a ponta

Um único projeto que cobre boa parte do roadmap e vira **portfólio no GitHub**.

## 🏗️ Arquitetura alvo
```
GitHub repo (app) ──CI──► build → SAST (SonarQube/Semgrep) → SCA/Trivy → SBOM (Syft) → cosign sign → push registry
                                                             │
                                          commit da tag no repo de manifests
                                                             ▼
K3S ◄── ArgoCD (GitOps) ── Kyverno (admissão: assinatura, PSS) ── OpenBao + External Secrets
 │
 └── Falco (runtime) → alertas · ZAP baseline (DAST) em staging · Prowler/kube-bench (postura)
```

## 🪜 Fases (cada uma vira uma seção com evidências)
| # | Fase | Notas relacionadas | Status |
|---|---|---|---|
| 1 | K3S em VM/WSL + kubectl | [[01_Fundamentos/Kubernetes]] | ⬜ |
| 2 | ArgoCD + repo de manifests | [[01_Fundamentos/GitOps & ArgoCD]] | ⬜ |
| 3 | OpenBao + External Secrets | [[02_Ferramentas_Stack/OpenBao]] · [[04_Dominios/Secrets Management]] | ⬜ |
| 4 | Pipeline CI com SAST/SCA/SBOM/assinatura | [[04_Dominios/CI-CD]] · [[04_Dominios/Supply Chain Security]] | ⬜ |
| 5 | Kyverno (policies) | [[04_Dominios/Compliance as Code]] | ⬜ |
| 6 | Falco + DAST | [[04_Dominios/AppSec]] | ⬜ |
| 7 | Dependency-Track + DefectDojo (métricas/MTTR) | [[04_Dominios/Vuln Management & Métricas]] | ⬜ |
| 8 | OpenCTI/MISP + Exploit Feed | [[04_Dominios/Threat Intel & Exploit Feed]] | ⬜ |

## 📝 Diário do lab
| Data | O que fiz | Problema / aprendizado |
|---|---|---|
