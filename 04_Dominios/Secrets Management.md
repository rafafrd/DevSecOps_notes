---
title: "Secrets Management"
tags: [secrets, openbao, vault, gitleaks, external-secrets]
status: estudando
---

# 🔑 Secrets Management

**Relacionado:** [[02_Ferramentas_Stack/OpenBao]] · [[02_Ferramentas_Stack/SonarQube]] · [[01_Fundamentos/Git]] · [[01_Fundamentos/Kubernetes]] · [[04_Dominios/CI-CD]]

## 🔄 Ciclo de vida
`Criar → Armazenar → Distribuir → Rotacionar → Revogar → Auditar`

## 🚫 Prevenir vazamento
```bash
gitleaks detect --source . -v           # varre o histórico
gitleaks protect --staged               # hook de pre-commit
trufflehog git file://. --only-verified # valida se o segredo ainda funciona
```
> [!DANGER] Segredo commitado é segredo vazado. **Rotacione primeiro**, depois limpe o histórico (git filter-repo). Limpar sem rotacionar não resolve. Ver o exemplo em [[02_Ferramentas_Stack/SonarQube]].

## 🏦 Onde guardar

| Opção | Quando usar |
|---|---|
| **OpenBao / Vault** | Multi-cloud, segredos dinâmicos, PKI |
| Nativo da cloud (Secrets Manager, Key Vault) | Workloads de uma única cloud |
| Sealed Secrets / SOPS | GitOps simples (segredo cifrado no repo) |
| **External Secrets Operator** | Ponte entre o cofre e o Secret do K8s |

## ☸️ Kubernetes
- `Secret` do K8s é **base64, não criptografia** → habilitar encryption at rest no etcd
- RBAC restrito para `get secrets`
- Preferir injeção via ESO ou CSI driver a segredos estáticos

## 📊 Métricas
Segredos detectados por mês · tempo até a rotação · % de apps usando cofre · segredos sem rotação há mais de 90 dias

## ✅ Próximos passos
- [ ] OpenBao + External Secrets no [[06_Labs/Homelab K3S]]
- [ ] Documentar o processo de resposta a segredo vazado usado no trabalho
