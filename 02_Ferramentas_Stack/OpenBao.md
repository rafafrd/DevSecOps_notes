---
title: "OpenBao"
tags: [ferramenta, secrets, openbao, vault]
status: backlog
categoria: Secrets Management
---

# 🔐 OpenBao

**Relacionado:** [[04_Dominios/Secrets Management]] · [[01_Fundamentos/Kubernetes]] · [[01_Fundamentos/GitOps & ArgoCD]]

## 🎯 O que é
Fork open source (Linux Foundation, licença MPL 2.0) do HashiCorp Vault, criado após a mudança de licença do Vault para BSL. A API e os conceitos são compatíveis com o Vault; a CLI é `bao`.

## 🧠 Conceitos-chave
| Conceito | O que é |
|---|---|
| **Seal/Unseal** | O cofre inicia selado; precisa de chaves (Shamir) ou auto-unseal via KMS |
| **Secrets engines** | KV (estático), Database (credencial dinâmica), PKI (certificados), Transit (criptografia como serviço) |
| **Auth methods** | Kubernetes, OIDC, AppRole, tokens |
| **Policies** | HCL definindo quem acessa qual path |
| **Leases** | Segredos dinâmicos expiram sozinhos |
| **Audit devices** | Log de todo acesso |

## 🧪 Lab rápido (modo dev, nunca em produção)
```bash
bao server -dev
export BAO_ADDR=http://127.0.0.1:8200
bao kv put secret/app db_password=s3nh4
bao kv get secret/app
```

## 🔗 Integração com o K8S
- Auth method `kubernetes` (o pod se autentica pela ServiceAccount)
- **External Secrets Operator** → `ClusterSecretStore` apontando para o OpenBao
- Deploy via Helm chart oficial `openbao/openbao`, gerenciado pelo ArgoCD

## ⚠️ Pegadinhas
- Guardar as unseal keys e o root token fora do cluster; revogar o root token após o setup
- Backup do storage (Raft snapshots)
