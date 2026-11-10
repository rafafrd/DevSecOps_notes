---
title: "Cloud Security"
tags: [cloud, aws, azure, gcp, cspm, cnapp, iam, multi-cloud]
status: estudando
---

# ☁️ Cloud Security

**Relacionado:** [[01_Fundamentos/Redes Cloud-Native]] · [[02_Ferramentas_Stack/Wiz]] · [[04_Dominios/Compliance as Code]] · [[04_Dominios/Data Security]] · [[01_Fundamentos/Kubernetes]]

## 🧱 Pilares
1. **Identidade (IAM):** o novo perímetro. Least privilege, sem chaves de longa duração, federação/SSO
2. **Configuração (CSPM):** buckets públicos, SGs abertos, logging desligado
3. **Workload (CWPP):** VMs, containers, serverless
4. **Dados (DSPM):** onde estão os dados sensíveis e quem os acessa
5. **Detecção:** CloudTrail / Activity Log / Audit Logs → SIEM

## 🔀 Equivalências multi-cloud

| Conceito | AWS | Azure | GCP |
|---|---|---|---|
| Identidade | IAM / Identity Center | Entra ID | Cloud IAM |
| Audit log | CloudTrail | Activity Log | Cloud Audit Logs |
| Postura | Security Hub | Defender for Cloud | Security Command Center |
| Segredos | Secrets Manager | Key Vault | Secret Manager |
| KMS | KMS | Key Vault | Cloud KMS |
| Storage | S3 | Blob Storage | Cloud Storage |

## 🪣 S3: checklist
- [ ] Block Public Access ligado (conta e bucket)
- [ ] Bucket policy sem `"Principal": "*"`
- [ ] Criptografia (SSE-KMS) e versionamento
- [ ] Server access logs / CloudTrail data events
- [ ] Sem ACLs (Object Ownership = BucketOwnerEnforced)

## 🧱 Databricks: pontos de atenção
- Unity Catalog para governança e controle de acesso aos dados
- Tokens pessoais (PAT) → preferir service principals e OAuth
- Secret scopes em vez de credenciais em notebooks
- Clusters sem acesso irrestrito à internet; workspace com private link
- Ligação com IA: modelos e endpoints de serving entram no inventário de IA ([[05_IA/AI Security]])

## 🛠️ Ferramentas
- **Comercial (trabalho):** [[02_Ferramentas_Stack/Wiz]]
- **Open source multi-cloud:** Prowler, ScoutSuite, Steampipe, CloudSploit

## ✅ Próximos passos
- [ ] Rodar o Prowler numa conta AWS free tier
- [ ] Certificação: AWS Security Specialty → depois AZ-500
