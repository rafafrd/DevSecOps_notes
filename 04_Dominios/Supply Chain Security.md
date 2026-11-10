---
title: "Software Supply Chain Security"
tags: [supply-chain, sbom, slsa, sigstore, vex]
status: backlog
---

# 📦 Software Supply Chain Security

**Relacionado:** [[04_Dominios/AppSec]] · [[04_Dominios/CI-CD]] · [[04_Dominios/Compliance as Code]] · [[01_Fundamentos/Containers]]

## 🧾 SBOM (Software Bill of Materials)
Lista dos componentes (e versões) que compõem um software.

| Formato | Mantido por | Foco |
|---|---|---|
| **CycloneDX** | OWASP | Segurança, VEX nativo |
| **SPDX** | Linux Foundation | Licenças (ISO/IEC 5962) |

```bash
syft nginx:latest -o cyclonedx-json > sbom.json   # gerar
grype sbom:sbom.json                              # escanear o SBOM
trivy image --format cyclonedx nginx:latest       # alternativa
```

**Dependency-Track:** ingere SBOMs e monitora novas CVEs continuamente, transformando o SBOM num inventário vivo.

## 🧷 VEX (Vulnerability Exploitability eXchange)
Informa se uma CVE presente no SBOM **é ou não explorável** naquele produto (`not_affected`, `affected`, `fixed`, `under_investigation`). Reduz falsos positivos.

## 🪜 SLSA (Supply-chain Levels for Software Artifacts)
Níveis de garantia do processo de build: proveniência gerada → build hospedado → build isolado e não falsificável.

## ✍️ Assinatura: Sigstore / cosign
```bash
cosign sign --yes registry/app@sha256:...     # keyless (OIDC)
cosign verify registry/app@sha256:... \
  --certificate-identity=<identidade-do-pipeline> \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```
Verificar a assinatura na admissão do cluster com Kyverno ou policy-controller.

## ⚠️ Ataques de referência
SolarWinds (build comprometido) · Codecov (script de CI) · xz-utils (maintainer malicioso) · typosquatting em npm/PyPI

## ✅ Próximos passos
- [ ] Gerar SBOM + assinar a imagem no pipeline do [[06_Labs/Homelab K3S]]
- [ ] Subir o Dependency-Track no lab
