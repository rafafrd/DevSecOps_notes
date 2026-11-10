---
title: "Compliance as Code & Policy as Code"
tags: [compliance, opa, rego, kyverno, checkov, cis]
status: backlog
---

# 📜 Compliance as Code

**Relacionado:** [[02_Ferramentas_Stack/BigFix Compliance]] · [[04_Dominios/Cloud Security]] · [[01_Fundamentos/Kubernetes]] · [[04_Dominios/Supply Chain Security]]

## 💡 Ideia
Transformar controles (CIS, ISO 27001, PCI, LGPD) em **regras versionadas, testáveis e aplicadas automaticamente**, com a evidência gerada pelo próprio pipeline.

## 🧰 Onde cada ferramenta atua

| Camada | Ferramenta | Exemplo |
|---|---|---|
| IaC (antes do deploy) | Checkov, Conftest (OPA) | Bloquear bucket público no Terraform |
| Kubernetes (admissão) | Kyverno, OPA Gatekeeper | Bloquear container privilegiado |
| Endpoints | BigFix Compliance, OpenSCAP | CIS Benchmark em servidores |
| Cloud (runtime) | Wiz, Prowler | Postura contínua |

## 🧪 Exemplo Rego (Conftest)
```rego
package main
import rego.v1

deny contains msg if {
  input.kind == "Deployment"
  some c in input.spec.template.spec.containers
  c.securityContext.privileged
  msg := sprintf("container %s não pode ser privilegiado", [c.name])
}
```

## 🧪 Exemplo Kyverno
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: Enforce
  rules:
    - name: no-latest
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Use tag fixa, não :latest"
        pattern:
          spec:
            containers:
              - image: "!*:latest"
```

## ✅ Próximos passos
- [ ] Kyverno no lab K3S com as políticas do Pod Security Standards
- [ ] Mapear 5 controles CIS do BigFix para equivalentes as code
