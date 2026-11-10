---
title: "Kubernetes (K8S / K3S) e Segurança"
tags: [kubernetes, k3s, k8s, cloud-native, pss, rbac, falco]
status: estudando
---

# ☸️ Kubernetes (K8S / K3S) e Segurança

**Relacionado:** [[01_Fundamentos/Containers]] · [[01_Fundamentos/Redes Cloud-Native]] · [[01_Fundamentos/GitOps & ArgoCD]] · [[02_Ferramentas_Stack/OpenBao]] · [[04_Dominios/Compliance as Code]] · [[06_Labs/Homelab K3S]]

## K3S vs K8S

| | K3S | K8S "vanilla" (kubeadm) / gerenciado |
|---|---|---|
| Uso | Lab, edge, IoT | Produção, EKS/AKS/GKE |
| Instalação | 1 binário, `curl -sfL https://get.k3s.io \| sh -` | kubeadm ou serviço gerenciado |
| Datastore | SQLite (padrão) ou etcd embutido | etcd |
| Extras inclusos | Traefik, ServiceLB, local-path | Nada além do básico |

O K3S é um K8S certificado (CNCF): o que se aprende nele vale no K8S.

## 🔐 Camadas de segurança (4C: Cloud → Cluster → Container → Code)

| Controle | O que fazer |
|---|---|
| **RBAC** | Least privilege, nada de `cluster-admin` para apps; auditar com `kubectl auth can-i --list` |
| **Pod Security Standards** | Label no namespace: `pod-security.kubernetes.io/enforce=restricted` |
| **NetworkPolicy** | Default deny + liberações explícitas (exige um CNI que suporte, ex.: Calico/Cilium) |
| **Secrets** | Encryption at rest + cofre externo ([[04_Dominios/Secrets Management]]) |
| **Admissão** | Kyverno / Gatekeeper (imagem assinada, sem privileged, sem `:latest`) |
| **Runtime** | Falco / Tetragon detectando shell em container, escrita em `/etc` etc. |
| **Benchmark** | `kube-bench` (CIS), `kubescape`, `trivy k8s` |
| **API server** | Sem exposição pública, audit log ligado |

```yaml
# Default deny ingress no namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-ingress, namespace: app }
spec:
  podSelector: {}
  policyTypes: [Ingress]
```

## ⌨️ Comandos de investigação
```bash
kubectl get pods -A -o wide
kubectl auth can-i --list --as=system:serviceaccount:app:default
kubectl get rolebindings,clusterrolebindings -A
trivy k8s --report summary cluster
```

## 🎓 Certificações
CKA (operação) → **CKS** (segurança): CKS é o alvo natural para DevSecOps.
