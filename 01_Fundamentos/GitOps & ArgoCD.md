---
title: "GitOps & ArgoCD"
tags: [gitops, argocd, kubernetes, cicd]
status: backlog
---

# 🔁 GitOps & ArgoCD

**Relacionado:** [[01_Fundamentos/Git]] · [[01_Fundamentos/Kubernetes]] · [[04_Dominios/CI-CD]] · [[04_Dominios/Secrets Management]] · [[06_Labs/Homelab K3S]]

## 💡 Princípios GitOps (OpenGitOps)
1. **Declarativo:** o estado desejado está descrito (YAML/Helm/Kustomize)
2. **Versionado e imutável:** o Git é a fonte da verdade
3. **Pull automático:** um agente no cluster puxa as mudanças (sem `kubectl apply` vindo do CI)
4. **Reconciliação contínua:** drift é detectado e corrigido

## 🔄 CI vs CD no GitOps
`CI (build, testes, scans, push da imagem) → commit da nova tag no repo de manifests → ArgoCD sincroniza o cluster`

O CI **não precisa de credenciais do cluster**, o que reduz muito a superfície de ataque.

## 🚀 ArgoCD básico
```bash
kubectl create ns argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: { name: app, namespace: argocd }
spec:
  project: default
  source: { repoURL: https://github.com/<user>/manifests, path: app, targetRevision: main }
  destination: { server: https://kubernetes.default.svc, namespace: app }
  syncPolicy: { automated: { prune: true, selfHeal: true } }
```

## 🔐 Segurança do ArgoCD
- Trocar/desabilitar o admin inicial, usar SSO
- **AppProjects** restringindo repos, clusters e namespaces de destino
- RBAC do ArgoCD por time
- Não expor a UI publicamente
- Segredos: nunca em texto puro no repo → SOPS, Sealed Secrets ou External Secrets + [[02_Ferramentas_Stack/OpenBao]]
- Branch protection e PR obrigatório no repo de manifests (quem escreve no Git controla o cluster)
