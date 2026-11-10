---
title: "SDD & PDD — Desenvolvimento orientado a especificação e a prompt"
tags: [ia, sdd, pdd, ai-assisted-dev]
status: backlog
---

# 📐 SDD & PDD

**Relacionado:** [[05_IA/Loop Engineering & Harness]] · [[05_IA/AI Security]] · [[04_Dominios/AppSec]]

## SDD: Spec-Driven Development
A **especificação** (requisitos, critérios de aceite, contratos de API, restrições de segurança) é o artefato principal; o código é gerado e validado contra ela, muitas vezes por agentes de IA.
- Fluxo típico: `spec → plano → tarefas → implementação → verificação contra a spec`
- Ferramentas/exemplos: GitHub Spec Kit, Kiro, specs em Markdown no repo
- **Gancho de segurança:** requisitos de segurança (authz por objeto, validação de entrada, logging) entram na spec e viram testes, o que é shift-left de verdade

## PDD: Prompt-Driven Development
O prompt (ou conjunto de prompts) é tratado como **código-fonte versionado**, revisado e testado; o código é derivado dele.
- Versionar os prompts no Git, revisar em PR e testar com avaliações (evals)

## 🔐 Riscos
- Código gerado com vulnerabilidades plausíveis → SAST/SCA continuam obrigatórios
- Dependências alucinadas (slopsquatting) → validar pacotes antes de instalar
- Segredos colados em prompts

## ✅ Próximos passos
- [ ] Escrever uma spec com requisitos de segurança para um microserviço do lab e gerar o código com um agente
