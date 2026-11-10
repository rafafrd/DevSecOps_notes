---
title: "Loop Engineering & Harness — IA aplicada a software"
tags: [ia, agentes, harness, loop-engineering, mcp]
status: backlog
---

# 🔁 Loop Engineering & Harness

**Relacionado:** [[05_IA/SDD & PDD]] · [[05_IA/AI Security]]

## 🧰 Harness
O "arnês" em volta do modelo: tudo o que transforma um LLM em agente útil.
- **Ferramentas** (shell, edição de arquivos, busca, MCP)
- **Contexto** (instruções do projeto, memória, arquivos relevantes)
- **Permissões e sandbox** (o que o agente pode fazer sem pedir)
- **Hooks e verificações** (rodar testes/lint após edições)
- Exemplos: Claude Code, Cursor, Copilot agent mode

## 🔄 Loop Engineering
Projetar o **ciclo de feedback** do agente: `planejar → agir → observar resultado (testes, scanners, logs) → corrigir → repetir` até um critério de parada verificável.
- O agente é tão bom quanto o sinal que recebe → testes, linters e **scanners de segurança como oráculo do loop**
- Critérios de parada claros (testes verdes + SAST sem achados novos)
- Limitar iterações e custo

## 🛡️ Aplicação em DevSecOps
- Agente que triagem findings do SonarQube/Tenable e propõe correções
- Loop "corrige → re-scan → valida" para dependências vulneráveis
- Revisão automática de PR com foco em segurança
- **Riscos:** permissões excessivas, prompt injection via conteúdo do repo/issues, segredos no contexto → ver [[05_IA/AI Security]]

## ✅ Próximos passos
- [ ] Montar um loop: agente + Semgrep/Trivy como verificador no lab
