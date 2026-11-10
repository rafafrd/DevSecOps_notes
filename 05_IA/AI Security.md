---
title: "AI Security — Segurança de IA"
tags: [ia, ai-security, llm, owasp-llm, mitre-atlas, mcp, ai-bom]
status: estudando
---

# 🤖 AI Security

**Relacionado:** [[02_Ferramentas_Stack/Wiz]] · [[04_Dominios/AppSec]] · [[04_Dominios/Supply Chain Security]] · [[05_IA/Loop Engineering & Harness]]

## 🗺️ Duas frentes
1. **Segurança DA IA:** proteger modelos, apps LLM e agentes
2. **IA PARA segurança:** usar IA em triagem, code review, CTI (ver [[05_IA/SDD & PDD]])

## 🔟 OWASP Top 10 para LLM Apps (2025): principais
| Risco | Exemplo |
|---|---|
| Prompt Injection (direta/indireta) | Documento ou página com instruções escondidas que o agente obedece |
| Sensitive Information Disclosure | Modelo vaza dados de outros usuários ou do system prompt |
| Supply Chain | Modelo/pesos/plugins de origem não confiável |
| Excessive Agency | Agente com permissões demais (deletar, enviar, pagar) |
| Improper Output Handling | Saída do LLM vai direto para SQL/shell/HTML |

Também: **MITRE ATLAS** (ATT&CK para IA), NIST AI RMF, ISO/IEC 42001.

## 📋 Inventário de IA (AI-BOM)
O que mapear: serviços de IA em uso (Bedrock, Azure OpenAI, Vertex), modelos self-hosted, SDKs nas imagens, agentes e **servidores MCP**, dados enviados a cada um, dono e finalidade.
Ferramentas: Wiz AI-SPM, CycloneDX ML-BOM.

## 🔌 MCP e agentes
- Servidor MCP é código de terceiros com acesso a ferramentas → tratar como dependência (revisar, fixar versão)
- Least privilege nos tokens que o MCP usa
- Conteúdo que volta de ferramentas é **dado não confiável** (vetor de prompt injection indireta)
- Logar as chamadas de ferramenta

## ✅ Próximos passos
- [ ] Documentar o processo de inventário de IA do trabalho (genérico)
- [ ] Lab: app LLM vulnerável (ex.: Damn Vulnerable LLM Agent) e testes com garak/promptfoo
