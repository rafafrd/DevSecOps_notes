[[Linux]]
### Resumo

### BigFix Compliance (Correção e Conformidade)

**O que é:** O BigFix é uma ferramenta de **Gerenciamento de Endpoints e Patching**. Enquanto o Tenable _encontra_ o problema, o BigFix é quem vai lá e _resolve_ (aplica o patch/atualização) em milhares de máquinas ao mesmo tempo. A parte de "Compliance" garante que as configurações de segurança (ex: senha mínima de 8 caracteres) estejam ativas.

**A Analogia:** Se o Tenable é o inspetor que acha o problema, o BigFix é uma **equipe de manutenção com uma chave mestra mágica**. O inspetor diz "tem 500 lâmpadas queimadas no prédio". O BigFix estala os dedos e troca as 500 lâmpadas simultaneamente, sem precisar entrar de sala em sala.

**Como funciona no DevSecOps:** Automação de "higiene". Manter milhares de servidores atualizados manualmente é impossível. O BigFix automatiza isso para garantir que o ambiente esteja sempre em conformidade com as regras de segurança.

**Exemplo Prático:** A política da empresa diz que todos os computadores devem ter o antivírus ligado e o Chrome atualizado. O BigFix verifica 10.000 computadores. Ele descobre que 50 estão com o Chrome velho. Ele envia um comando silencioso que atualiza esses 50 computadores sem o usuário precisar clicar em nada.

**Relacionado:** [[02_Ferramentas_Stack/Tenable]] · [[02_Ferramentas_Stack/Vicarius]] · [[04_Dominios/Compliance as Code]] · [[04_Dominios/Vuln Management & Métricas]]

---

## 🧠 Conceitos-chave
| Conceito | O que é |
|---|---|
| **Fixlet** | Unidade de conteúdo: condição de relevância + ação de correção |
| **Relevance language** | Linguagem que avalia se o endpoint é afetado (ex.: versão de um arquivo) |
| **Baseline** | Conjunto de fixlets aplicados juntos (ex.: patch mensal) |
| **Action** | Execução de um fixlet/baseline em um grupo de endpoints |
| **Compliance checklists** | Conteúdo CIS/DISA STIG com check e remediação |
| **Relay** | Servidor intermediário que distribui conteúdo e reduz a banda |

```text
// Exemplo de relevance: o Chrome está abaixo da versão X?
exists file "C:\Program Files\Google\Chrome\Application\chrome.exe"
  whose (version of it < "120.0.0.0")
```

## 🔗 Uso no fluxo da squad
`Tenable detecta → prioriza (VPR/EPSS/KEV) → BigFix aplica baseline → Tenable valida → MTTR`

## ✅ Próximos passos
- [ ] Documentar o processo de janela de patch usado no trabalho (genérico)
- [ ] Mapear controles CIS do BigFix para [[04_Dominios/Compliance as Code]]