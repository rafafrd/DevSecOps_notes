[[Linux]]
### Resumo

### BigFix Compliance (Correção e Conformidade)

**O que é:** O BigFix é uma ferramenta de **Gerenciamento de Endpoints e Patching**. Enquanto o Tenable _encontra_ o problema, o BigFix é quem vai lá e _resolve_ (aplica o patch/atualização) em milhares de máquinas ao mesmo tempo. A parte de "Compliance" garante que as configurações de segurança (ex: senha mínima de 8 caracteres) estejam ativas.

**A Analogia:** Se o Tenable é o inspetor que acha o problema, o BigFix é uma **equipe de manutenção com uma chave mestra mágica**. O inspetor diz "tem 500 lâmpadas queimadas no prédio". O BigFix estala os dedos e troca as 500 lâmpadas simultaneamente, sem precisar entrar de sala em sala.

**Como funciona no DevSecOps:** Automação de "higiene". Manter milhares de servidores atualizados manualmente é impossível. O BigFix automatiza isso para garantir que o ambiente esteja sempre em conformidade com as regras de segurança.

**Exemplo Prático:** A política da empresa diz que todos os computadores devem ter o antivírus ligado e o Chrome atualizado. O BigFix verifica 10.000 computadores. Ele descobre que 50 estão com o Chrome velho. Ele envia um comando silencioso que atualiza esses 50 computadores sem o usuário precisar clicar em nada.