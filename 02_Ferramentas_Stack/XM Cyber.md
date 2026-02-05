### Resumo

#### XM Cyber (Simulação de Ataque - BAS)

**O que é:** XM Cyber é uma ferramenta de **Gerenciamento de Caminhos de Ataque** (Attack Path Management). Ela simula continuamente como um hacker poderia se mover dentro da sua rede. Ela não olha apenas uma falha isolada, mas sim a _combinação_ de falhas que leva ao "tesouro" (dados críticos).

**A Analogia:** O Tenable diz que a janela está aberta. O XM Cyber é como um **GPS para ladrões (Waze)**. Ele diz: "Se eu entrar por essa janela aberta (falha 1), eu consigo pegar a chave do carro que está na mesa (falha 2), e com o carro eu derrubo o portão dos fundos (falha 3) e roubo o cofre". Ele mostra a _rota_ do desastre.

**Como funciona no DevSecOps:** Ele ajuda a priorizar. Às vezes você tem 1.000 falhas para corrigir. O XM Cyber diz: "Corrija a falha A primeiro, porque ela é a ponte que permite chegar no servidor do Banco de Dados".

**Exemplo Prático:** Você tem uma impressora desatualizada na rede. Parece inofensivo. O XM Cyber mostra que, ao hackear a impressora, o invasor consegue roubar uma credencial salva na memória dela, e com essa credencial, ele acessa o servidor do CEO. Ele desenha esse caminho visualmente para você.