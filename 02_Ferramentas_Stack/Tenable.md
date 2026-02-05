## Resumo 
#### Tenable (Gestão de Vulnerabilidades - DAST/Infra)

**O que é:** A Tenable (famosa pelo produto **Nessus**) é líder em **Gestão de Vulnerabilidades**. Diferente do SonarQube (que olha o código), a Tenable olha para a infraestrutura e aplicações que já estão rodando. Ela escaneia servidores, redes e aplicações web procurando portas abertas, sistemas desatualizados e falhas conhecidas (CVEs).

**A Analogia:** Imagine que você é dono de uma casa. A Tenable é um **inspetor de segurança patrimonial** que visita sua casa periodicamente. Ele anda ao redor, verifica se alguma janela está destrancada, se a fechadura da porta é de uma marca que é fácil de arrombar, ou se você deixou a chave embaixo do tapete.

**Como funciona no DevSecOps:** Você agenda scans recorrentes. A ferramenta vai dizer: "O servidor X está rodando uma versão do Windows que tem uma falha descoberta ontem por hackers russos".

**Exemplo Prático:** Sua empresa tem um servidor web Apache rodando a versão 2.4.49. O scanner da Tenable detecta isso e avisa que essa versão é vulnerável a um ataque chamado _Path Traversal_. O relatório gera um ticket para o time de operações atualizar o servidor.