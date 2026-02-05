
Para o setup rápido, utilize o [[Docker_Basic]] com a imagem oficial.

### Resumo

#### SonarQube (Segurança no Código - SAST)

**O que é:** O SonarQube é uma ferramenta de **SAST** (Static Application Security Testing). Ele analisa o código-fonte "parado" (antes de ser compilado ou executado) em busca de bugs, vulnerabilidades de segurança e "code smells" (código mal escrito).

**A Analogia:** Imagine que você está escrevendo um livro. O SonarQube é como um **editor gramatical extremamente rigoroso**. Antes de você imprimir o livro (fazer o deploy), ele lê seu rascunho e marca em vermelho: "Aqui tem um erro de digitação", "Esta frase está ambígua" ou "Você usou uma palavra ofensiva aqui". Ele te impede de publicar algo com erros básicos.

**Como funciona no DevSecOps:** Geralmente, o SonarQube é integrado na esteira de CI/CD (Integração Contínua). Assim que o desenvolvedor sobe o código (git push), o SonarQube analisa. Se a nota de segurança for baixa (o chamado _Quality Gate_), ele bloqueia o processo e não deixa o código ir para produção.

**Exemplo Prático:** Um desenvolvedor esquece uma senha _hardcoded_ (escrita diretamente no código) dentro de um arquivo Java: `String password = "admin123";`. O SonarQube detecta isso imediatamente e alerta: "Risco de Segurança Crítico: Credencial exposta".