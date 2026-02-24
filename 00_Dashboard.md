na squad são utilizados essas ferramentas
- [[02_Ferramentas_Stack/SonarCube]]
- [[02_Ferramentas_Stack/Tenable]]
- [[02_Ferramentas_Stack/OpenCTI]]
- [[XM Cyber]]
- [[02_Ferramentas_Stack/BigFix Compliance]]


---
### nav. rapido

| **🏗️ Fundamentos**                                       | **🛠️ Stack Tecnológica**                                         | **📚 Referências**                               |
| --------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------ |
| [[01_Fundamentos/Linux\|🐧 Linux & Hardening]]            | [[02_Ferramentas_Stack/SonarCube\|🔍 SonarQube (SAST)]]           | [[03_Glossarios/Siglas\|📖 Glossário de Siglas]] |
| [[Conteiners\|🐳 Docker & Containers]]   | [[02_Ferramentas_Stack/Tenable\|🎯 Tenable (Vulnerability)]]      | [[99_Inbox/\|📥 Capturas Rápidas]]               |
| [[01_Fundamentos/Git\|🌿 Git & GitOps]]                   | [[02_Ferramentas_Stack/XM Cyber\|🛣️ XM Cyber (Attack Path)]]     |                                                  |
| [[Redes\|🌐 Redes de Computadores]] | [[02_Ferramentas_Stack/BigFix Compliance\|🛠️ BigFix (Patching)]] |                                                  |
|                                                           | [[02_Ferramentas_Stack/OpenCTI\|🧠 OpenCTI (Threat Intel)]]       |                                                  |

---
## Ciclo de Operação (Squad)

| **Ferramenta** | **Onde atua?** | **Função Principal** | **Pergunta que responde**                          |
| -------------- | -------------- | -------------------- | -------------------------------------------------- |
| **SonarQube**  | Código (Build) | Qualidade/SAST       | "Meu código tem brechas de segurança?"             |
| **Tenable**    | Infraestrutura | Scanner de Vuln.     | "Quais portas e softwares velhos tenho na rede?"   |
| **OpenCTI**    | Inteligência   | Base de Conhecimento | "Quem são os vilões e como eles agem?"             |
| **XM Cyber**   | Estratégia     | Caminhos de Ataque   | "Como um hacker chegaria nos meus dados críticos?" |
| **BigFix**     | Operação       | Patching/Correção    | "Como atualizo tudo isso de uma vez só?"           |

## Fluxo de Trabalho Técnico

Para uma atuação de DevSecOps eficiente, as notas se conectam da seguinte forma:

1. **Identificação:** O `[[02_Ferramentas_Stack/Tenable|Tenable]]` identifica um host vulnerável baseado em `[[01_Fundamentos/Resumo Redes|protocolos de rede]]` inseguros.
    
2. **Contextualização:** Consulto o `[[02_Ferramentas_Stack/OpenCTI|OpenCTI]]` para verificar se essa vulnerabilidade está sendo explorada ativamente por algum grupo de Ransomware.
    
3. **Priorização:** O `[[02_Ferramentas_Stack/XM Cyber|XM Cyber]]` me mostra se essa vulnerabilidade permite um "Lateral Movement" até o nosso banco de dados crítico.
    
4. **Remediação:** Utilizo o `[[02_Ferramentas_Stack/BigFix Compliance|BigFix]]` para realizar o deploy do patch em larga escala, garantindo que o `[[01_Fundamentos/Linux|SO Linux]]` esteja em conformidade.
    
5. **Prevenção:** O `[[02_Ferramentas_Stack/SonarCube|SonarQube]]` garante que novas versões do código não reintroduzam falhas de segurança no pipeline de CI/CD via `[[01_Fundamentos/Git|Git]]`.

---
### 1. SonarQube (Segurança no Código - SAST)

- **O que faz:** Analisa o **código-fonte** parado (antes de rodar) buscando bugs e senhas expostas.

- **Analogia:** É o **Corretor Ortográfico** rigoroso. Não deixa você publicar o livro (software) com erros de português.

- **Foco:** Qualidade e Segurança do _Software_.


### 2. Tenable (Gestão de Vulnerabilidades)

- **O que faz:** Escaneia **infraestrutura** (servidores/redes) buscando sistemas desatualizados e portas abertas.

- **Analogia:** É o **Inspetor Predial**. Checa se as janelas estão trancadas e se o muro está alto o suficiente.

- **Foco:** Falhas na _Infraestrutura_.


### 3. OpenCTI (Inteligência de Ameaças)

- **O que faz:** Banco de dados que organiza informações sobre **hackers e tipos de vírus**.

- **Analogia:** É o **Quadro do Detetive**. Conecta as pistas para entender quem é o inimigo e como ele ataca.

- **Foco:** _Conhecimento_ sobre o inimigo.


### 4. XM Cyber (Caminhos de Ataque)

- **O que faz:** Simula ataques para mostrar a **rota** que um hacker faria para chegar no dado mais crítico.

- **Analogia:** É o **GPS do Ladrão (Waze)**. Mostra o caminho exato da porta de entrada até o cofre.

- **Foco:** _Priorização_ (o que corrigir primeiro).


### 5. BigFix Compliance (Correção e Patching)

- **O que faz:** Aplica atualizações e correções em **milhares de máquinas** de forma automática.

- **Analogia:** É a **Equipe de Manutenção Mágica**. Troca 1.000 lâmpadas queimadas ao mesmo tempo com um estalar de dedos.

- **Foco:** _Automação_ da correção (mão na massa).


---

> **Fluxo Lógico:** O **SonarQube** limpa o código -> O **Tenable** acha o buraco na rede -> O **OpenCTI** diz quem pode atacar -> O **XM Cyber** diz por onde eles vão entrar -> O **BigFix** vai lá e fecha o buraco.

