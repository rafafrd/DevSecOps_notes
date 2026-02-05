
### 1. Tipos de Testes e Análises (AST)

_Essas siglas definem **como** e **quando** a segurança é verificada no software._

- **AST (Application Security Testing):** Termo "guarda-chuva" para qualquer ferramenta que testa segurança de software.
    
- **SAST (Static Application Security Testing):**
    
    - _O que é:_ Análise Estática. É o "Teste de Caixa Branca".
        
    - _Detalhe:_ Analisa o código-fonte, byte code ou binários **sem executar** a aplicação. Procura erros de sintaxe insegura.
        
    - _Ferramenta ex:_ **SonarQube**.
        
- **DAST (Dynamic Application Security Testing):**
    
    - _O que é:_ Análise Dinâmica. É o "Teste de Caixa Preta".
        
    - _Detalhe:_ Interage com a aplicação **em execução** (rodando). Simula um hacker tentando invadir de fora (inputs maliciosos, SQL Injection).
        
    - _Ferramenta ex:_ OWASP ZAP, Burp Suite.
        
- **SCA (Software Composition Analysis):**
    
    - _O que é:_ Análise de Composição de Software.
        
    - _Detalhe:_ Não olha o seu código, mas sim as **bibliotecas e dependências** (Open Source) que você usou. Se você importou uma biblioteca Java antiga com falha, o SCA avisa.
        
    - _Contexto:_ Essencial para segurança da cadeia de suprimentos (Supply Chain).
        
- **IAST (Interactive Application Security Testing):**
    
    - _O que é:_ Teste Interativo.
        
    - _Detalhe:_ Um híbrido de SAST e DAST. Um agente é instalado dentro da aplicação e analisa a execução do código em tempo real enquanto testes funcionais rodam.
        
- **RASP (Runtime Application Self-Protection):**
    
    - _O que é:_ Autoproteção em Tempo de Execução.
        
    - _Detalhe:_ Não é apenas um teste, é uma defesa. O software consegue detectar que está sendo atacado e bloquear a ação sozinho.
        

---

### 2. Infraestrutura e Nuvem (Cloud Native)

_Onde o código "mora". Aqui entram as siglas modernas de Cloud Security._

- **IaC (Infrastructure as Code):**
    
    - _O que é:_ Infraestrutura como Código.
        
    - _Detalhe:_ Gerenciar servidores usando arquivos de configuração (ex: Terraform, Ansible) em vez de painéis manuais. Permite versionar a infraestrutura.
        
- **CSPM (Cloud Security Posture Management):**
    
    - _O que é:_ Gerenciamento de Postura de Segurança na Nuvem.
        
    - _Detalhe:_ Ferramenta que monitora AWS/Azure/GCP para ver se você configurou algo errado (ex: deixou um bucket S3 público sem querer).
        
- **CWPP (Cloud Workload Protection Platform):**
    
    - _O que é:_ Plataforma de Proteção de Workloads na Nuvem.
        
    - _Detalhe:_ Foca na segurança do que _roda_ na nuvem (o container, a máquina virtual, a função serverless), protegendo contra malwares e intrusões.
        
- **CNAPP (Cloud-Native Application Protection Platform):**
    
    - _O que é:_ Plataforma de Proteção de Aplicações Cloud-Native.
        
    - _Detalhe:_ É a tendência atual. Combina **CSPM + CWPP + CIEM** em uma única ferramenta. É a "solução completa" para nuvem.
        
- **K8s (Kubernetes):**
    
    - _O que é:_ Abreviação de Kubernetes (8 letras entre o K e o s).
        
    - _Detalhe:_ Sistema de orquestração de containers. Em DevSecOps, proteger o K8s é uma das tarefas mais críticas e difíceis.
        

---

### 3. Vulnerabilidades e Métricas

_Como classificamos e medimos os problemas encontrados._

- **CVE (Common Vulnerabilities and Exposures):**
    
    - _O que é:_ É o "RG" de uma vulnerabilidade.
        
    - _Detalhe:_ Uma lista pública mundial. Exemplo: `CVE-2021-44228` (Log4Shell). Se o scanner (Tenable) achou algo, ele te dará o código CVE.
        
- **CVSS (Common Vulnerability Scoring System):**
    
    - _O que é:_ A "Nota" da vulnerabilidade.
        
    - _Detalhe:_ Vai de 0.0 a 10.0. Ajuda a priorizar.
        
        - 0-3.9: Baixa
            
        - 4.0-6.9: Média
            
        - 7.0-8.9: Alta
            
        - 9.0-10.0: Crítica
            
- **CWE (Common Weakness Enumeration):**
    
    - _O que é:_ A categoria do erro.
        
    - _Detalhe:_ Enquanto CVE é a falha específica, CWE é o "tipo" (ex: CWE-79 é Cross-Site Scripting).
        
- **NVD (National Vulnerability Database):**
    
    - _O que é:_ O banco de dados do governo dos EUA que lista todos os CVEs.
        
- **Zero-Day (0-day):**
    
    - _O que é:_ Vulnerabilidade de "Dia Zero".
        
    - _Detalhe:_ Uma falha que os hackers descobriram, mas o fabricante do software ainda não conhece ou não criou a correção. Não há "vacina" (patch) ainda.
        

---

### 4. Operações de Defesa e Resposta

_O dia a dia de monitoramento e reação (onde entra OpenCTI e Tenable)._

- **SIEM (Security Information and Event Management):**
    
    - _O que é:_ Gerenciamento e Correlação de Eventos.
        
    - _Detalhe:_ Centraliza logs de toda a empresa (firewall, servidores, antivírus) para detectar padrões de ataque. Ferramentas: Splunk, Elastic, Sentinel.
        
- **SOAR (Security Orchestration, Automation, and Response):**
    
    - _O que é:_ Orquestração e Resposta Automatizada.
        
    - _Detalhe:_ Se o SIEM detecta um ataque, o SOAR pode executar um script automático para bloquear o IP do atacante no firewall sem intervenção humana.
        
- **SOC (Security Operations Center):**
    
    - _O que é:_ O time/local físico onde os analistas de segurança monitoram as telas 24/7.
        
- **CTI (Cyber Threat Intelligence):**
    
    - _O que é:_ Inteligência de Ameaças.
        
    - _Detalhe:_ Coleta de dados para entender táticas, técnicas e procedimentos (TTPs) dos hackers. (Área do **OpenCTI**).
        

---

### 5. Processos e Governança

_Termos administrativos e de fluxo de trabalho._

- **CI/CD (Continuous Integration / Continuous Delivery):**
    
    - _O que é:_ A esteira automática de software.
        
    - _Detalhe:_ O "tubo" por onde o código passa. O objetivo do DevSecOps é colocar ferramentas de segurança (SAST/DAST) _dentro_ do CI/CD.
        
- **SBOM (Software Bill of Materials):**
    
    - _O que é:_ Lista de Materiais de Software.
        
    - _Detalhe:_ Um "inventário" completo de todos os componentes que compõem seu software. Muito exigido hoje em dia para auditoria.
        
- **OWASP (Open Web Application Security Project):**
    
    - _O que é:_ Fundação mundial sem fins lucrativos que define padrões de segurança web.
        
    - _Destaque:_ **OWASP Top 10** (a lista das 10 falhas mais críticas da web). Todo DevSecOps tem que saber isso de cor.
        
- **MTTR (Mean Time to Remediate/Response):**
    
    - _O que é:_ Tempo Médio para Remediação.
        
    - _Detalhe:_ KPI (indicador) importante. Quanto tempo seu time demora entre descobrir uma falha crítica e aplicar a correção?
        

---

### Dica para Anotação:

Se você tiver que priorizar para aprender **hoje**, foque neste trio:

1. **CI/CD** (Onde tudo acontece).
    
2. **SAST/DAST** (As principais ferramentas).
    
3. **CVE/CVSS** (Como medir o risco).
    

Quer que eu explique com mais detalhes alguma dessas categorias específicas, como por exemplo, o **OWASP Top 10**?