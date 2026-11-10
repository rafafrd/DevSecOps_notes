---
title: "CI/CD — Pipeline com Code Quality e Observabilidade"
tags: [cicd, github-actions, sonarqube, devsecops, pipeline]
status: em-construcao
---

# 🚀 CI/CD — Pipeline DevSecOps

**Relacionado:** [[02_Ferramentas_Stack/SonarQube]] · [[04_Dominios/AppSec]] · [[04_Dominios/Supply Chain Security]] · [[04_Dominios/Secrets Management]] · [[01_Fundamentos/GitOps & ArgoCD]]

## 🗺️ Estágios de segurança no pipeline

| Estágio | Controle | Ferramentas |
|---|---|---|
| Pre-commit | Secrets, lint | gitleaks, pre-commit |
| Build | SAST, SCA | SonarQube, Semgrep, Trivy fs |
| Package | Container scan, SBOM, assinatura | Trivy, Syft, cosign |
| IaC | Misconfig | Checkov, Trivy config |
| Deploy | Policy gate | OPA/Conftest, Kyverno |
| Runtime | DAST, detecção | ZAP, Falco |

> [!TODO] Expandir cada estágio com o exemplo do lab em [[06_Labs/Homelab K3S]].

---

## Exemplo: GitHub Actions + SonarQube + Observabilidade


A arquitetura que faz mais sentido é esta:

1. **PR gate**: lint, testes, coverage, dependency review, SonarQube.
    
2. **Build principal**: build da app e imagem Docker.
    
3. **Performance**: sobe app + Prometheus + Grafana, roda **k6**, e falha o job se os thresholds de latência/erro estourarem. O Prometheus continua no modelo de scrape para a aplicação, e o k6 pode enviar métricas para o endpoint de remote write do Prometheus em cenários pequenos de CI. ([GitHub Docs](https://docs.github.com/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review "About dependency review - GitHub Docs"))
    

Uma estrutura de pastas boa para isso fica assim:

```text
.github/workflows/build.yml
sonar-project.properties
docker-compose.observability.yml
observability/prometheus/prometheus.yml
observability/grafana/provisioning/datasources/prometheus.yml
observability/grafana/provisioning/dashboards/provider.yml
performance/smoke.js
```

## 1) `build.yml`

Este exemplo é para **SonarQube Developer Edition+**. Se você estiver na Community Build/Edition, remova o trecho de `pull_request` do fluxo do Sonar e rode análise só na `main`. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-community-build/devops-platform-integration/github-integration/adding-analysis-to-github-actions-workflow?utm_source=chatgpt.com "Adding SonarQube analysis to your GitHub Actions workflow."))

```yaml
name: build

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write
  security-events: write

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  APP_PORT: 8080

jobs:
  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Dependency review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high

  build-test-sonar:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
        with:
          fetch-depth: 0

      # Escolha UM setup do seu stack:
      #
      # Node.js
      # - name: Setup Node
      #   uses: actions/setup-node@v4
      #   with:
      #     node-version: '22'
      #     cache: npm
      #
      # Java
      # - name: Setup Java
      #   uses: actions/setup-java@v4
      #   with:
      #     distribution: temurin
      #     java-version: '21'
      #     cache: maven
      #
      # Python
      # - name: Setup Python
      #   uses: actions/setup-python@v5
      #   with:
      #     python-version: '3.12'

      - name: Instalar dependências
        run: |
          # Node:
          # npm ci
          #
          # Maven:
          # mvn -B -DskipTests dependency:go-offline
          #
          # Gradle:
          # ./gradlew dependencies
          echo "Troque este bloco pelos comandos do seu stack"

      - name: Lint e testes com cobertura
        run: |
          # Node:
          # npm run lint
          # npm test -- --coverage
          #
          # Maven:
          # mvn -B clean verify
          #
          # Gradle:
          # ./gradlew clean test jacocoTestReport
          echo "Troque este bloco pelos comandos do seu stack"

      - name: Build da aplicação
        run: |
          # Node:
          # npm run build
          #
          # Maven:
          # mvn -B package -DskipTests
          #
          # Gradle:
          # ./gradlew build -x test
          echo "Troque este bloco pelos comandos do seu stack"

      - name: SonarQube scan
        uses: SonarSource/sonarqube-scan-action@v7
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
          # SONAR_ROOT_CERT: ${{ secrets.SONAR_ROOT_CERT }} # se usar CA interna
        with:
          args: >
            -Dsonar.qualitygate.wait=true
            -Dsonar.qualitygate.timeout=600

  performance:
    needs: build-test-sonar
    if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Build da imagem da aplicação
        run: docker build -t myapp:ci .

      - name: Subir app + Prometheus + Grafana
        run: docker compose -f docker-compose.observability.yml up -d

      - name: Esperar aplicação responder
        run: |
          for i in {1..30}; do
            curl -fsS http://localhost:${APP_PORT}/health && exit 0
            sleep 5
          done
          docker compose -f docker-compose.observability.yml logs
          exit 1

      - name: Instalar k6
        uses: grafana/setup-k6-action@v1

      - name: Rodar teste de carga
        env:
          K6_OUT: experimental-prometheus-rw
          K6_PROMETHEUS_RW_SERVER_URL: http://localhost:9090/api/v1/write
        run: |
          mkdir -p performance
          k6 run performance/smoke.js --summary-export=performance/k6-summary.json

      - name: Derrubar stack
        if: always()
        run: docker compose -f docker-compose.observability.yml down -v
```

Nesse YAML eu usei `fetch-depth: 0` porque o SonarQube recomenda evitar clone raso para não perder contexto do histórico. Também usei `sonar.qualitygate.wait=true`, que faz o step de análise esperar o resultado do quality gate e falhar o job se o gate ficar vermelho; o timeout padrão é 300s, mas você pode aumentar com `sonar.qualitygate.timeout`. O `dependency-review-action` é a action oficial do GitHub para bloquear dependências vulneráveis em PRs. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-server/10.6/devops-platform-integration/github-integration/adding-analysis-to-github-actions-workflow "Adding analysis to GitHub Actions workflow | SonarQube Server 10.6 | Sonar Documentation"))

As versões atuais que usei como referência foram `actions/checkout@v5`, `actions/dependency-review-action@v4`, `SonarSource/sonarqube-scan-action@v7` e `grafana/setup-k6-action@v1`. Em repositório real, o mais seguro é **fixar por SHA completo**, porque o GitHub recomenda isso para ações de terceiros e também recomenda dar ao `GITHUB_TOKEN` apenas as permissões mínimas necessárias. ([GitHub Docs](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configuring-the-dependency-review-action "Configuring the dependency review action - GitHub Docs"))

## 2) `sonar-project.properties`

```properties
sonar.projectKey=meu-projeto
sonar.projectName=meu-projeto
sonar.sourceEncoding=UTF-8

# Ajuste para o seu repositório
sonar.sources=src
sonar.tests=test

# Exemplos de cobertura: escolha o do seu stack
# JavaScript / TypeScript
# sonar.javascript.lcov.reportPaths=coverage/lcov.info

# Python
# sonar.python.coverage.reportPaths=coverage.xml

# Java / JaCoCo
# sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml

# Exemplo de exclusões
sonar.exclusions=**/node_modules/**,**/dist/**,**/*.min.js
```

O SonarQube pede que você configure os parâmetros de análise do projeto, e o `sonar-project.properties` é o jeito mais simples para o caso genérico com SonarScanner CLI/Action. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-server/10.6/devops-platform-integration/github-integration/adding-analysis-to-github-actions-workflow "Adding analysis to GitHub Actions workflow | SonarQube Server 10.6 | Sonar Documentation"))

## 3) `docker-compose.observability.yml`

```yaml
services:
  app:
    image: myapp:ci
    container_name: app
    ports:
      - "8080:8080"

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    command:
      - --config.file=/etc/prometheus/prometheus.yml
      - --web.enable-remote-write-receiver
    volumes:
      - ./observability/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    depends_on:
      - app

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD:-admin}
    volumes:
      - ./observability/grafana/provisioning:/etc/grafana/provisioning:ro
    depends_on:
      - prometheus
```

O Prometheus usa `scrape_configs` para coletar métricas dos alvos e o Grafana aceita provisioning por arquivos versionados em Git. Para o k6 mandar métricas para o Prometheus, você precisa habilitar o receiver com `--web.enable-remote-write-receiver`; quando isso está ligado, o endpoint é `/api/v1/write`. A própria documentação do Prometheus avisa que esse receiver não é para substituir scraping em alta escala, mas ele encaixa bem num uso controlado de CI/performance. ([Prometheus](https://prometheus.io/docs/prometheus/latest/configuration/configuration/ "Configuration | Prometheus"))

## 4) `observability/prometheus/prometheus.yml`

```yaml
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: "app"
    metrics_path: /metrics
    static_configs:
      - targets: ["app:8080"]

  - job_name: "prometheus"
    static_configs:
      - targets: ["prometheus:9090"]
```

Para isso funcionar, sua aplicação precisa expor métricas num endpoint HTTP, normalmente `/metrics`, usando uma client library do Prometheus da linguagem do seu projeto. O modelo padrão do Prometheus é **pull over HTTP**. ([Prometheus](https://prometheus.io/docs/instrumenting/clientlibs/ "Client libraries | Prometheus"))

## 5) `observability/grafana/provisioning/datasources/prometheus.yml`

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
```

## 6) `observability/grafana/provisioning/dashboards/provider.yml`

```yaml
apiVersion: 1

providers:
  - name: ci-performance
    orgId: 1
    folder: CI Performance
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /etc/grafana/provisioning/dashboards/json
```

O Grafana recomenda provisioning por arquivo para data sources e dashboards, justamente para deixar isso versionado como código. ([Grafana Labs](https://grafana.com/docs/grafana/latest/administration/provisioning/ "Provision Grafana | Grafana documentation"))

## 7) `performance/smoke.js`

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 20,
  duration: '1m',
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<300', 'p(99)<800'],
  },
};

export default function () {
  const res = http.get('http://localhost:8080/health');

  check(res, {
    'status 200': (r) => r.status === 200,
  });

  sleep(1);
}
```

No k6, **thresholds** são exatamente o mecanismo de “passa/falha” para performance. Então, no seu workflow, quem decide se a performance está aceitável não é o Grafana; é o k6, e o Grafana/Prometheus entram para visualizar e comparar os dados. ([Grafana Labs](https://grafana.com/docs/k6/latest/using-k6/thresholds/ "Thresholds | Grafana k6 documentation"))

## Como configurar os secrets e variables

No GitHub, você pode criar secrets em nível de **repositório**, **environment** ou **organização**. Para secret de repositório em organização, você precisa de acesso de escrita; para secret de environment em organização, precisa de acesso admin. O GitHub também recomenda usar secrets para dados sensíveis e aplicar princípio de menor privilégio. ([GitHub Docs](https://docs.github.com/actions/security-guides/using-secrets-in-github-actions "Using secrets in GitHub Actions - GitHub Docs"))

Crie estes:

- `SONAR_TOKEN`  
    Token do projeto no SonarQube. Obrigatório. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-server/2025.1/devops-platform-integration/github-integration/adding-analysis-to-github-actions-workflow "Adding analysis to GitHub Actions workflow | SonarQube Server 2025.1 LTA | Sonar Documentation"))
    
- `SONAR_HOST_URL`  
    URL do seu SonarQube Server. Pode ficar em secret; no material oficial também aparece como bom candidato a variável/secret em nível global. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-server/2025.1/devops-platform-integration/github-integration/adding-analysis-to-github-actions-workflow "Adding analysis to GitHub Actions workflow | SonarQube Server 2025.1 LTA | Sonar Documentation"))
    
- `SONAR_ROOT_CERT`  
    Só se o seu SonarQube estiver atrás de certificado interno/self-signed. ([GitHub](https://github.com/marketplace/actions/official-sonarqube-scan "Official SonarQube Scan · Actions · GitHub Marketplace · GitHub"))
    
- `GRAFANA_ADMIN_PASSWORD`  
    Opcional, só para não deixar a senha padrão do Grafana no compose.
    

Se várias repos vão usar o mesmo SonarQube, vale criar `SONAR_TOKEN` e `SONAR_HOST_URL` como **organization secrets**. Só toma cuidado: um token global do SonarQube dá acesso amplo aos projetos da instância, então é melhor usar token por projeto quando possível. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-server/10.8/devops-platform-integration/github-integration/setting-up-at-global-level/setting-parameters-for-github-actions "Setting parameters for GitHub Actions | SonarQube Server 10.8 | Sonar Documentation"))

## Como configurar cada ferramenta

### SonarQube

1. Crie o projeto no SonarQube.
    
2. Gere um token do projeto.
    
3. Salve `SONAR_TOKEN` e `SONAR_HOST_URL` no GitHub.
    
4. Adicione o `sonar-project.properties`.
    
5. No branch protection do GitHub, marque o job do workflow como **required** para impedir merge quando falhar. O SonarQube também consegue decorar PR com status do quality gate. ([Sonar Documentation](https://docs.sonarsource.com/sonarqube-server/2025.1/devops-platform-integration/github-integration/adding-analysis-to-github-actions-workflow "Adding analysis to GitHub Actions workflow | SonarQube Server 2025.1 LTA | Sonar Documentation"))
    

### Prometheus

1. Instrumente a aplicação para expor `/metrics`.
    
2. Configure `scrape_configs` apontando para o container da app.
    
3. Habilite remote write receiver só para o k6 enviar métricas do teste. ([Prometheus](https://prometheus.io/docs/instrumenting/clientlibs/ "Client libraries | Prometheus"))
    

### Grafana

1. Faça provisioning do datasource do Prometheus por YAML.
    
2. Versione dashboards como arquivo se quiser manter tudo em Git. ([Grafana Labs](https://grafana.com/docs/grafana/latest/administration/provisioning/ "Provision Grafana | Grafana documentation"))
    

### GitHub Actions

1. Use `permissions` mínimos no workflow.
    
2. Prefira actions oficiais/verificadas.
    
3. Em produção, fixe por SHA completo. ([GitHub Docs](https://docs.github.com/actions/reference/authentication-in-a-workflow "Use GITHUB_TOKEN for authentication in workflows - GitHub Docs"))
    

## O que eu sugiro adicionar também

Eu colocaria mais quatro coisas:

- **CodeQL** para segurança estática nativa do GitHub. Ele gera alerts de code scanning; para começar rápido, o melhor é usar o **default setup** no próprio GitHub. ([GitHub Docs](https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql "About code scanning with CodeQL - GitHub Docs"))
    
- **Dependabot alerts + security updates + version updates** para dependências vulneráveis e atualização automática. ([GitHub Docs](https://docs.github.com/code-security/dependabot/dependabot-alerts/about-dependabot-alerts "About Dependabot alerts - GitHub Docs"))
    
- **Trivy** se você gera imagem Docker, para escanear vulnerabilidades na imagem e em misconfigs. O Trivy tem integração oficial/documentada para GitHub Actions. ([Trivy](https://trivy.dev/docs/latest/tutorials/integrations/github-actions/ "GitHub Actions - Trivy"))
    
- **OIDC** para cloud, em vez de guardar credenciais long-lived em secrets, quando você precisar publicar imagem ou fazer deploy. ([GitHub Docs](https://docs.github.com/en/actions/reference/security/secure-use "Secure use reference - GitHub Docs"))
    

Se você estiver na **Community Build/Edition**, meu ajuste seria: manter `lint + test + dependency review + k6` no PR e rodar **SonarQube só na `main`**. Se você quiser, no próximo passo eu posso te devolver isso já pronto em um pacote completo para o seu stack específico, por exemplo **Node**, **Java/Spring Boot**, **Python/FastAPI** ou **.NET**.