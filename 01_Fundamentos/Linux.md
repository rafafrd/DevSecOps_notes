

# 🐧 Linux: O Sistema Operacional da Nuvem

**Conceito:** No DevSecOps, o Linux não é apenas uma plataforma; é a ferramenta de trabalho. Servidores, containers (Docker) e orquestradores (Kubernetes) rodam sobre o Kernel Linux.

**Objetivo:** Controlar recursos, gerenciar permissões e auditar processos.

---

## 1. O Sistema de Arquivos e Permissões (A Base da Segurança)

Entender permissões é a primeira linha de defesa.

### Permissões Clássicas (`rwx`)

Cada arquivo tem 3 grupos de permissão: **Owner** (Dono), **Group** (Grupo), **Others** (Outros/Mundo).

- **r (Read/4):** Ler o arquivo / Listar diretório.
    
- **w (Write/2):** Editar o arquivo / Criar ou deletar arquivos no diretório.
    
- **x (Execute/1):** Rodar o script / Entrar no diretório (`cd`).
    

**Comandos Essenciais:**

Bash

```
# Muda o dono e o grupo (chown = change owner)
chown usuario:grupo arquivo.txt

# Muda permissões (chmod = change mode)
# 7 (4+2+1) = rwx | 5 (4+1) = r-x
chmod 750 script.sh  # Dono faz tudo, Grupo lê/executa, Outros não fazem nada.

# --- MODO EXPERT (BITS ESPECIAIS) ---

# SUID (Set User ID): Permite rodar um arquivo com a permissão do DONO, não de quem executou.
# Perigo: Se o comando 'passwd' tem SUID root, qualquer um roda como root.
chmod u+s binario_perigoso

# SGID (Set Group ID): Arquivos criados na pasta herdam o grupo da pasta.
chmod g+s /pasta/compartilhada

# Sticky Bit: Apenas o dono pode deletar o arquivo (usado no /tmp).
chmod +t /tmp
```

### Atributos Imutáveis (`chattr`)

Às vezes `root` não é suficiente. Use isso para impedir que hackers (ou você mesmo) apaguem logs ou arquivos de configuração.

Bash

```
# +i: Torna o arquivo IMUTÁVEL. Nem o root pode deletar ou alterar.
sudo chattr +i /etc/resolv.conf

# Lista atributos
lsattr /etc/resolv.conf

# Remove a proteção
sudo chattr -i /etc/resolv.conf
```

---

## 2. Manipulação Avançada de Arquivos e Texto

Em DevSecOps, você vai minerar logs e arquivos de configuração o tempo todo.

### `grep` (Global Regular Expression Print)

A ferramenta número 1 de busca.

Bash

```
# Procura recursivamente (-r) por "password" ignorando maiúsculas (-i) e mostra a linha (-n)
grep -rin "password" /var/www/html/

# Exclui resultados irrelevantes (-v)
cat logs.txt | grep "Error" | grep -v "Timeout"
```

### `find` (O Buscador do Sistema)

Usado para auditoria de arquivos suspeitos.

Bash

```
# Achar arquivos modificados nos últimos 10 minutos (forense rápida)
find / -mmin -10

# Achar arquivos maiores que 100MB (detectar dumps ou exfiltração)
find / -size +100M

# Achar arquivos com permissão 777 (perigo mundial)
find / -type f -perm 0777
```

---

## 3. Gerenciamento de Processos e Sinais

Seu servidor está lento ou tem um minerador de bitcoin rodando escondido?

### Monitoramento em Tempo Real

Bash

```
# htop: O gerenciador de tarefas visual (instale se não tiver)
htop

# ps: Snapshot dos processos atuais
# aux: a=todos usuários, u=detalhes do usuário, x=processos sem terminal
ps aux | grep nginx
```

### Matando Processos (`kill`)

O Linux usa "Sinais" para falar com processos.

Bash

```
# SIGTERM (15): "Por favor, feche gentilmente" (Padrão)
kill 1234

# SIGKILL (9): "MORRA IMEDIATAMENTE" (O processo não pode salvar nada/ignorar)
kill -9 1234

# SIGHUP (1): "Reinicie sua configuração" (Sem parar o processo)
kill -1 1234
```

### `lsof` (List Open Files) - **Ouro para Segurança**

No Linux, "tudo é um arquivo", inclusive conexões de rede.

Bash

```
# "Quem está escutando na porta 80?"
lsof -i :80

# "Quais arquivos o usuário 'apache' abriu?"
lsof -u apache

# "Quem está usando este arquivo específico?"
lsof /var/log/syslog
```

---

## 4. Redes e Diagnóstico (`ip`, `ss`, `nc`)

Esqueça `ifconfig` e `netstat`. Eles são obsoletos (depreciados).

### Verificação de Interfaces (`ip`)

Bash

```
# Mostra IPs
ip addr show

# Mostra tabela de roteamento (Gateway padrão)
ip route show
```

### Análise de Sockets (`ss` - Socket Statistics)

Bash

```
# Mostra todas as portas TCP (-t) escutando (-l) com números (-n) e processos (-p)
sudo ss -tulpn

# Saída típica (Auditando portas abertas):
# LISTEN  0  128  0.0.0.0:22  Users:(("sshd",pid=890,fd=3))
```

### `nc` (Netcat) - O Canivete Suíço TCP/IP

Usado para testar conexões, transferir arquivos e debugar firewalls.

Bash

```
# Testar se a porta 3306 (MySQL) está aberta num servidor remoto (-v = verbose, -z = scan)
nc -vz 192.168.1.50 3306

# Criar um chat simples (Servidor)
nc -l -p 1234
# Conectar no chat (Cliente)
nc 192.168.1.X 1234
```

---

## 5. Systemd (Gerenciamento de Serviços)

O `systemd` é o "pai" de todos os processos (PID 1). Ele controla o boot e os serviços.

### Controle Básico (`systemctl`)

Bash

```
# Iniciar, Parar, Reiniciar
sudo systemctl start docker
sudo systemctl stop nginx
sudo systemctl restart sshd

# Habilitar no boot (inicia automático quando liga o PC)
sudo systemctl enable fail2ban

# Ver logs de um serviço específico (mesmo que ele tenha morrido)
journalctl -u nginx -f
```

### Exemplo Prático: Criando um Serviço

Em DevSecOps, você cria serviços para suas automações.

Arquivo: `/etc/systemd/system/meu-monitor.service`

Ini, TOML

```
[Unit]
Description=Meu Monitor de Segurança
After=network.target

[Service]
User=devsecops
ExecStart=/usr/bin/python3 /opt/scripts/monitor.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Comando para ativar: `systemctl daemon-reload && systemctl start meu-monitor`.

---

## 6. Logs e Auditoria (`/var/log`)

O primeiro lugar que você olha quando algo dá errado.

- `/var/log/syslog` ou `/var/log/messages`: Logs gerais do sistema.
    
- `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (RHEL/CentOS): **Crítico.** Registra logins, sudo, e tentativas de invasão SSH.
    
- `/var/log/dmesg`: Logs do Kernel (Hardware, drivers).
    

**Comando de Auditoria em Tempo Real:**

Bash

```
# Monitora tentativas de login SSH ao vivo
tail -f /var/log/auth.log
```

---

## 7. Pacotes e Segurança (APT/YUM)

Manter o sistema atualizado é a tarefa #1 de segurança.

Bash

```
# Debian/Ubuntu (APT)
apt update             # Atualiza a lista de repositórios
apt list --upgradable  # Vê o que tem atualização
apt upgrade -y         # Aplica atualizações

# Instalar pacote de segurança específico
apt install fail2ban ufw

# RedHat/CentOS/Amazon Linux (YUM/DNF)
yum check-update
yum update -y
```

---

## 8. Ferramentas de Hardening & Diagnóstico (Nível Avançado)

Estas são as ferramentas que dão "peso" ao seu currículo.

- **`strace`**: Debuga a execução de um binário. Mostra cada chamada de sistema (abrir arquivo, ler rede).
    
    - _Uso:_ "Por que esse programa está travando sem erro?" -> `strace -p PID`.
        
- **`tcpdump`**: Captura pacotes de rede brutos (Wireshark via terminal).
    
    - _Uso:_ `tcpdump -i eth0 port 80`.
        
- **`curl`**: Cliente HTTP.
    
    - _Uso:_ Testar APIs. `curl -I https://site.com` (Vê apenas os headers, útil para checar versões de servidor expostas).
        
- **`ufw` (Uncomplicated Firewall)**: Firewall simples para host.
    
    - _Uso:_ `ufw allow 22/tcp`, `ufw enable`.
        

---

### Tabela de Referência Rápida (Cheat Sheet)

|**Categoria**|**Comando**|**Função**|
|---|---|---|
|**Arquivo**|`chown user:group`|Muda dono do arquivo.|
|**Arquivo**|`chmod 755`|Muda permissão (rwx).|
|**Arquivo**|`chattr +i`|Torna imutável (anti-delete).|
|**Busca**|`grep -r "txt" .`|Busca texto dentro de arquivos.|
|**Busca**|`find / -perm 777`|Busca arquivos inseguros.|
|**Rede**|`ss -tulpn`|Lista portas abertas.|
|**Rede**|`ip a`|Mostra IPs.|
|**Processo**|`ps aux`|Lista processos.|
|**Processo**|`kill -9 PID`|Mata processo à força.|
|**Sistema**|`systemctl status`|Vê status de serviço.|
|**Log**|`tail -f file`|Acompanha log ao vivo.|