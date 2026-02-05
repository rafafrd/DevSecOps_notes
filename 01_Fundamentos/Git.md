# 🐙 Git: O Manual Completo do DevSecOps

Este guia cobre desde a configuração até a "cirurgia" no repositório.

## 1. Configuração e Identidade (Foundation)

_Sem isso, seus logs de auditoria não valem nada._

Bash

```
# Define seu nome e email (básico)
git config --global user.name "Seu Nome"
git config --global user.email "seu@email.com"

# --- ADICIONADOS ---

# Define o editor padrão (evita cair no VIM sem querer)
git config --global core.editor "code --wait"  # Para VS Code

# Ativa cores no terminal (ajuda a ler diffs de segurança)
git config --global color.ui auto

# Assinatura GPG (Crucial para DevSecOps: prova que o commit é seu)
git config --global user.signingkey <ID-DA-SUA-CHAVE>
git config --global commit.gpgsign true

# Lista todas as configurações atuais (para debug)
git config --list
```

---

## 2. Staging e Commits (O dia a dia "Cirúrgico")

_Um DevSecOps não commita "lixo". Seus commits devem ser atômicos._

Bash

```
# Inicia repositório
git init

# Adiciona arquivos específicos
git add arquivo.txt

# --- ADICIONADOS ---

# Adição Interativa (O MAIS IMPORTANTE):
# Permite revisar pedaço por pedaço (hunk) do código antes de adicionar.
# Evita subir senhas ou console.log esquecidos.
git add -p 

# Desfaz o 'git add' de um arquivo (tira da staging area)
git restore --staged arquivo.txt

# Corrige o ÚLTIMO commit (muda mensagem ou adiciona arquivos esquecidos)
# Evita criar commits do tipo "fix", "fix 2", "agora vai"
git commit --amend -m "Nova mensagem correta"

# Commita ignorando os hooks de pré-commit (PERIGOSO - Use só em emergência)
# Ex: Se o hook de segurança estiver bloqueando um falso-positivo
git commit --no-verify -m "Hotfix critico"
```

---

## 3. Navegação e Branches (Moderno)

_Comandos atualizados. `checkout` faz muita coisa, por isso o Git moderno dividiu em `switch` e `restore`._

Bash

```
# Lista branches (locais e remotos)
git branch -a

# Cria e muda para a branch nova
git checkout -b feature/nova-auth

# --- ADICIONADOS ---

# (Moderno) Muda de branch
git switch main

# (Moderno) Cria e muda de branch
git switch -c feature/nova-auth

# Deleta uma branch local (só se já tiver feito merge)
git branch -d nome-da-branch

# FORÇA a deleção de uma branch (mesmo sem merge - útil para limpar testes)
git branch -D nome-da-branch

# Renomeia a branch atual (ex: master -> main)
git branch -m main
```

---

## 4. Sincronização e Remoto (Trabalho em Equipe)

Bash

```
# Baixa atualizações
git pull origin main

# Envia alterações
git push origin main

# --- ADICIONADOS ---

# Adiciona um repositório remoto
git remote add origin https://github.com/user/repo.git

# Verifica para onde seu código está indo (Audit)
git remote -v

# Baixa atualizações SEM aplicar no seu código (Seguro para inspeção)
git fetch --all

# Limpa referências locais de branches que já foram apagadas no servidor
# Mantém seu 'git branch -a' limpo
git fetch --prune

# Push Forçado SEGURO.
# Só sobrescreve se ninguém mais tiver enviado código nesse meio tempo.
# Use isso em vez de 'git push --force' para não apagar trabalho dos colegas.
git push --force-with-lease
```

---

## 5. Auditoria e Investigação (Ferramentas Forenses)

_Aqui vive o DevSecOps. Comandos para achar agulha no palheiro._

Bash

```
# Histórico simples
git log --oneline

# Histórico detalhado com alterações de código
git log -p

# O "Dedo-duro" (quem alterou a linha)
git blame arquivo.txt

# --- ADICIONADOS ---

# O Gráfico Visual no Terminal
# Ótimo para entender merges complexos e onde as branches se separaram
git log --graph --oneline --decorate --all

# Busca por TEXTO em todo o histórico (Ex: achar onde vazou a API Key)
# Procura no CONTEÚDO (código), não na mensagem do commit.
git log -S "API_KEY_VALUE" --source --all

# Busca por TEXTO no código ATUAL (muito mais rápido que o grep do linux)
# Mostra o número da linha (-n)
git grep -n "password"

# Estatísticas: Quem está commitando mais?
git shortlog -sn

# O SALVA-VIDAS (Reflog)
# Mostra TUDO que você fez localmente, inclusive commits deletados e resets.
# Se você fez um 'git reset --hard' e se arrependeu, o commit perdido está aqui.
git reflog
```

---

## 6. Debugging Automatizado (`git bisect`)

_Este é um superpoder. Encontre qual commit quebrou o sistema ou inseriu a vulnerabilidade automaticamente._

**Cenário:** A versão 1.0 estava segura. A versão 2.0 (100 commits depois) tem uma falha. Qual dos 100 commits causou isso?

Bash

```
# Inicia o modo detetive
git bisect start

# Diz que a versão atual está ruim (vulnerável)
git bisect bad

# Diz que a versão antiga (hash ou tag) estava boa
git bisect good v1.0

# O Git vai pular para o meio do histórico.
# Você testa. Se estiver ruim, digite 'git bisect bad'. Se bom, 'git bisect good'.
# Ele vai dividindo a busca até sobrar 1 único commit culpado.

# Sai do modo bisect
git bisect reset
```

---

## 7. Manipulação Avançada de Histórico (`Rebase`)

_Usado para limpar o histórico antes de jogar na main ou remover dados sensíveis._

Bash

```
# Traz alterações da main para sua branch (mantendo histórico linear)
git rebase main

# --- ADICIONADOS ---

# Rebase Interativo (Poderoso)
# Abre um editor onde você pode:
# - pick: manter o commit
# - drop: apagar o commit (útil se o commit tiver um arquivo sensível)
# - squash: fundir esse commit com o anterior (esconder bagunça)
# - reword: mudar a mensagem do commit
git rebase -i HEAD~5  (Olha os últimos 5 commits)

# Abortar rebase se der conflito e pânico
git rebase --abort
```

---

## 8. Limpeza e "Nuke" (Use com Cuidado)

Bash

```
# --- ADICIONADOS ---

# Mostra quais arquivos "não rastreados" (novos) seriam apagados
git clean -n

# APAGA de verdade arquivos não rastreados e diretórios (-d)
# Útil para limpar arquivos de build ou logs gerados após um teste
git clean -fd

# Reseta TUDO para o estado do último commit (Destrutivo)
git reset --hard HEAD

# Reseta, mas mantém as mudanças na sua máquina (Seguro)
git reset --soft HEAD~1
```

---

## 9. Submodules (Comum em projetos grandes)

_Muitas empresas usam repositórios dentro de repositórios._

Bash

```
# --- ADICIONADOS ---

# Adiciona um submódulo
git submodule add https://github.com/lib/lib.git

# Inicializa e atualiza submódulos ao clonar um projeto
git submodule update --init --recursive
```

---

## Exemplo Prático de Segurança: O "Roubo" via Cherry-Pick

Você pediu um exemplo detalhado de como usar `cherry-pick` para "roubar" ou recuperar algo.

**Cenário:**

Um desenvolvedor estava trabalhando na branch `feature-login`. Ele criou um arquivo `.env` com as credenciais de produção para testar (erro grave). Ele percebeu, deletou o arquivo em um novo commit, e continuou trabalhando.

A branch `feature-login` foi deletada, mas o commit **ainda existe** no banco de dados do Git (dangling commit) ou em outra branch de backup.

**Passo a Passo do DevSecOps:**

1. **Achar o commit perdido:**
    
    Você suspeita que houve vazamento. Você usa o `fsck` (File System Check) para achar objetos perdidos ou o `reflog`.
    
    Bash
    
    ```
    git fsck --lost-found
    # ou
    git log --all --full-history -- "**.env"
    ```
    
    _Resultado:_ Você acha o hash `a1b2c3d` onde o arquivo foi criado.
    
2. **Trazer o arquivo para análise (Isolation):**
    
    Você não quer sujar sua branch atual fazendo merge de tudo o que o desenvolvedor fez. Você quer **apenas** aquele momento onde o arquivo existia.
    
    Bash
    
    ```
    # Cria uma branch temporária para auditoria
    git checkout -b auditoria-seguranca
    
    # "Rouba" (Cherry-pick) apenas aquele commit específico para sua branch
    git cherry-pick a1b2c3d
    ```
    
3. **Resultado:**
    
    Agora, na sua branch `auditoria-seguranca`, o arquivo `.env` "mágico" apareceu na sua pasta. Você pode abri-lo, confirmar que as credenciais são reais, revogá-las na AWS/Azure e gerar o relatório de incidente.
    

---

fiquei de ver

1. `git reflog` (Recuperar o irremediável)
    
2. `git commit --amend` (Corrigir o último erro)
    
3. `git reset --soft HEAD~1` (Desfazer o commit mas manter o código)