
### Grupo 1: Fundamentos e Modelos Teóricos

_A base de como a comunicação é estruturada._

#### 1. Modelo OSI (Open Systems Interconnection)

- **Conceito:** Um modelo teórico de 7 camadas que padroniza a comunicação. Para DevSecOps, as camadas mais críticas são a 3, 4 e 7.
    
    - **Camada 3 (Rede):** Onde vive o IP e o Roteamento.
        
    - **Camada 4 (Transporte):** Onde vivem TCP e UDP (portas).
        
    - **Camada 7 (Aplicação):** Onde vivem HTTP, SSH, FTP (o que o usuário vê).
        
- **Exemplo:** Um firewall de rede (L3/L4) bloqueia IPs e Portas. Um WAF (Web Application Firewall - L7) bloqueia ataques dentro do site, como SQL Injection.
    

#### 2. Encapsulamento

- **Conceito:** É o processo de "embrulhar" os dados à medida que descem as camadas do modelo OSI.
    
    - Dados -> Segmento (L4) -> Pacote (L3) -> Quadro/Frame (L2) -> Bits (L1).
        
- **Exemplo:** Imagine enviar uma carta. O papel é o dado. O envelope é o cabeçalho TCP. O malote do correio é o cabeçalho IP. O caminhão do correio é o quadro Ethernet.
    

---

### Grupo 2: Protocolos de Conexão e Transporte

_Como os dados viajam e garantem entrega._

#### 3. TCP vs. UDP

- **TCP (Transmission Control Protocol):** Orientado a conexão. Garante que o dado chegou. É lento, mas confiável.
    
- **UDP (User Datagram Protocol):** "Dispare e esqueça". Envia rápido sem checar se chegou. Usado em streaming e DNS.
    
- **Exemplo:** O download de um arquivo usa TCP (você não quer um arquivo corrompido). Uma chamada de vídeo usa UDP (se perder um pixel, o vídeo segue fluindo).
    

#### 4. Three-Way Handshake (O "Aperto de Mão" Triplo)

- **Conceito:** O processo rigoroso que o TCP usa para iniciar uma conexão segura antes de trocar dados.
    
    1. **SYN:** Cliente diz: "Oi Servidor, quero conectar" (sincronizar).
        
    2. **SYN-ACK:** Servidor diz: "Recebi seu Oi, posso conectar também?" (sincronizar + confirmar).
        
    3. **ACK:** Cliente diz: "Beleza, conexão estabelecida".
        
- **Segurança:** Um ataque famoso é o **SYN Flood**, onde o hacker manda milhões de "SYN" mas nunca manda o "ACK" final, deixando o servidor esperando até travar.
    

#### 5. Portas (Ports)

- **Conceito:** Endereços lógicos dentro de um IP para diferenciar serviços. Existem 65.535 portas possíveis.
    
- **Portas Comuns:** 80 (HTTP), 443 (HTTPS), 22 (SSH), 3389 (RDP).
    
- **Exemplo:** O IP é o endereço do prédio. A porta é o número do apartamento.
    

---

### Grupo 3: Endereçamento e Sub-redes (O "Terror" dos iniciantes)

_Como organizamos e dividimos as redes._

#### 6. CIDR (Classless Inter-Domain Routing)

- **Conceito:** Uma notação compacta para definir o tamanho de uma rede (máscara de sub-rede). É aquele `/24` ou `/16` no final do IP.
    
- **Como ler:** Indica quantos bits são fixos para a rede.
    
    - `192.168.1.0/24`: Os primeiros 24 bits são a rede. Sobram 8 bits para hosts (256 IPs).
        
    - `10.0.0.0/16`: Rede maior, sobram 16 bits para hosts (65.536 IPs).
        
- **Exemplo:** Em cloud (AWS/Azure), você bloqueia acesso dizendo: "Aceitar tráfego apenas de `10.0.1.0/24`".
    

#### 7. NAT (Network Address Translation)

- **Conceito:** Permite que vários dispositivos em uma rede privada (sua casa) acessem a internet usando apenas um IP Público.
    
- **Exemplo:** Seu notebook tem IP `192.168.0.5`. Seu celular `192.168.0.6`. Na internet, ambos aparecem com o IP do roteador `200.1.1.1`. O roteador faz a tradução (NAT) na volta para saber quem pediu o quê.
    

#### 8. DNS (Domain Name System)

- **Conceito:** A lista telefônica da internet. Traduz nomes (`google.com`) para IPs (`142.250.1.1`).
    
- **Segurança:** Ataques de **DNS Poisoning** tentam corromper essa lista para que, quando você digite `banco.com`, seja levado ao IP do hacker.
    

---

### Grupo 4: Infraestrutura Moderna e Virtualização

_Onde o DevSecOps trabalha hoje._

#### 9. VPS (Virtual Private Server)

- **Conceito:** Uma máquina virtual alugada em um servidor físico gigante. Ela tem seu próprio sistema operacional, CPU e RAM dedicados, simulando um servidor físico.
    
- **Exemplo:** DigitalOcean Droplet ou AWS EC2. É mais barato que um servidor dedicado, mas oferece isolamento total dos vizinhos (diferente de hospedagem compartilhada).
    

#### 10. Load Balancer (Balanceador de Carga)

- **Conceito:** Um dispositivo (ou software) que distribui o tráfego de entrada entre vários servidores backend.
    
- **Função:** Garante que nenhum servidor fique sobrecarregado.
    
- **Exemplo:** Quando 1 milhão de pessoas acessam a Amazon, o Load Balancer distribui 100 mil usuários para cada um dos 10 servidores disponíveis. Também ajuda na segurança ao esconder o IP real dos servidores de aplicação.
    

![Imagem de load balancer architecture diagram](https://encrypted-tbn2.gstatic.com/licensed-image?q=tbn:ANd9GcR0JpDr0M3EyphwcINs1vqSNsgNj-qgdH_jIy1cTftPikXAzf2UIzmrJ_XSJwqdyW8tWcD8WvwrjII0ba-V12_FGhU2IMWM2UTHGgC5-VNLQM3zzEM)

Shutterstock

#### 11. Proxy e Reverse Proxy

- **Proxy (Forward):** Age em nome do cliente. (Ex: Empresa usa proxy para bloquear funcionários de acessar Facebook).
    
- **Reverse Proxy:** Age em nome do servidor. Fica na frente do servidor web para receber requisições, fazer cache e criptografia. (Ex: Nginx recebendo a conexão e repassando para o backend em Node.js).
    

#### 12. SDN (Software Defined Networking)

- **Conceito:** Rede Definida por Software. Em vez de configurar cabos e roteadores físicos manualmente, você configura a rede via código/API.
    
- **Exemplo:** No Kubernetes ou AWS VPC, você cria redes, sub-redes e regras de firewall escrevendo arquivos YAML ou Terraform, sem tocar em hardware.
    

---

### Grupo 5: Segurança de Rede (Conceitos Defensivos)

#### 13. SSL/TLS Handshake

- **Conceito:** O processo que ocorre logo após o TCP Handshake para criptografar a conexão (transformar HTTP em HTTPS). Envolve troca de chaves públicas e certificação digital.
    
- **Exemplo:** Garante que, se alguém interceptar o cabo de rede, verá apenas lixo criptografado, e não sua senha.
    

#### 14. DMZ (Demilitarized Zone)

- **Conceito:** Uma sub-rede física ou lógica que expõe serviços externos (web server) à internet, mas isola estritamente o resto da rede interna (banco de dados).
    
- **Exemplo:** Se um hacker invade seu Site (na DMZ), ele ainda tem que passar por outro firewall para chegar ao Banco de Dados (na rede interna).
    

#### 15. VPN (Virtual Private Network)

- **Conceito:** Túnel criptografado sobre uma rede pública (Internet).
    
- **Site-to-Site VPN:** Conecta o escritório de SP ao escritório do RJ permanentemente.
    
- **Client-to-Site VPN:** Conecta o notebook do funcionário em home office à rede da empresa.
    

---

### Resumo para seu caderno (Relação DevSecOps)

Ao migrar para DevSecOps, você vai usar esses conceitos assim:

1. Vai escrever **IaC (Terraform)** para criar uma **VPC** (Rede Virtual).
    
2. Vai calcular o **CIDR** para garantir que cabem IPs suficientes para seus containers.
    
3. Vai configurar um **Load Balancer** para receber tráfego na porta **443 (HTTPS)**.
    
4. Vai configurar o **Firewall (Security Group)** para permitir entrada apenas na porta 443 e saída para o banco de dados.
    
5. Se algo der errado, vai usar o **TCP Dump** para ver se o **Three-way Handshake** está completando.