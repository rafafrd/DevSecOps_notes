### Resumo
#### OpenCTI (Inteligência de Ameaças - CTI)

**O que é:** OpenCTI (Open Cyber Threat Intelligence) é uma plataforma para armazenar, organizar e visualizar informações sobre ameaças cibernéticas. É uma ferramenta de **conhecimento**. Ela ajuda a entender _quem_ está atacando, _como_ e _por quê_.

**A Analogia:** Lembra daqueles filmes policiais onde o detetive tem um **quadro na parede cheio de fotos de suspeitos conectadas por fios vermelhos**? O OpenCTI é esse quadro, só que digital e automatizado. Ele conecta um arquivo de vírus (malware) a um grupo hacker, que se conecta a uma técnica específica de ataque.

**Como funciona no DevSecOps:** Ele alimenta as outras ferramentas. Se o OpenCTI sabe que existe um novo vírus atacando bancos, ele pode avisar os times de defesa para procurarem por sinais específicos desse vírus.

**Exemplo Prático:** O OpenCTI ingere dados de várias fontes e mostra que o grupo hacker "Lazarus" está usando um arquivo PDF falso chamado "Fatura.pdf" para invadir empresas. Você usa essa informação para bloquear qualquer e-mail contendo esse arquivo específico antes que ele chegue ao usuário.

**Relacionado:** [[02_Ferramentas_Stack/MISP]] · [[04_Dominios/Threat Intel & Exploit Feed]] · [[04_Dominios/Purple Team]]

---

## 🧠 Conceitos-chave
| Conceito | O que é |
|---|---|
| **STIX 2.1** | Modelo de dados: Threat Actor, Intrusion Set, Campaign, Malware, Attack Pattern, Indicator, Vulnerability… |
| **TAXII** | Protocolo de transporte para trocar STIX |
| **Relationships** | O valor está nas ligações: `Intrusion Set —uses→ Attack Pattern` |
| **Connectors** | External import (MITRE, MISP, AlienVault, CISA KEV), enrichment (VirusTotal, Shodan), stream (SIEM) |
| **Observable vs Indicator** | Observable = fato (um IP); Indicator = padrão de detecção baseado nele |
| **Marking (TLP)** | Controle de compartilhamento |

## 🧪 Lab
- docker-compose oficial: github.com/OpenCTI-Platform/docker (exige ElasticSearch/OpenSearch, Redis, RabbitMQ, MinIO e bastante RAM)
- Conectores iniciais: MITRE ATT&CK, CISA KEV, MISP, CVE

## 🔗 Uso no fluxo da squad
- CVE na KEV → ver no OpenCTI quais atores a exploram → priorizar no Tenable/Vicarius
- Ator relevante ao setor → TTPs → cenários de [[04_Dominios/Purple Team]] e validação no XM Cyber

## ✅ Próximos passos
- [ ] Subir no lab e documentar os conectores
- [ ] Queries GraphQL da API para automação