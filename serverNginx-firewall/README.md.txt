# Laboratório de Servidor Web Seguro com Kali Linux, Nginx e nftables

## Visão Geral

Este projeto tem como objetivo estudar Linux, Redes, Web Security e nftables de forma prática através da construção de um servidor web protegido por firewall stateful.

O foco não é apenas configurar ferramentas, mas compreender profundamente como os pacotes trafegam pela pilha de rede do Linux, como os serviços são expostos, como as regras de firewall são processadas e como monitorar e validar os controles de segurança implementados.

O ambiente foi construído em uma máquina virtual utilizando:

* Kali Linux
* Nginx
* nftables
* Firewall Stateful
* Logs e Monitoramento
* Whitelist por IP
* Tracing de Pacotes

O objetivo final é permitir o acesso ao servidor web apenas para dispositivos autorizados, reduzindo a superfície de ataque e aplicando o princípio do menor privilégio.

---

## Objetivos de Aprendizado

### Linux

* Administração de servidores Linux
* Gerenciamento de serviços
* Estrutura de diretórios
* Logs do sistema
* Interfaces de rede

### Redes

* Modelo TCP/IP
* Comunicação cliente-servidor
* Portas e serviços
* Fluxo de pacotes
* Análise de tráfego

### nftables

* Tables
* Base Chains
* Regular Chains
* Hooks
* Priorities
* Policies
* Rules
* Counters
* Handles
* Tracing
* Meta Expressions
* Interface Matching
* Connection Tracking

### Segurança Web

* Controle de acesso
* Redução da superfície de ataque
* Modelo Default Deny
* Firewall Stateful
* Monitoramento de eventos

---

## Arquitetura do Projeto

```text
Celular Autorizado
         │
         ▼
 Firewall nftables
         │
         ▼
      Nginx
         │
         ▼
 Conteúdo Web
```

---

## Estrutura do Firewall

### Table Principal

```text
inet firewall
```

Foi utilizada a família `inet` para permitir o tratamento de tráfego IPv4 e IPv6 dentro da mesma table.

---

## Chains Implementadas

### Input

Responsável por controlar todo o tráfego destinado à máquina.

Exemplos:

* Requisições HTTP
* Ping (ICMP)
* Tentativas de conexão externas

---

### Output

Responsável pelo controle do tráfego gerado pela própria máquina.

Exemplos:

* Consultas DNS
* Atualizações do sistema
* Acesso a sites externos

---

### Forward

Reservada para tráfego roteado.

Atualmente o servidor não atua como roteador, mas a chain foi criada para fins de estudo e expansão futura do laboratório.

---

### Whitelist

Chain auxiliar utilizada para organizar os IPs autorizados a acessar os serviços expostos.

---

### Logging

Chain destinada ao registro centralizado de eventos e pacotes bloqueados.

---

### Diagnostics

Utilizada durante testes, troubleshooting e análise de comportamento das regras.

---

## Modelo de Segurança

O firewall segue o conceito:

```text
Negar Tudo por Padrão (Default Deny)
```

Todo tráfego é bloqueado, exceto aquele explicitamente autorizado.

Princípios aplicados:

* Menor Privilégio
* Whitelist de Acesso
* Defesa em Profundidade
* Exposição Mínima de Serviços

---

## Funcionalidades de Segurança

### Firewall Stateful

Utilização do Connection Tracking do kernel Linux para acompanhar o estado das conexões.

Estados monitorados:

* NEW
* ESTABLISHED
* RELATED
* INVALID

---

### Controle de Acesso por IP

Apenas dispositivos autorizados podem acessar o servidor web.

---

### Logging

Registro de eventos relevantes para análise e auditoria.

---

### Tracing de Pacotes

Análise detalhada do processamento de pacotes utilizando:

```bash
nft monitor trace
```

Permitindo visualizar exatamente quais regras foram avaliadas e qual decisão foi tomada pelo firewall.

---

## Processo de Validação

Os controles implementados são validados através de testes controlados.

Exemplos:

* Testes de conectividade HTTP
* Verificação de regras de firewall
* Monitoramento de logs
* Análise de tracing
* Validação da whitelist

---

## Tecnologias Utilizadas

* Kali Linux
* Nginx
* nftables
* Connection Tracking (conntrack)
* VirtualBox

---

## Próximos Passos

* Implementação de HTTPS
* Certificados TLS
* Rate Limiting
* Integração com Fail2Ban
* Dashboard de monitoramento
* Coleta centralizada de logs
* Integração com SIEM
* Testes de segurança em ambiente controlado
* Hardening do Nginx
* Automação da configuração do firewall

---

## Autor

**Matheus Veiga Bacetic Joaquim**

Estudante de Ciência da Computação com foco em Linux, Redes, Web Security e Cyber Security.

Projeto desenvolvido com o objetivo de aprofundar conhecimentos em segurança ofensiva e defensiva através da construção de laboratórios práticos e documentáveis para portfólio profissional.
