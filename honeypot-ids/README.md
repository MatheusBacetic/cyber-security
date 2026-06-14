# SSH Honeypot + IDS

> Honeypot SSH desenvolvido em C para Linux com mecanismo básico de Intrusion Detection System (IDS) e integração com nftables.

## Sobre o Projeto

Este projeto foi desenvolvido como laboratório prático de Cyber Security com o objetivo de estudar programação de baixo nível em C, monitoramento de rede, detecção de intrusão e automação de resposta a incidentes em ambientes Linux.

O sistema simula um serviço SSH falso, registrando conexões recebidas, identificando possíveis tentativas de brute force e realizando bloqueio automático de endereços IP maliciosos utilizando nftables.

## Tecnologias Utilizadas

* C
* Linux
* Sockets TCP/IP
* nftables
* Git
* GCC
* Make

## Arquitetura

```text
Cliente
   │
   ▼
Honeypot SSH (Porta 2222)
   │
   ├── Captura IP
   │
   ├── Registro de Logs
   │
   ├── IDS
   │      └── Detecção de Brute Force
   │
   └── nftables
          └── Bloqueio Automático
```

## Estrutura do Projeto

```text
honeypot-ids/
├── include/
│   ├── server.h
│   ├── logger.h
│   ├── ids.h
│   └── nftables.h
│
├── src/
│   ├── main.c
│   ├── server.c
│   ├── logger.c
│   ├── ids.c
│   └── nftables.c
│
├── logs/
│
├── Makefile
└── README.md
```

## Funcionalidades

### Honeypot SSH

* Serviço TCP escutando na porta 2222
* Banner SSH falso
* Simulação de servidor OpenSSH

### Logging

* Registro de conexões recebidas
* Armazenamento de IP de origem
* Registro de data e horário dos eventos

### IDS

* Monitoramento de tentativas por endereço IP
* Detecção de possíveis ataques de força bruta
* Geração de alertas de segurança

### Resposta Automatizada

* Integração com nftables
* Criação dinâmica de regras de bloqueio
* Inserção automática de IPs maliciosos em blacklist

## Fluxo de Funcionamento

```text
Nova Conexão
      │
      ▼
Captura do IP
      │
      ▼
Registro em Log
      │
      ▼
Análise do IDS
      │
      ▼
Limite Excedido?
   │         │
  Não       Sim
   │         │
   ▼         ▼
 Continua  Gera Alerta
                │
                ▼
        Bloqueio via nftables
```

## Compilação

```bash
make
```

## Execução

```bash
sudo ./honeypot
```

## Exemplo de Detecção

```text
[CONEXAO] IP: 192.168.15.25

[IDS ALERT]
Possível brute force detectado:
IP: 192.168.15.25
Tentativas: 5
```

