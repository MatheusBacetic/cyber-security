# Arquitetura do Laboratório

## Objetivo

Construir um servidor web protegido por firewall utilizando nftables e Nginx.

## Ambiente

* Arch Linux
* Nginx
* nftables
* SSH (porta 2409)

## Fluxo da Rede

Celular Autorizado
↓
Firewall nftables
↓
Nginx
↓
Conteúdo Web

## Serviços Expostos

* HTTP (80)
* SSH (2409)

## Política de Segurança

* Default Deny
* Whitelist por IP
* Firewall Stateful
* Logging
* Counters
