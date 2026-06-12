# Configuração do Nginx

## Objetivo

Disponibilizar conteúdo web para dispositivos autorizados.

## Diretório Web

/usr/share/nginx/html

## Serviço

nginx.service

## Comandos Utilizados

Verificar status:

systemctl status nginx

Testar configuração:

nginx -t

Recarregar configuração:

systemctl reload nginx

## Validações

* Acesso via localhost
* Acesso via IP da máquina
* Acesso pelo celular
