# Hardening da Instância EC2

## Objetivo

Reduzir a superfície de ataque do servidor Ubuntu utilizado para hospedar o Nginx e realizar os exercícios do laboratório.

## Atualização do Sistema

Os pacotes do sistema foram atualizados antes da configuração dos serviços:

```bash
sudo apt update
sudo apt upgrade -y
```

## Proteção do SSH

Foram adotadas configurações para reduzir o risco de acesso administrativo indevido:

```text
PermitRootLogin no
PasswordAuthentication no
```

O acesso administrativo utiliza autenticação por chave e também é restringido pelo Security Group ao IP autorizado.

## Nginx

O Nginx foi instalado como servidor web da instância:

```bash
sudo apt install nginx -y
sudo systemctl enable --now nginx
```

Somente a porta necessária para o serviço web foi exposta. O funcionamento do serviço pode ser validado com:

```bash
sudo systemctl status nginx
sudo ss -tulpen
```

## Controles Complementares

- Uso de usuário administrativo sem login direto como `root`.
- Restrição de portas por Security Group.
- Atualização dos pacotes do sistema operacional.
- Monitoramento de CPU e do status da instância pelo CloudWatch.
- Registro de alterações administrativas pelo CloudTrail.
- Detecção de ameaças pelo GuardDuty e centralização de findings no Security Hub.

## Verificação

```bash
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication'
sudo systemctl is-active nginx
sudo ss -tulpen
```

## Limitações

O hardening realizado é adequado ao escopo do laboratório, mas não substitui controles de produção, como gerenciamento centralizado de patches, varredura de vulnerabilidades, EDR e acesso administrativo por rede privada ou bastion host.
