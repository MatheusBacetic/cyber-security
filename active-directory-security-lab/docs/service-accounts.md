# Service Accounts

Service Accounts são contas do Active Directory utilizadas por serviços, aplicações ou tarefas automatizadas.

## Contas criadas

- svc_web
- svc_backup
- svc_monitor

## SPNs configurados

| Conta | SPN |
|---|---|
| svc_web | HTTP/intranet.treino.local |
| svc_backup | BACKUP/backup.treino.local |

## Objetivo

Entender como contas de serviço se relacionam com Kerberos, SPNs e permissões dentro do domínio.

## Importância em Cyber Security

Service Accounts são relevantes porque frequentemente possuem permissões elevadas ou acesso a recursos críticos. Elas também aparecem em análises de BloodHound, Kerberoasting e auditorias de Active Directory.