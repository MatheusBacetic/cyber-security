# Auditing

Este laboratório utiliza Windows Event Logs para observar ações relevantes dentro do Active Directory.

## Eventos analisados

| Event ID | Descrição |
|---|---|
| 4624 | Logon bem-sucedido |
| 4625 | Falha de logon |
| 4720 | Usuário criado |
| 4728 | Usuário adicionado a grupo |
| 4738 | Usuário alterado |
| 4740 | Conta bloqueada |

## Objetivo

Entender como mudanças no domínio aparecem nos logs de segurança e como esses eventos podem ser usados em detecção.

## Exemplo

O evento `4738` foi utilizado para identificar alteração em uma conta de usuário.