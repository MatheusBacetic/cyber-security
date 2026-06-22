# Kerberos

Kerberos foi analisado usando o comando `klist` no cliente Windows ingressado no domínio.

## Conceitos observados

- TGT
- TGS
- KDC
- SPN
- Tickets para LDAP
- Tickets para CIFS

## Fluxo básico

1. Usuário faz login no domínio.
2. O Domain Controller atua como KDC.
3. O usuário recebe um TGT.
4. Ao acessar um serviço, solicita um TGS.
5. O serviço valida o ticket.

## Exemplos observados

- `krbtgt/TREINO.LOCAL`
- `ldap/WIN-4JCARDE4JOD.treino.local`
- `cifs/WIN-4JCARDE4JOD.treino.local`