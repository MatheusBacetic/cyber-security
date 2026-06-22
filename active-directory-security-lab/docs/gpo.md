# Group Policy Objects

As GPOs foram utilizadas para aplicar políticas centralizadas aos usuários do domínio.

## Políticas implementadas

- Bloqueio do Painel de Controle para usuários fora da TI
- Account Lockout Policy
- Drive Mapping por departamento

## Drive Mapping

Cada departamento recebe automaticamente sua unidade de rede:

| Departamento | Unidade | Share |
|---|---|---|
| RH | R: | \\10.0.0.10\RH |
| TI | T: | \\10.0.0.10\TI |
| Jurídico | J: | \\10.0.0.10\Juridico |
| Financeiro | F: | \\10.0.0.10\Financeiro |