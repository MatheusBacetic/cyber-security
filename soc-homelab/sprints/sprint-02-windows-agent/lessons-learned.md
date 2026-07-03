# Lessons Learned

## Problema

Após a instalação do agente, o serviço WazuhSvc permaneceu parado.

## Diagnóstico

Foi verificado o status do serviço utilizando:

Get-Service WazuhSvc

O serviço existia, porém estava parado.

## Solução

O serviço foi iniciado manualmente:

Start-Service WazuhSvc

Após a inicialização, o agente realizou o enrollment automaticamente.

## Validação

- Agente listado no manager
- Agent ID criado
- Agent Active
- Logs mostrando geração da chave de autenticação