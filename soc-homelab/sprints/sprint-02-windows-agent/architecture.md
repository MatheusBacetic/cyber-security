# Architecture — Sprint 02

## Objetivo

Nesta sprint foi integrado o primeiro endpoint Windows ao Wazuh SIEM.

O Windows Server 2022, responsável pelo Active Directory, passou a enviar eventos de segurança para o Wazuh Manager instalado no Ubuntu Server.

---

# Componentes

| Componente | Função |
|------------|--------|
| Windows Server 2022 | Domain Controller e origem dos eventos |
| Wazuh Agent | Coleta eventos do Windows |
| Wazuh Manager | Recebe e processa eventos |
| Wazuh Indexer | Armazena os eventos |
| Wazuh Dashboard | Interface de visualização |

---

# Fluxo de Comunicação

```text
Windows Server
    │
    │ Enrollment (1515/TCP)
    ▼
Wazuh Authd
    │
    │ Agent Key
    ▼
Wazuh Manager
    │
    │ Event Collection (1514/TCP)
    ▼
Wazuh Indexer
    │
    ▼
Wazuh Dashboard
```

---

# Fluxo dos Logs

```text
Windows Event Log
        │
        ▼
Wazuh Agent
        │
        ▼
Wazuh Manager
        │
        ▼
Detection Rules
        │
        ▼
Indexer
        │
        ▼
Dashboard
```

---

# Comunicação

| Origem | Destino | Porta | Função |
|---------|----------|-------|--------|
| Windows Server | Wazuh Authd | TCP 1515 | Enrollment |
| Windows Server | Wazuh Manager | TCP 1514 | Envio de eventos |
| Dashboard | Indexer | HTTPS | Consultas |
| Dashboard | Manager | API | Gerenciamento |

---

# Estado da Arquitetura

Após esta sprint, o SOC Home Lab possui:

- 1 SIEM centralizado
- 1 Domain Controller monitorado
- Comunicação segura entre agente e manager
- Coleta centralizada de eventos do Windows
- Base preparada para integração do Sysmon