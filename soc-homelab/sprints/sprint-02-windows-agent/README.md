# Sprint 02 — Windows Server Agent Onboarding

## Overview

Nesta sprint foi realizada a integração do **Windows Server 2022 (Domain Controller)** ao **Wazuh SIEM**, transformando o controlador de domínio no primeiro endpoint monitorado do SOC Home Lab.

O objetivo desta etapa foi estabelecer a comunicação entre o Active Directory e o Wazuh Manager, permitindo a centralização de logs e preparando o ambiente para as próximas fases do laboratório, como Sysmon, Sigma Rules, MITRE ATT&CK, Threat Hunting e Incident Response.

---

# Objetivos da Sprint

- Integrar o Windows Server ao Wazuh Manager
- Registrar o agente no Manager (Enrollment)
- Validar a comunicação entre agente e servidor
- Confirmar o envio de eventos para o SIEM
- Documentar todo o processo
- Criar a base para monitoramento do Active Directory

---

# Arquitetura

```text
                    INTERNET
                        │
                 VirtualBox NAT
                        │
        ┌─────────────────────────────────────┐
        │                                     │
        │      Internal Network               │
        │        192.168.100.0/24             │
        │                                     │
        └─────────────────────────────────────┘
              │                     │
              │                     │
              │                     ▼
              │            Ubuntu Server 24.04
              │            192.168.100.30
              │
              │             ┌──────────────────┐
              └────────────▶│   Wazuh Manager   │
                            │   Wazuh Indexer   │
                            │   Wazuh Dashboard │
                            │   Filebeat        │
                            └──────────────────┘
                                      ▲
                                      │
                         Secure Agent Communication
                                      │
                         Enrollment (1515/TCP)
                         Event Forwarding (1514/TCP)
                                      │
                                      │
                                      ▼
                       Windows Server 2022
                       Domain Controller
                       192.168.100.10
                       Wazuh Agent
```

---

# Ambiente

| Componente | Versão |
|------------|---------|
| Ubuntu Server | 24.04 |
| Windows Server | 2022 |
| Wazuh | 4.14.x |
| VirtualBox | Rede NAT + Internal Network |

---

# Implementação

## 1. Deploy do agente

O agente foi implantado utilizando o assistente **Deploy New Agent** do próprio Wazuh Dashboard.

Foram utilizados os seguintes parâmetros:

- Sistema Operacional: Windows
- Agent Name: `WIN-SERVER-DC`
- Manager:

```
192.168.100.30
```

---

## 2. Instalação

A instalação foi realizada em modo silencioso utilizando o MSI oficial do Wazuh.

Durante a instalação foram definidos:

- endereço do Manager
- nome do agente

Após a instalação foi iniciado o serviço:

```
WazuhSvc
```

---

## 3. Validação do serviço

Foi confirmado que o serviço do agente estava em execução.

```powershell
Get-Service WazuhSvc
```

Resultado esperado:

```
Status : Running
```

---

## 4. Enrollment

Após iniciar o serviço, o agente realizou automaticamente o processo de registro (Enrollment) junto ao Wazuh Manager.

Durante esse processo:

- o agente solicitou registro;
- o Wazuh Authd recebeu a requisição;
- uma chave criptográfica foi criada;
- o agente passou a ser autenticado pelo Manager.

Trecho observado no servidor:

```
Received request for a new agent
Agent key generated
Authentication file changed
```

---

## 5. Comunicação

Após o enrollment, o agente passou a enviar eventos continuamente ao Wazuh Manager.

Fluxo de comunicação:

```
Windows Server
      │
      │ Enrollment
      ▼
Porta TCP 1515
      │
      ▼
Wazuh Authd
      │
      ▼
Agent Key
      │
      ▼
Porta TCP 1514
      │
      ▼
Wazuh Manager
      │
      ▼
Indexer
      │
      ▼
Dashboard
```

---

# Evidências

Adicionar as capturas de tela em:

```
evidence/
```

Sugestão de arquivos:

```
01-deploy-agent.png

02-wazuh-service-running.png

03-agent-active-dashboard.png

04-agent-control.png

05-ossec-registration-log.png
```

---

# Validação

Checklist da Sprint:

- [x] Wazuh Agent instalado
- [x] Serviço WazuhSvc em execução
- [x] Agente registrado no Manager
- [x] Enrollment realizado
- [x] Agent Key criada
- [x] Comunicação com o Manager validada
- [x] Agente listado como Active
- [x] Logs chegando ao SIEM

---

# Conceitos Aprendidos

## Wazuh Agent

Software instalado nos endpoints responsável por coletar eventos e enviá-los ao Wazuh Manager.

---

## Enrollment

Processo inicial de registro entre agente e servidor.

Durante o enrollment:

- o agente solicita autorização;
- o Manager gera uma chave única;
- o agente passa a ser considerado confiável.

---

## Wazuh Authd

Serviço responsável pelo registro seguro de novos agentes.

Utiliza a porta:

```
1515/TCP
```

---

## Wazuh Manager

Recebe todos os eventos enviados pelos agentes, executa regras de detecção, correlação e gera alertas.

Recebe eventos pela porta:

```
1514/TCP
```

---

# Troubleshooting

## Problema encontrado

Após a instalação do agente, o serviço:

```
WazuhSvc
```

permaneceu parado.

---

## Diagnóstico

Foi realizada a verificação:

```powershell
Get-Service WazuhSvc
```

Resultado:

```
Stopped
```

---

## Solução

Inicialização manual do serviço:

```powershell
Start-Service WazuhSvc
```

Após isso:

- o agente iniciou corretamente;
- realizou o enrollment automaticamente;
- passou a aparecer como **Active**.

---

# Importância para um SOC

O Domain Controller é um dos ativos mais críticos de uma infraestrutura corporativa.

Centralizar seus logs permite detectar eventos como:

- autenticações suspeitas;
- brute force;
- password spraying;
- criação de usuários;
- alterações em grupos privilegiados;
- movimentação lateral;
- abuso de privilégios;
- persistência.

O onboarding do controlador de domínio representa o primeiro passo para a construção de um ambiente de monitoramento semelhante ao utilizado em SOCs reais.

---

# Próximos Passos

Sprint 03

**Sysmon Integration**

Objetivos:

- Instalar Sysmon
- Configurar SwiftOnSecurity Sysmon Config
- Coletar eventos avançados
- Integrar Sysmon ao Wazuh
- Validar Process Creation
- Validar Network Connections
- Preparar ambiente para Sigma Rules e MITRE ATT&CK

---

# Tecnologias Utilizadas

- Wazuh Manager
- Wazuh Agent
- Wazuh Dashboard
- Filebeat
- Windows Server 2022
- Ubuntu Server 24.04
- Active Directory
- VirtualBox

---

# Resultado

Ao final da Sprint 02, o Domain Controller foi integrado com sucesso ao Wazuh SIEM, tornando-se o primeiro endpoint monitorado do SOC Home Lab.

Com essa integração concluída, o laboratório passa a possuir uma arquitetura capaz de centralizar eventos de segurança, servindo como base para detecção de ameaças, engenharia de detecção, threat hunting e resposta a incidentes nas próximas sprints.