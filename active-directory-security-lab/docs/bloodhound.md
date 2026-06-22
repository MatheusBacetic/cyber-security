# BloodHound Analysis

## Visão Geral

Após a implementação do ambiente Active Directory, foi realizada uma etapa de enumeração e análise utilizando o BloodHound Community Edition.

O objetivo desta fase foi validar a estrutura do domínio criada no laboratório e compreender como usuários, grupos, computadores, unidades organizacionais (OUs), GPOs e Service Accounts são representados sob a perspectiva de segurança ofensiva.

O BloodHound é amplamente utilizado por profissionais de Cyber Security para identificar relações de privilégio e possíveis caminhos de movimentação lateral em ambientes Active Directory.

---

# Ambiente Analisado

## Domínio

```text
TREINO.LOCAL
```

## Infraestrutura

* Windows Server 2022 (Domain Controller)
* Active Directory Domain Services
* DNS
* Kerberos
* Compartilhamentos SMB
* Windows 10 Client
* Kali Linux

---

# Estrutura Organizacional

O domínio foi organizado utilizando Unidades Organizacionais (OUs) para simular um ambiente corporativo.

```text
TREINO.LOCAL
│
├── Corporativo
│   ├── Usuarios
│   ├── Computadores
│   ├── Grupos
│   └── Service Accounts
│
├── Domain Controllers
│
└── Containers Padrão do Active Directory
```

---

# Coleta de Dados

A coleta foi realizada a partir do Kali Linux utilizando BloodHound Python.

## Comando utilizado

```bash
bloodhound-python -u matheus.ti -p 'PASSWORD' -d treino.local -ns 10.0.0.10 -c All
```

## Objetivo da Coleta

Enumerar:

* Usuários
* Grupos
* Computadores
* OUs
* GPOs
* Containers
* Service Accounts
* Relacionamentos de privilégio

---

# Resultados da Enumeração

A coleta identificou os seguintes objetos:

| Tipo         | Quantidade |
| ------------ | ---------- |
| Usuários     | 19         |
| Grupos       | 61         |
| Computadores | 11         |
| OUs          | 15         |
| GPOs         | 10         |
| Domínios     | 1          |
| Trusts       | 0          |

---

# Usuários e Grupos

Foram criados usuários representando diferentes departamentos da organização.

Exemplos:

```text
matheus.ti
patricia.rh
joao.financeiro
```

Os usuários foram associados a grupos de segurança específicos para implementação de RBAC (Role-Based Access Control).

Exemplo identificado pelo BloodHound:

```text
PATRICIA.RH
        │
        └── MemberOf
                │
                ▼
GG_RH_ADMINS
```

Esse relacionamento demonstra que a usuária recebe permissões através da associação ao grupo de segurança correspondente.

---

# Compartilhamentos SMB

Foram implementados compartilhamentos departamentais:

```text
RH
Financeiro
Jurídico
TI
```

O acesso aos compartilhamentos foi controlado através de grupos do Active Directory.

Essa abordagem segue boas práticas corporativas, permitindo gerenciamento centralizado de permissões.

---

# Service Accounts

Para simular serviços corporativos foram criadas contas de serviço dedicadas.

## Contas criadas

```text
svc_web
svc_backup
svc_monitor
```

Essas contas representam aplicações e serviços executados dentro do domínio.

---

# Service Principal Names (SPN)

Foram registrados SPNs para simular serviços autenticados via Kerberos.

## SPNs configurados

| Conta      | SPN                        |
| ---------- | -------------------------- |
| svc_web    | HTTP/intranet.treino.local |
| svc_backup | BACKUP/backup.treino.local |

Os SPNs permitem que serviços sejam identificados pelo Kerberos durante processos de autenticação.

---

# Kerberos

O laboratório foi utilizado para estudar o funcionamento do Kerberos em um ambiente Active Directory.

Foram analisados:

* TGT (Ticket Granting Ticket)
* Service Tickets
* SPNs
* Cache de Tickets
* KDC

Validação realizada através do comando:

```powershell
klist
```

---

# Políticas de Segurança

## Account Lockout Policy

Foi configurada uma política de bloqueio de contas para reduzir riscos de ataques de força bruta.

O laboratório permitiu observar:

* Falhas de autenticação
* Bloqueio de contas
* Eventos gerados no Event Viewer

---

# Auditoria

A auditoria do Active Directory foi habilitada para monitoramento de alterações relevantes.

Eventos analisados:

| Event ID | Descrição             |
| -------- | --------------------- |
| 4624     | Logon bem-sucedido    |
| 4625     | Falha de autenticação |
| 4720     | Criação de usuário    |
| 4728     | Inclusão em grupo     |
| 4738     | Alteração de usuário  |
| 4740     | Bloqueio de conta     |

Esses eventos serão utilizados futuramente em um projeto de monitoramento e detecção de atividades suspeitas utilizando Python.

---

# BloodHound Community Edition

Após a coleta, os dados foram importados para o BloodHound CE para visualização gráfica dos relacionamentos existentes no domínio.

A ferramenta permitiu validar:

* Estrutura do domínio
* Relações usuário → grupo
* Service Accounts
* OUs
* GPOs
* Objetos do Active Directory

---

# Evidências

## Domain Overview

![Domain Overview](../screenshots/bloodhound-overview.png)

---

## User Membership Analysis

![User Group Relationship](../screenshots/bloodhound-user-group.png)

---

## Service Account Analysis

![Service Account Analysis](../screenshots/bloodhound-service-account.png)

---

# Conhecimentos Praticados

Durante o desenvolvimento deste laboratório foram praticados conceitos relacionados a:

* Active Directory
* DNS
* Kerberos
* Group Policy
* Service Accounts
* SPNs
* Compartilhamentos SMB
* Auditoria Windows
* BloodHound
* Enumeração de Diretório
* Controle de Acesso Baseado em Grupos
* Administração Windows Server

---

# Conclusão

Este laboratório foi desenvolvido com o objetivo de compreender o funcionamento interno de ambientes Active Directory e visualizar como seus componentes são interpretados por ferramentas utilizadas em avaliações de segurança.

A utilização do BloodHound permitiu validar a estrutura implementada e compreender como usuários, grupos, computadores e contas de serviço se relacionam dentro do domínio.

Além dos conceitos de administração, o projeto forneceu uma base sólida para estudos futuros relacionados a detecção de ameaças, monitoramento de eventos e segurança ofensiva em ambientes Windows.
