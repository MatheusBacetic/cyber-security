# AD Security Monitor

Monitor Blue Team para Active Directory baseado no Windows Security Event Log. O projeto acompanha eventos em tempo real, correlaciona sessões pelo `Logon ID` e IP de origem, calcula risco por usuário e grava incidentes em arquivo.

## Requisitos

- Windows Server com Active Directory Domain Services;
- Python 3;
- PowerShell executado como administrador;
- módulo Active Directory do PowerShell;
- políticas de auditoria avançada habilitadas;
- pacotes Python `pywin32` e `colorama`.

Instalação das dependências:

```powershell
python -m pip install pywin32 colorama
```

## Execução

Abra o PowerShell como administrador:

```powershell
cd C:\AD-Monitor
python .\monitor.py
```

O monitor utiliza dois mecanismos simultâneos:

1. callback da API moderna do Windows Event Log;
2. polling incremental por `EventRecordID` a cada segundo.

O polling funciona como fallback quando o `EvtSubscribe` do `pywin32` não entrega eventos ao vivo. Eventos já existentes não são processados por padrão.

## Eventos monitorados

| Event ID | Uso no monitor |
|---:|---|
| 4624 | Sessão de rede e correlação entre `TargetLogonId` e IP |
| 4625 | Falha de autenticação e aumento do Risk Score |
| 4662 | Acesso a objetos do AD e possível enumeração LDAP |
| 4720 | Criação de usuário |
| 4728 | Inclusão em grupo privilegiado |
| 4738 | Alteração de usuário |
| 4740 | Bloqueio de conta e possível password spraying |
| 4768 | Solicitação de TGT Kerberos |
| 4769 | Solicitação de TGS e possível Kerberoasting |
| 4798/4799 | Enumeração de grupos locais |
| 5140/5145 | Acesso a compartilhamentos de rede |

Eventos usados apenas como telemetria podem permanecer silenciosos. O monitor apresenta o alerta quando a correlação indicar comportamento suspeito, reduzindo ruído no console.

## Risk Score Engine

O score é calculado por usuário em uma janela móvel de cinco minutos:

| Evento | Pontos |
|---:|---:|
| 4625 | +10 |
| 4740 | +25 |
| 4738 | +30 |
| 4662 | +15 |
| 4728 | +100 |

Ao atingir 100 pontos:

```text
========== INCIDENT ==========
Usuário: matheus.ti
Risk Score: 145
Status: CRITICAL
==============================
```

Contas terminadas em `$` e contas internas como `SYSTEM`, `LOCAL SERVICE` e `NETWORK SERVICE` são ignoradas pelo score.

## Detecções comportamentais

### Atividade suspeita no Active Directory

O monitor correlaciona LDAP, Kerberos, enumeração de grupos e SMB por conta e IP em uma janela de 120 segundos. O alerta é gerado quando há alto volume de acessos LDAP ou combinação de pelo menos três tipos de sinal.

O Windows não informa com certeza qual ferramenta originou a atividade. Por isso, o alerta descreve o comportamento observado sem atribuí-lo a um software específico.

### Kerberoasting

Uma conta que solicitar cinco TGS em até 60 segundos gera alerta crítico. São exibidos conta, serviços solicitados, endereço do cliente e tipo de criptografia. Contas de máquina e endereços do próprio DC são ignorados.

As contas de serviço monitoradas com regra adicional são:

- `svc_web`;
- `svc_backup`;
- `svc_monitor`.

### Outras detecções

- rajada de falhas de autenticação;
- criação e alteração de usuários;
- alteração em massa de contas;
- inclusão em grupos privilegiados;
- onda de bloqueios;
- acesso e enumeração de objetos do diretório;
- atividade Kerberos anormal;
- acessos SMB e SYSVOL suspeitos.

## Correlação por IP

O evento `4662` é gerado no Domain Controller e não contém diretamente o IP remoto. A correlação utiliza:

```text
4624.TargetLogonId + 4624.IpAddress
                    ↓
4662.SubjectLogonId
                    ↓
Conta e IP de origem
```

O monitor precisa observar o `4624` da sessão para conseguir atribuir eventos posteriores ao IP correto.

## Configuração da auditoria

Execute como administrador:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\enable-monitor-auditing.ps1
```

O script habilita auditoria de logon, gerenciamento de contas e grupos, Directory Service, Kerberos e compartilhamentos.

Observações:

- o evento `4662` também exige uma SACL de auditoria nos objetos do AD;
- `5140/5145` são registrados no computador que hospeda o compartilhamento;
- `4798/4799` podem ser registrados nos endpoints consultados;
- uma GPO de domínio pode sobrescrever configurações locais.

## Geração de eventos de teste

Use apenas em laboratório:

```powershell
.\generate-test-alerts.ps1 -Test All
```

Testes que concedem privilégio ou provocam bloqueio exigem confirmação explícita por parâmetro:

```powershell
.\generate-test-alerts.ps1 -Test AccountChanges `
  -IncludePrivilegeTest `
  -IncludeLockoutTest
```

O script cria uma conta temporária para os testes de alteração e tenta removê-la ao final.

## Variáveis de ambiente

### DEBUG

```powershell
$env:AD_MONITOR_DEBUG = "1"
python .\monitor.py
```

Exibe parsing, sessões, correlações e atualização de scores.

### Backfill

```powershell
$env:AD_MONITOR_BACKFILL_EVENTS = "100"
python .\monitor.py
```

O padrão é `0`, processando somente eventos novos.

### Endereços do Domain Controller

```powershell
$env:AD_MONITOR_DC_ADDRESSES = "10.0.0.10,192.168.1.10"
```

Esses IPs são ignorados nas detecções que procuram uma origem externa.

## Logs

Alertas e incidentes são gravados em:

```text
logs\alerts.log
```

O diretório é criado automaticamente.

## Auto Response e quarentena

O código possui resposta automática e quarentena para determinadas alterações privilegiadas. Por padrão:

```python
AUTO_RESPONSE_ENABLED = True
DRY_RUN = True
```

Com `DRY_RUN = True`, nenhuma conta é desabilitada. Antes de desativar o modo de simulação, revise obrigatoriamente:

- `PROTECTED_ACCOUNTS`;
- grupos privilegiados;
- caminho da OU de quarentena;
- permissões da conta que executa o monitor.

O caminho de quarentena deve existir no domínio configurado. Não habilite ações automáticas em produção sem teste e processo de recuperação.

## Limitações

- o monitor local enxerga diretamente apenas o Security Log da máquina em que está executando;
- eventos de endpoints exigem execução local, Windows Event Forwarding ou SIEM centralizado;
- eventos de auditoria dependem de GPO, subcategoria e SACL corretamente configuradas;
- correlação comportamental indica risco, não prova qual ferramenta foi utilizada;
- thresholds devem ser ajustados à linha de base do ambiente.
