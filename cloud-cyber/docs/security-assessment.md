# Cloud Security Assessment

## 1. Arquitetura do Ambiente

O ambiente foi desenvolvido em uma conta AWS Academy/Vocareum com o objetivo de implementar controles de segurança, monitoramento, auditoria e governança sobre uma instância EC2 Ubuntu executando Nginx.

Os principais fluxos são:

- Internet → Security Group → EC2 Ubuntu → Nginx.
- EC2 Metrics → CloudWatch Alarm → SNS → E-mail.
- AWS API Activity → CloudTrail → S3.
- AWS Resources → AWS Config → Compliance Rules.
- GuardDuty → Security Hub.

O diagrama completo está disponível em `../architecture/architecture-diagram.png`.

## 2. Findings

| ID | Finding | Fonte | Severidade | Status |
|---|---|---|---|---|
| F-001 | Instância EC2 com IPv4 público | Security Hub | High | Risk Accepted |
| F-002 | Compartilhamento público de documentos SSM não bloqueado | Security Hub | Critical | Risk Accepted |
| F-003 | Volume EBS sem conformidade de criptografia | AWS Config | N/A | Non-compliant |
| F-004 | Portas autorizadas do Security Group fora da regra esperada | AWS Config | N/A | Non-compliant |

Os findings F-001 e F-002 possuem análises detalhadas nos Incident Reports `IR-004` e `IR-003`, respectivamente.

## 3. Controles Implementados

| Categoria | Controle | Status |
|---|---|---|
| Preventivo | Security Groups | Implementado |
| Preventivo | Hardening do Ubuntu e SSH | Implementado |
| Detectivo | CloudWatch Metrics e Alarms | Implementado |
| Detectivo | GuardDuty | Implementado |
| Detectivo | Security Hub | Implementado |
| Auditoria | CloudTrail com logs no S3 | Implementado |
| Compliance | AWS Config Rules | Implementado |
| Resposta | SNS Email Alerts | Implementado |
| Resposta | Incident Reports | Implementado |
| Governança | Registro e aceitação de riscos | Implementado |

O ambiente possui controles preventivos e detectivos adequados ao escopo educacional. Os itens non-compliant permanecem registrados para demonstrar o processo de identificação, avaliação e tratamento de riscos.

## 4. Limitações do Ambiente

| Serviço ou ação | Restrição | Impacto |
|---|---|---|
| IAM | `iam:CreateRole` negado | Impediu a role necessária para algumas integrações |
| Amazon Inspector | `inspector2:BatchGetAccountStatus` negado | Impediu a ativação e a varredura de vulnerabilidades |
| EventBridge | Dependência de criação de role | Impediu a integração GuardDuty → EventBridge → SNS |
| Amazon Athena | `datazone:ListDomains` negado | Impediu consultas SQL e threat hunting sobre logs |

As limitações foram documentadas como evidências do ambiente, sem serem tratadas como falhas de implementação. Sempre que possível, foram utilizados controles compensatórios e análises manuais.

## Conclusão

O laboratório permitiu validar controles de rede, hardening, monitoramento, compliance, auditoria, detecção de ameaças, resposta a incidentes e gestão de riscos. O estado geral é parcialmente conforme, com riscos residuais conhecidos e formalmente documentados.
