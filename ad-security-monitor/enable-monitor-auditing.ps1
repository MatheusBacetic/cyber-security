#requires -RunAsAdministrator

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Enable-AuditSubcategory {
    param(
        [Parameter(Mandatory)]
        [string[]]$Names,

        [ValidateSet('enable', 'disable')]
        [string]$Success = 'enable',

        [ValidateSet('enable', 'disable')]
        [string]$Failure = 'enable'
    )

    foreach ($name in $Names) {
        & auditpol.exe /set "/subcategory:$name" "/success:$Success" "/failure:$Failure" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] $name" -ForegroundColor Green
            return $name
        }
    }

    Write-Warning "Subcategoria nao encontrada neste idioma: $($Names -join ' / ')"
    return $null
}

Write-Host '=== AD Security Monitor - Audit Policy Setup ===' -ForegroundColor Cyan

# Faz a Advanced Audit Policy prevalecer sobre a politica de auditoria legada.
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
New-ItemProperty `
    -Path $lsaPath `
    -Name 'SCENoApplyLegacyAuditPolicy' `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null
Write-Host '[OK] Advanced Audit Policy habilitada como politica efetiva' -ForegroundColor Green

$configured = @()

# 4624 e 4625
$configured += Enable-AuditSubcategory -Names @('Logon', 'Logon de Conta')

# 4720, 4738, 4740, 4798 e 4799
$configured += Enable-AuditSubcategory -Names @(
    'User Account Management',
    'Gerenciamento de Conta de Usuario'
)

# 4728 e outras mudancas em grupos de seguranca
$configured += Enable-AuditSubcategory -Names @(
    'Security Group Management',
    'Gerenciamento de Grupo de Seguranca'
)

# 4662. Este evento tambem depende de SACL nos objetos do Active Directory.
$configured += Enable-AuditSubcategory -Names @(
    'Directory Service Access',
    'Acesso ao Servico de Diretorio'
)

# 4768
$configured += Enable-AuditSubcategory -Names @(
    'Kerberos Authentication Service',
    'Servico de Autenticacao Kerberos'
)

# 4769
$configured += Enable-AuditSubcategory -Names @(
    'Kerberos Service Ticket Operations',
    'Operacoes de Tíquete de Servico Kerberos',
    'Operacoes de Ticket de Servico Kerberos'
)

# 5140
$configured += Enable-AuditSubcategory -Names @(
    'File Share',
    'Compartilhamento de Arquivos'
)

# 5145
$configured += Enable-AuditSubcategory -Names @(
    'Detailed File Share',
    'Compartilhamento de Arquivos Detalhado'
)

Write-Host "`n=== Configuracao efetiva ===" -ForegroundColor Cyan
foreach ($subcategory in ($configured | Where-Object { $_ } | Select-Object -Unique)) {
    & auditpol.exe /get "/subcategory:$subcategory"
}

Write-Host "`n=== Observacoes ===" -ForegroundColor Yellow
Write-Host '1. O evento 4662 exige uma SACL de auditoria nos objetos do AD.'
Write-Host '2. Os eventos 5140/5145 sao gravados no computador que hospeda o compartilhamento.'
Write-Host '3. Para 4798/4799 em endpoints, execute este script nesses computadores ou distribua por GPO.'
Write-Host '4. Uma GPO de dominio pode sobrescrever estas configuracoes locais.'
Write-Host "`nConcluido. Reinicie o monitor.py e gere novos eventos." -ForegroundColor Green
