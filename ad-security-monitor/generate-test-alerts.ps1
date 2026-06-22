#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet('All', 'FailedLogon', 'Kerberoasting', 'BloodHound', 'AccountChanges')]
    [string]$Test = 'All',

    [string]$DomainController,

    [switch]$IncludePrivilegeTest,

    [switch]$IncludeLockoutTest
)

$ErrorActionPreference = 'Stop'

function Write-TestStep([string]$Message) {
    Write-Host "`n[TEST] $Message" -ForegroundColor Cyan
}

function Test-Selected([string]$Name) {
    return $Test -eq 'All' -or $Test -eq $Name
}

Import-Module ActiveDirectory
$domain = Get-ADDomain
if (-not $DomainController) {
    $DomainController = (Get-ADDomainController -Discover -DomainName $domain.DNSRoot).HostName
}

$domainDn = $domain.DistinguishedName
$dnsDomain = $domain.DNSRoot
$runId = Get-Date -Format 'MMddHHmmss'
$testUser = "soc.test.$runId"
$testPasswordText = 'Monitor-Test-2026!'
$testPassword = ConvertTo-SecureString $testPasswordText -AsPlainText -Force
$createdUser = $false

Write-Host '=== AD Security Monitor - Gerador de Eventos ===' -ForegroundColor Yellow
Write-Host "DC: $DomainController"
Write-Host "Dominio: $dnsDomain"
Write-Host "Teste: $Test"
Write-Warning 'Use somente em laboratorio. O script gera eventos reais no Security Log.'

try {
    if (Test-Selected 'FailedLogon') {
        Write-TestStep 'Gerando cinco falhas de autenticacao para o evento 4625'
        1..5 | ForEach-Object {
            try {
                $entry = [System.DirectoryServices.DirectoryEntry]::new(
                    "LDAP://$DomainController/$domainDn",
                    "$dnsDomain\usuario.inexistente",
                    "SenhaIncorreta-$_"
                )
                $null = $entry.NativeObject
            }
            catch {
                Write-Host "  Falha $_/5 gerada"
            }
        }
    }

    if (Test-Selected 'Kerberoasting') {
        Write-TestStep 'Solicitando TGS para gerar eventos 4769 e testar Kerberoasting'
        $spns = Get-ADComputer -Filter * -Properties ServicePrincipalName |
            ForEach-Object { $_.ServicePrincipalName } |
            Where-Object { $_ -and $_ -notlike 'krbtgt/*' } |
            Select-Object -Unique -First 6

        if (@($spns).Count -lt 5) {
            Write-Warning 'Foram encontrados menos de cinco SPNs. O threshold pode nao ser atingido.'
        }
        foreach ($spn in $spns) {
            Write-Host "  TGS: $spn"
            & klist.exe get $spn | Out-Null
        }
    }

    if (Test-Selected 'BloodHound') {
        Write-TestStep 'Gerando sinais LDAP, Kerberos e SMB semelhantes a uma enumeracao'
        Write-Warning 'Execute este teste em uma estacao do dominio, nao no proprio DC, para registrar o IP remoto.'

        & klist.exe get "ldap/$DomainController" | Out-Null
        & klist.exe get "cifs/$DomainController" | Out-Null

        $root = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DomainController/$domainDn")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
        $searcher.PageSize = 500
        foreach ($filter in @(
            '(objectCategory=person)',
            '(objectCategory=group)',
            '(objectCategory=computer)',
            '(objectClass=groupPolicyContainer)',
            '(objectClass=organizationalUnit)'
        )) {
            $searcher.Filter = $filter
            1..3 | ForEach-Object {
                $results = $searcher.FindAll()
                Write-Host "  LDAP $filter -> $($results.Count) objetos"
                $results.Dispose()
            }
        }

        Get-ChildItem "\\$DomainController\SYSVOL" -ErrorAction SilentlyContinue | Out-Null
        Get-ChildItem "\\$DomainController\NETLOGON" -ErrorAction SilentlyContinue | Out-Null
    }

    if (Test-Selected 'AccountChanges') {
        Write-TestStep "Criando usuario temporario $testUser para eventos 4720 e 4738"
        New-ADUser `
            -Name $testUser `
            -SamAccountName $testUser `
            -UserPrincipalName "$testUser@$dnsDomain" `
            -AccountPassword $testPassword `
            -Enabled $true `
            -Description 'Conta temporaria do AD Security Monitor'
        $createdUser = $true

        1..3 | ForEach-Object {
            Set-ADUser -Identity $testUser -Description "Alteracao de teste $_ - $runId"
        }

        if ($IncludePrivilegeTest) {
            $group = Get-ADGroup -Identity 'Domain Admins'
            Write-Warning "Adicionando temporariamente $testUser a $($group.Name) para gerar 4728"
            Add-ADGroupMember -Identity $group -Members $testUser
            Start-Sleep -Seconds 2
            Remove-ADGroupMember -Identity $group -Members $testUser -Confirm:$false
        }

        if ($IncludeLockoutTest) {
            Write-Warning "Provocando tentativas invalidas contra a conta temporaria $testUser"
            1..20 | ForEach-Object {
                try {
                    $entry = [System.DirectoryServices.DirectoryEntry]::new(
                        "LDAP://$DomainController/$domainDn",
                        "$dnsDomain\$testUser",
                        "SenhaErrada-$_"
                    )
                    $null = $entry.NativeObject
                }
                catch {}
            }
        }
    }
}
finally {
    if ($createdUser) {
        Write-TestStep "Removendo conta temporaria $testUser"
        Remove-ADUser -Identity $testUser -Confirm:$false -ErrorAction SilentlyContinue
    }
}

Write-Host "`nTestes concluidos. Verifique o monitor e logs\alerts.log." -ForegroundColor Green
