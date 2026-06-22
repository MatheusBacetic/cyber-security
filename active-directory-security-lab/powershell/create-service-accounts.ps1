$password = ConvertTo-SecureString "Senha@123" -AsPlainText -Force

$serviceAccounts = @(
    "svc_web",
    "svc_backup",
    "svc_monitor"
)

foreach ($svc in $serviceAccounts) {
    New-ADUser `
        -Name $svc `
        -SamAccountName $svc `
        -UserPrincipalName "$svc@treino.local" `
        -Path "OU=Service Accounts,OU=Corporativo,DC=treino,DC=local" `
        -AccountPassword $password `
        -Enabled $true `
        -PasswordNeverExpires $true
}

setspn -S HTTP/intranet.treino.local svc_web
setspn -S BACKUP/backup.treino.local svc_backup