$password = ConvertTo-SecureString "Senha@123" -AsPlainText -Force

$usuarios = @(
    @{ Nome="Ana Lima"; Login="ana.lima"; OU="Juridico" },
    @{ Nome="Bruno Costa"; Login="bruno.costa"; OU="Juridico" },
    @{ Nome="Carla Mendes"; Login="carla.mendes"; OU="Juridico" },
    @{ Nome="Marcos Financeiro"; Login="marcos.financeiro"; OU="Financeiro" },
    @{ Nome="Juliana Contas"; Login="juliana.contas"; OU="Financeiro" },
    @{ Nome="Patricia RH"; Login="patricia.rh"; OU="RH" },
    @{ Nome="Matheus TI"; Login="matheus.ti"; OU="TI" },
    @{ Nome="Admin TI"; Login="admin.ti"; OU="TI" }
)

foreach ($u in $usuarios) {
    New-ADUser `
        -Name $u.Nome `
        -SamAccountName $u.Login `
        -UserPrincipalName "$($u.Login)@treino.local" `
        -Path "OU=$($u.OU),OU=Usuarios,OU=Corporativo,DC=treino,DC=local" `
        -AccountPassword $password `
        -Enabled $true
}