$groups = @(
    "GG_Juridico_Users",
    "GG_Financeiro_Users",
    "GG_RH_Users",
    "GG_TI_Users",
    "GG_TI_Admins",
    "GG_Backup_Operators"
)

foreach ($group in $groups) {
    New-ADGroup `
        -Name $group `
        -GroupScope Global `
        -GroupCategory Security `
        -Path "OU=Grupos,OU=Corporativo,DC=treino,DC=local"
}