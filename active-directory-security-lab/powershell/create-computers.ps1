$computadores = @(
    @{ Nome="JUR-PC-01"; OU="Workstations" },
    @{ Nome="FIN-PC-01"; OU="Workstations" },
    @{ Nome="RH-PC-01"; OU="Workstations" },
    @{ Nome="TI-PC-01"; OU="Workstations" },
    @{ Nome="FILE-SRV-01"; OU="Servidores" }
)

foreach ($pc in $computadores) {
    New-ADComputer `
        -Name $pc.Nome `
        -Path "OU=$($pc.OU),OU=Computadores,OU=Corporativo,DC=treino,DC=local"
}