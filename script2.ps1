$SharesRoot = "C:\Partages"

# dossier -> groupe DL -> droit
$Map = @{
    "DossiersClients" = @{ "DL_DossiersClients_Modification" = "Modify";
                           "DL_DossiersClients_Lecture"      = "ReadAndExecute" }
    "Comptabilite"    = @{ "DL_Comptabilite_Modification"    = "Modify" }
    "Commun"          = @{ "DL_PartageCommun_Modification"   = "Modify" }
    "Modeles"         = @{ "DL_Modeles_Lecture"              = "ReadAndExecute" }
}

$Domain = $env:USERDOMAIN

foreach ($folder in $Map.Keys) {
    $path = Join-Path $SharesRoot $folder
    if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }

    $acl = Get-Acl $path
    foreach ($grp in $Map[$folder].Keys) {
        $right = $Map[$folder][$grp]
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$Domain\$grp", $right, "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Write-Host "  $folder : $grp = $right" -ForegroundColor Green
    }
    Set-Acl -Path $path -AclObject $acl
}

Write-Host "`nTermine. Dossiers crees dans $SharesRoot" -ForegroundColor Cyan