Clear-Host
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "        DEMONSTRATION DU MODELE AGDLP" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "`n[A -> G]  Comptes membres du groupe Global G_Avocats" -ForegroundColor Yellow
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
Get-ADGroupMember G_Avocats |
  ForEach-Object { "   {0,-22} ({1})" -f $_.Name, $_.objectClass } | Write-Host

Write-Host "`n[G -> DL] Membres du groupe Domaine Local DL_DossiersClients_Modification" -ForegroundColor Yellow
Write-Host "          (ce sont des GROUPES, pas des utilisateurs)" -ForegroundColor DarkGray
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
Get-ADGroupMember DL_DossiersClients_Modification |
  ForEach-Object { "   {0,-32} ({1})" -f $_.Name, $_.objectClass } | Write-Host

Write-Host "`n[A -> G]  Groupes d'appartenance de Marie Martin (mmartin)" -ForegroundColor Yellow
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
Get-ADPrincipalGroupMembership mmartin |
  ForEach-Object { "   $($_.Name)" } | Write-Host

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host " Chaine AGDLP : Marie Martin -> G_Avocats -> DL_DossiersClients_Modification -> Modify" -ForegroundColor Green
Write-Host "==================================================`n" -ForegroundColor Cyan