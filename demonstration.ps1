Write-Host "`n===== DEMONSTRATION DU MODELE AGDLP =====" -ForegroundColor Cyan

Write-Host "`n[A] Comptes utilisateurs (avocats) membres de [G] G_Avocats :" -ForegroundColor Yellow
Get-ADGroupMember G_Avocats | Select-Object Name, objectClass | Format-Table -AutoSize

Write-Host "[G -> DL] Membres de DL_DossiersClients_Modification (des GROUPES, pas des users) :" -ForegroundColor Yellow
Get-ADGroupMember DL_DossiersClients_Modification | Select-Object Name, objectClass | Format-Table -AutoSize

Write-Host "[A -> G] Groupes d'appartenance de Marie Martin :" -ForegroundColor Yellow
Get-ADPrincipalGroupMembership mmartin | Select-Object Name | Format-Table -AutoSize

Write-Host "===== FIN DE LA DEMONSTRATION AGDLP =====`n" -ForegroundColor Cyan