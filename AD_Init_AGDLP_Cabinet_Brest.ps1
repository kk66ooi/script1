<#
==============================================================================
  Initialisation Active Directory - Modele AGDLP
  Cabinet d'Avocats de Brest  -  Domaine : brest.local
------------------------------------------------------------------------------
  Cree l'arborescence d'UO, les utilisateurs, les groupes Globaux (roles) et
  Domaine Local (ressources), realise l'imbrication AGDLP et (option) applique
  les permissions NTFS sur les partages.

  Regle d'or AGDLP :
     A  (Account)        -> l'utilisateur
     G  (Global group)   -> regroupe les comptes par ROLE / service
     DL (Domain Local)   -> regroupe les acces par RESSOURCE (niveau de droit)
     P  (Permission)     -> la permission NTFS est posee sur le groupe DL
  => On n'attribue JAMAIS un droit directement a un utilisateur.

  Prerequis : executer sur un DC (ou machine avec RSAT-AD-PowerShell),
              en tant qu'administrateur du domaine.
  Le script est idempotent : il peut etre relance sans casse.
==============================================================================
#>

#Requires -Modules ActiveDirectory

# ----------------------------- PARAMETRES -----------------------------------
$Domain        = "brest.local"
$DomainDN      = "DC=brest,DC=local"
$BaseOUName    = "Cabinet-Brest"                         # UO racine du projet
$BaseOU        = "OU=$BaseOUName,$DomainDN"
$UpnSuffix     = "brest.local"

# Mot de passe initial (change a la premiere connexion). A adapter en prod.
$DefaultPassword = ConvertTo-SecureString "Cabinet@2025!" -AsPlainText -Force

# Application des permissions NTFS (P). Passe a $true si tu executes le script
# sur le serveur de fichiers et que tu veux creer les partages + ACL.
$CreateShares  = $false
$SharesRoot    = "C:\Partages"                           # racine des dossiers

Import-Module ActiveDirectory -ErrorAction Stop

# ----------------------------- FONCTIONS ------------------------------------
function New-OUIfMissing {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$Name)" -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false
        Write-Host "  [OU]    cree : $dn" -ForegroundColor Green
    } else {
        Write-Host "  [OU]    existe deja : $dn" -ForegroundColor DarkGray
    }
    return $dn
}

function New-GroupIfMissing {
    param([string]$Name, [string]$Path, [ValidateSet("Global","DomainLocal")][string]$Scope, [string]$Description)
    if (-not (Get-ADGroup -LDAPFilter "(cn=$Name)" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $Name -SamAccountName $Name -GroupCategory Security `
                    -GroupScope $Scope -Path $Path -Description $Description
        Write-Host "  [GRP]   cree ($Scope) : $Name" -ForegroundColor Green
    } else {
        Write-Host "  [GRP]   existe deja : $Name" -ForegroundColor DarkGray
    }
}

function New-UserIfMissing {
    param([string]$First, [string]$Last, [string]$Sam, [string]$OUPath, [string]$Title, [string]$GlobalGroup)
    if (-not (Get-ADUser -LDAPFilter "(sAMAccountName=$Sam)" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "$First $Last" -GivenName $First -Surname $Last `
                   -SamAccountName $Sam -UserPrincipalName "$Sam@$UpnSuffix" `
                   -DisplayName "$First $Last" -Title $Title -Path $OUPath `
                   -AccountPassword $DefaultPassword -Enabled $true `
                   -ChangePasswordAtLogon $true
        Write-Host "  [USER]  cree : $Sam ($First $Last)" -ForegroundColor Green
    } else {
        Write-Host "  [USER]  existe deja : $Sam" -ForegroundColor DarkGray
    }
    # A -> G : le compte entre dans son groupe Global (role)
    Add-MemberSafe -Group $GlobalGroup -Member $Sam
}

function Add-MemberSafe {
    param([string]$Group, [string]$Member)
    $current = Get-ADGroupMember -Identity $Group -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
    if ($current -notcontains $Member) {
        Add-ADGroupMember -Identity $Group -Members $Member
        Write-Host "    -> $Member ajoute a $Group" -ForegroundColor Cyan
    }
}

# ============================================================================
# 1) ARBORESCENCE D'UNITES D'ORGANISATION
# ============================================================================
Write-Host "`n=== 1. Unites d'organisation ===" -ForegroundColor Yellow

# UO racine
if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$BaseOUName)" -SearchBase $DomainDN -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $BaseOUName -Path $DomainDN -ProtectedFromAccidentalDeletion $false
    Write-Host "  [OU]    cree : $BaseOU" -ForegroundColor Green
}

$OU_Users   = New-OUIfMissing -Name "Utilisateurs"    -Path $BaseOU
$OU_Groups  = New-OUIfMissing -Name "Groupes"         -Path $BaseOU
$OU_Comp    = New-OUIfMissing -Name "Ordinateurs"     -Path $BaseOU
$OU_Svc     = New-OUIfMissing -Name "ComptesDeService" -Path $BaseOU

# Sous-UO par service (structure metier)
$Services = "Direction","Administration","Technique","Avocats"
$OU_Service = @{}
foreach ($s in $Services) { $OU_Service[$s] = New-OUIfMissing -Name $s -Path $OU_Users }

# UO dediees aux groupes (bonne pratique : separer G et DL)
$OU_Global = New-OUIfMissing -Name "Global"      -Path $OU_Groups
$OU_DL     = New-OUIfMissing -Name "DomainLocal" -Path $OU_Groups

# ============================================================================
# 2) GROUPES GLOBAUX (G) : par ROLE / service
# ============================================================================
Write-Host "`n=== 2. Groupes Globaux (roles) ===" -ForegroundColor Yellow
New-GroupIfMissing -Name "G_Direction"      -Path $OU_Global -Scope Global -Description "Role : Direction"
New-GroupIfMissing -Name "G_Administration" -Path $OU_Global -Scope Global -Description "Role : Administration / Secretariat"
New-GroupIfMissing -Name "G_Technique"      -Path $OU_Global -Scope Global -Description "Role : Service informatique"
New-GroupIfMissing -Name "G_Avocats"        -Path $OU_Global -Scope Global -Description "Role : Avocats"

# ============================================================================
# 3) GROUPES DOMAINE LOCAL (DL) : par RESSOURCE + niveau d'acces
# ============================================================================
Write-Host "`n=== 3. Groupes Domaine Local (ressources) ===" -ForegroundColor Yellow
New-GroupIfMissing -Name "DL_DossiersClients_Modification" -Path $OU_DL -Scope DomainLocal -Description "Dossiers clients - Modification"
New-GroupIfMissing -Name "DL_DossiersClients_Lecture"      -Path $OU_DL -Scope DomainLocal -Description "Dossiers clients - Lecture seule"
New-GroupIfMissing -Name "DL_Comptabilite_Modification"    -Path $OU_DL -Scope DomainLocal -Description "Comptabilite - Modification"
New-GroupIfMissing -Name "DL_PartageCommun_Modification"   -Path $OU_DL -Scope DomainLocal -Description "Partage commun - Modification"
New-GroupIfMissing -Name "DL_Modeles_Lecture"              -Path $OU_DL -Scope DomainLocal -Description "Modeles / trames - Lecture seule"

# ============================================================================
# 4) IMBRICATION G -> DL  (le coeur de l'AGDLP)
# ============================================================================
Write-Host "`n=== 4. Imbrication AGDLP (G dans DL) ===" -ForegroundColor Yellow

# Avocats : modif dossiers clients + commun, lecture des modeles
Add-MemberSafe -Group "DL_DossiersClients_Modification" -Member "G_Avocats"
Add-MemberSafe -Group "DL_PartageCommun_Modification"   -Member "G_Avocats"
Add-MemberSafe -Group "DL_Modeles_Lecture"              -Member "G_Avocats"

# Direction : dossiers clients + compta + commun (modif)
Add-MemberSafe -Group "DL_DossiersClients_Modification" -Member "G_Direction"
Add-MemberSafe -Group "DL_Comptabilite_Modification"    -Member "G_Direction"
Add-MemberSafe -Group "DL_PartageCommun_Modification"   -Member "G_Direction"

# Administration : lecture dossiers clients, modif compta + commun
Add-MemberSafe -Group "DL_DossiersClients_Lecture"      -Member "G_Administration"
Add-MemberSafe -Group "DL_Comptabilite_Modification"    -Member "G_Administration"
Add-MemberSafe -Group "DL_PartageCommun_Modification"   -Member "G_Administration"

# Technique : acces au partage commun (l'admin serveurs passe par le Bastion)
Add-MemberSafe -Group "DL_PartageCommun_Modification"   -Member "G_Technique"

# ============================================================================
# 5) COMPTES UTILISATEURS (A) -> ajoutes a leur groupe Global
# ============================================================================
Write-Host "`n=== 5. Utilisateurs ===" -ForegroundColor Yellow
#            Prenom   Nom        Sam        UO service                   Titre                 Groupe Global
New-UserIfMissing "Jean"   "Dupont"  "jdupont" $OU_Service["Direction"]      "Associe gerant"      "G_Direction"
New-UserIfMissing "Marie"  "Martin"  "mmartin" $OU_Service["Avocats"]        "Avocate"             "G_Avocats"
New-UserIfMissing "Paul"   "Bernard" "pbernard" $OU_Service["Avocats"]       "Avocat"              "G_Avocats"
New-UserIfMissing "Claire" "Robin"   "crobin"  $OU_Service["Avocats"]        "Avocate collaboratrice" "G_Avocats"
New-UserIfMissing "Sophie" "Petit"   "spetit"  $OU_Service["Administration"] "Secretaire juridique" "G_Administration"
New-UserIfMissing "Anne"   "Leroy"   "aleroy"  $OU_Service["Administration"] "Assistante"          "G_Administration"
New-UserIfMissing "Luc"    "Moreau"  "lmoreau" $OU_Service["Technique"]      "Administrateur IT"   "G_Technique"

# ============================================================================
# 6) PERMISSIONS NTFS (P) sur les groupes DL  [optionnel]
# ============================================================================
if ($CreateShares) {
    Write-Host "`n=== 6. Permissions NTFS (P) ===" -ForegroundColor Yellow

    # dossier -> @{ Groupe DL = Droit NTFS }
    $Shares = @{
        "DossiersClients" = @{ "DL_DossiersClients_Modification" = "Modify";
                               "DL_DossiersClients_Lecture"      = "ReadAndExecute" }
        "Comptabilite"    = @{ "DL_Comptabilite_Modification"    = "Modify" }
        "Commun"          = @{ "DL_PartageCommun_Modification"   = "Modify" }
        "Modeles"         = @{ "DL_Modeles_Lecture"              = "ReadAndExecute" }
    }

    foreach ($folder in $Shares.Keys) {
        $path = Join-Path $SharesRoot $folder
        if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }

        $acl = Get-Acl $path
        # (Optionnel) desactiver l'heritage pour un controle strict :
        # $acl.SetAccessRuleProtection($true, $false)

        foreach ($grp in $Shares[$folder].Keys) {
            $right = $Shares[$folder][$grp]
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$Domain\$grp", $right,
                "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($rule)
            Write-Host "  [ACL]   $folder : $grp = $right" -ForegroundColor Green
        }
        Set-Acl -Path $path -AclObject $acl
    }
} else {
    Write-Host "`n=== 6. Permissions NTFS : ignore (CreateShares = false) ===" -ForegroundColor DarkGray
    Write-Host "     Sur le serveur de fichiers : passe \$CreateShares a \$true." -ForegroundColor DarkGray
}

# ============================================================================
# RECAPITULATIF
# ============================================================================
Write-Host "`n============================================================" -ForegroundColor Yellow
Write-Host " Initialisation AGDLP terminee." -ForegroundColor Yellow
Write-Host " Verification rapide de la chaine (exemple avocats) :" -ForegroundColor Yellow
Write-Host "   A  mmartin / pbernard / crobin" -ForegroundColor White
Write-Host "   G  G_Avocats" -ForegroundColor White
Write-Host "   DL DL_DossiersClients_Modification" -ForegroundColor White
Write-Host "   P  Modify sur \\SRV-FICHIERS\DossiersClients" -ForegroundColor White
Write-Host "============================================================`n" -ForegroundColor Yellow

# Aide au controle :
#   Get-ADGroupMember G_Avocats
#   Get-ADGroupMember DL_DossiersClients_Modification
#   Get-ADPrincipalGroupMembership mmartin | Select Name
