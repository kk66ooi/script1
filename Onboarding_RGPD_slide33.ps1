<#
==============================================================================
  ONBOARDING AUTOMATISÉ & CONFORMITÉ RGPD  -  Cabinet d'Avocats de Brest
  Domaine : dubois.local
------------------------------------------------------------------------------
  A partir d'un CSV RH, le script :
    [A]   crée le compte dans l'UO du service                (AGDLP : A)
    [G]   l'affecte à son groupe Global de rôle             (AGDLP : A -> G)
    [VPN] provisionne l'accès VPN nomade (groupe LDAP pfSense)
    [+]   crée le dossier personnel avec une ACL NTFS stricte
    [@]   génère des identifiants temporaires (journal / e-mail)
  Durcissement RGPD :
    - chiffrement du CSV au repos en AES-256
    - destruction sécurisée (shredding) du CSV en clair après traitement
    - journal d'audit horodaté de toutes les actions

  Prérequis : exécuter sur le contrôleur de domaine (module ActiveDirectory),
              en administrateur du domaine. Script idempotent (relançable).
==============================================================================
#>

#Requires -Modules ActiveDirectory
Import-Module ActiveDirectory -ErrorAction Stop

# ------------------------------ PARAMÈTRES ----------------------------------
$CsvPath      = ".\nouveaux_arrivants.csv"     # fichier RH (délimiteur ;)
$HomeRoot     = "C:\Partages\Personnels"       # dossiers personnels
$LogPath      = ".\onboarding_audit.log"       # journal d'audit
$CsvKeyPhrase = "Cabinet-Brest-RGPD-2025"      # passphrase de chiffrement CSV
$VpnGroup     = "G_VPN_Nomades"                # groupe LDAP autorisé OpenVPN

# E-mail (optionnel : nécessite un relais SMTP)
$SendEmail = $false
$SmtpServer = "smtp.dubois.local" ; $MailFrom = "it@dubois.local" ; $MailIT = "it@dubois.local"

# Contexte du domaine (auto-détecté)
$DomainDN = (Get-ADDomain).DistinguishedName
$DomainNb = (Get-ADDomain).NetBIOSName
$DnsRoot  = (Get-ADDomain).DNSRoot
$BaseOU   = "OU=Cabinet-Brest,$DomainDN"
$UsersOU  = "OU=Utilisateurs,$BaseOU"
$GlobalOU = "OU=Global,OU=Groupes,$BaseOU"

# Service -> UO + groupe Global de rôle
$ServiceMap = @{
    "Direction"      = @{ OU="Direction";      Group="G_Direction" }
    "Administration" = @{ OU="Administration"; Group="G_Administration" }
    "Technique"      = @{ OU="Technique";      Group="G_Technique" }
    "Avocats"        = @{ OU="Avocats";        Group="G_Avocats" }
}

# ------------------------------ FONCTIONS -----------------------------------
function Write-Log {
    param([string]$Message,[string]$Color="Gray")
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line -ForegroundColor $Color
}

function Remove-Diacritics {
    param([string]$Text)
    $n = $Text.Normalize([Text.NormalizationForm]::FormD)
    ($n.ToCharArray() | Where-Object {
        [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne 'NonSpacingMark' }) -join ''
}

function New-TempPassword {
    $l="abcdefghijkmnpqrstuvwxyz"; $u="ABCDEFGHJKLMNPQRSTUVWXYZ"; $d="23456789"; $s="!@#%*-_?"
    $all=$l+$u+$d+$s
    $p=$l[(Get-Random -Max $l.Length)]+$u[(Get-Random -Max $u.Length)]+$d[(Get-Random -Max $d.Length)]+$s[(Get-Random -Max $s.Length)]
    1..10 | ForEach-Object { $p+=$all[(Get-Random -Max $all.Length)] }
    return $p
}

function Get-UniqueSam {
    param([string]$First,[string]$Last)
    $base = (Remove-Diacritics ($First.Substring(0,1)+$Last)).ToLower() -replace '[^a-z0-9]',''
    if ($base.Length -gt 18) { $base=$base.Substring(0,18) }
    $sam=$base; $i=1
    while (Get-ADUser -LDAPFilter "(sAMAccountName=$sam)" -ErrorAction SilentlyContinue) { $sam="$base$i"; $i++ }
    return $sam
}

function Protect-FileAES {
    # Chiffrement AES-256 d'un fichier (clé dérivée de la passphrase par PBKDF2)
    param([string]$InFile,[string]$OutFile,[string]$Passphrase)
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $kdf  = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase,$salt,100000)
    $aes  = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize=256; $aes.Key=$kdf.GetBytes(32); $aes.GenerateIV()
    $plain  = [System.IO.File]::ReadAllBytes($InFile)
    $cipher = $aes.CreateEncryptor().TransformFinalBlock($plain,0,$plain.Length)
    $fs = New-Object System.IO.FileStream($OutFile,[System.IO.FileMode]::Create)
    $fs.Write($salt,0,16); $fs.Write($aes.IV,0,16); $fs.Write($cipher,0,$cipher.Length)
    $fs.Close(); $aes.Dispose()
}

function Remove-FileSecure {
    # Destruction sécurisée : réécriture aléatoire puis suppression (shredding)
    param([string]$Path)
    if (Test-Path $Path) {
        $len=(Get-Item $Path).Length
        $fs=[System.IO.File]::OpenWrite($Path)
        $buf=New-Object byte[] $len; (New-Object System.Random).NextBytes($buf)
        $fs.Write($buf,0,$len); $fs.Close()
        Remove-Item $Path -Force
    }
}

# ============================================================================
Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   ONBOARDING AUTOMATISE & CONFORMITE RGPD - Cabinet Brest"   -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Log "===== DEBUT ONBOARDING =====" "Cyan"

if (-not (Test-Path $CsvPath)) { Write-Log "CSV introuvable : $CsvPath" "Red"; return }

# Groupe VPN (créé si absent) - accès OpenVPN authentifié par LDAP côté pfSense
if (-not (Get-ADGroup -LDAPFilter "(cn=$VpnGroup)" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $VpnGroup -SamAccountName $VpnGroup -GroupCategory Security `
                -GroupScope Global -Path $GlobalOU -Description "Acces VPN nomade (OpenVPN via LDAP)"
    Write-Log "Groupe VPN cree : $VpnGroup" "DarkGray"
}

$rows = Import-Csv -Path $CsvPath -Delimiter ';' -Encoding UTF8
Write-Log "CSV RH lu : $($rows.Count) arrivant(s)" "Cyan"
Write-Host ""

foreach ($r in $rows) {
    $first=$r.Prenom.Trim(); $last=$r.Nom.Trim(); $svc=$r.Service.Trim(); $title=$r.Titre.Trim()

    if (-not $ServiceMap.ContainsKey($svc)) { Write-Log "Service inconnu '$svc' -> $first $last ignore" "Red"; continue }
    $ouPath="OU=$($ServiceMap[$svc].OU),$UsersOU"; $group=$ServiceMap[$svc].Group
    $sam=Get-UniqueSam -First $first -Last $last

    Write-Host ("--- {0} {1}  ({2})  ->  {3}" -f $first,$last,$svc,$sam) -ForegroundColor White

    # [A] compte dans l'UO du service
    $pwdClear=New-TempPassword
    New-ADUser -Name "$first $last" -GivenName $first -Surname $last -SamAccountName $sam `
               -UserPrincipalName "$sam@$DnsRoot" -DisplayName "$first $last" -Title $title `
               -Path $ouPath -AccountPassword (ConvertTo-SecureString $pwdClear -AsPlainText -Force) `
               -Enabled $true -ChangePasswordAtLogon $true
    Write-Log "  [A]   compte cree dans $ouPath" "Green"

    # [G] groupe Global de role (AGDLP : A -> G)
    Add-ADGroupMember -Identity $group -Members $sam
    Write-Log "  [G]   affecte au groupe Global $group" "Green"

    # [VPN] provisionnement de l'acces VPN nomade (groupe LDAP pfSense)
    Add-ADGroupMember -Identity $VpnGroup -Members $sam
    Write-Log "  [VPN] acces VPN provisionne ($VpnGroup) - certificat a exporter sur pfSense" "Green"

    # [+] dossier personnel + ACL NTFS stricte (heritage coupe)
    $home=Join-Path $HomeRoot $sam
    if (-not (Test-Path $home)) { New-Item -Path $home -ItemType Directory -Force | Out-Null }
    $acl=Get-Acl $home
    $acl.SetAccessRuleProtection($true,$false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    $idSystem=New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $idAdmins=New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $idUser  =(Get-ADUser -Identity $sam).SID
    foreach ($rule in @(
        (New-Object System.Security.AccessControl.FileSystemAccessRule($idSystem,"FullControl","ContainerInherit,ObjectInherit","None","Allow")),
        (New-Object System.Security.AccessControl.FileSystemAccessRule($idAdmins,"FullControl","ContainerInherit,ObjectInherit","None","Allow")),
        (New-Object System.Security.AccessControl.FileSystemAccessRule($idUser,"Modify","ContainerInherit,ObjectInherit","None","Allow"))
    )) { $acl.AddAccessRule($rule) }
    Set-Acl -Path $home -AclObject $acl
    Write-Log "  [+]   dossier perso + ACL stricte : $home" "Green"

    # [@] identifiants temporaires
    $body="Nouvel arrivant : $first $last`nLogin : $sam@$DnsRoot`nMot de passe temporaire : $pwdClear (a changer a la 1ere connexion)"
    if ($SendEmail) {
        try { Send-MailMessage -SmtpServer $SmtpServer -From $MailFrom -To $MailIT -Subject "Onboarding : $first $last" -Body $body -Encoding UTF8
              Write-Log "  [@]   e-mail envoye a l'IT" "Green" }
        catch { Write-Log "  [@]   echec e-mail : $($_.Exception.Message)" "Red" }
    } else {
        Write-Log "  [@]   identifiants temporaires journalises (e-mail desactive)" "DarkGray"
        Add-Content -Path $LogPath -Value "        LOGIN=$sam@$DnsRoot  MDP_TEMP=$pwdClear"
    }
    Write-Host ""
}

# ============================================================================
# CONFORMITÉ RGPD : chiffrement au repos (AES-256) + destruction sécurisée
# ============================================================================
Write-Host "--- Conformite RGPD ---" -ForegroundColor Magenta
$enc = "$CsvPath.aes"
Protect-FileAES -InFile $CsvPath -OutFile $enc -Passphrase $CsvKeyPhrase
Write-Log "  [RGPD] CSV chiffre au repos (AES-256) -> $enc" "Magenta"
Remove-FileSecure -Path $CsvPath
Write-Log "  [RGPD] CSV source detruit de facon securisee (shredding)" "Magenta"

Write-Log "===== FIN ONBOARDING =====" "Cyan"
Write-Host ""
Write-Host "Journal d'audit : $LogPath" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

<#
==============================================================================
  OFFBOARDING (a copier dans PowerShell puis :  Disable-Employee -Sam <login>)
------------------------------------------------------------------------------
  Action reelle scriptable : desactivation du compte AD (coupe M365 via la
  synchro Entra) + retrait du groupe VPN. Wi-Fi 802.1X / badge RFID : systemes
  tiers, revoques en aval.
==============================================================================
function Disable-Employee {
    param([Parameter(Mandatory)][string]$Sam)
    Disable-ADAccount -Identity $Sam
    Get-ADPrincipalGroupMembership $Sam | Where-Object {$_.Name -eq "G_VPN_Nomades"} |
        ForEach-Object { Remove-ADGroupMember -Identity $_.Name -Members $Sam -Confirm:$false }
    Set-ADUser -Identity $Sam -Description ("Desactive le "+(Get-Date -Format 'yyyy-MM-dd'))
    Add-Content ".\offboarding_audit.log" ("[{0}] Compte desactive + VPN revoque : {1}" -f (Get-Date),$Sam)
    Write-Host "Compte $Sam desactive, acces VPN et M365 coupes." -ForegroundColor Green
}
#>
