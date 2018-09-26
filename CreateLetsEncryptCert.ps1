#Requires -Modules ACMESharp, AzureRm

param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [String]$Fqdn,

    [Parameter(Mandatory = $true)]
    [String]$ContactEmail,

    [Parameter(Mandatory = $false)]
    [String]$WebAppName,

    [Parameter(Mandatory = $false)]
    [String]$VaultName,

    [Parameter(Mandatory = $true)]
    [SecureString]$CertificatePassword,

    [Parameter(Mandatory = $true)]
    [guid]$SubscriptionId
)

. .\WebAppFiles.ps1
Import-Module ACMESharp

Set-AzureRmContext -Subscription $SubscriptionId

#Create a VaultName if not supplied
if ([String]::IsNullOrEmpty($VaultName))
{
    $VaultName = $WebAppName
}
    $vaultRootPath = "$pwd\CertificateVault\" + $vaultName
    $vaultPath = Join-Path -Path $vaultRootPath -ChildPath $vaultName
    $vaultParam = @{RootPath = $vaultPath.ToLower(); CreatePath = $true; BypassEFS = $true }
    Set-ACMEVaultProfile -ProfileName $VaultName -Provider local -VaultParameters $vaultParam -Force
    Initialize-ACMEVault -VaultProfile $VaultName -Force
    $vault = Get-ACMEVault -VaultProfile $VaultName


#Create new registration
New-ACMERegistration -VaultProfile $VaultName -Contacts mailto:$ContactEmail -AcceptTos

$alias = $Fqdn.replace('.','-')
$alias = $alias + $(Get-Random).ToString()

#Identifier for DNS
New-ACMEIdentifier -VaultProfile $VaultName -Dns $Fqdn -Alias $alias

#Start http challenge
Complete-ACMEChallenge -VaultProfile $VaultName -IdentifierRef $alias -Force -ChallengeType http-01 -Handler manual -Regenerate -RepeatHandler
$challenge = $(Update-ACMEIdentifier $alias -VaultProfile $VaultName -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}

#Figure out what the challenge file and content should be
$challengeFile = $($challenge.HandlerHandleMessage -match "File Path:[^\[]+\[([^\]]+)\]" | Out-Null; $Matches[1])
$fileComp = $challengeFile.Split("/")
$challengeContent = $($challenge.HandlerHandleMessage -match "File Content:[^\[]+\[([^\]]+)\]" | Out-Null; $Matches[1])
$challengeContent | Out-File -Encoding ASCII -NoNewline -FilePath ".\ACMEChallengeFile.txt"

#Create the folder for the challenge file
Create-WebAppDirectory -WebAppName $WebAppName -ResourceGroupName $ResourceGroupName -Directory $fileComp[0]
$folder = $fileComp[0] + "/" + $fileComp[1]
Create-WebAppDirectory -WebAppName $WebAppName -ResourceGroupName $ResourceGroupName -Directory $folder

#Upload challenge file and web.config
$cred = Copy-FileToWebApp -WebAppName $WebAppName -ResourceGroupName $ResourceGroupName -Destination $challengeFile -File ".\ACMEChallengeFile.txt"
$fileloc = $fileComp[0] + "/" + $fileComp[1] + "/web.config"
$cred = Copy-FileToWebApp -WebAppName $WebAppName -ResourceGroupName $ResourceGroupName -Destination $fileloc -File .\web.config -PublishingCredentials $cred

$challenge = $(Update-ACMEIdentifier $alias -VaultProfile $VaultName -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}

#Submit challenge responde
if ($challenge.Status -ne 'valid') {
    Submit-ACMEChallenge -VaultProfile $VaultName -IdentifierRef $alias -ChallengeType http-01
}

#Check until valid
$challenge = $(Update-ACMEIdentifier $alias -VaultProfile $VaultName -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}
$try = 0
while (($challenge.Status -eq 'pending') -and ($try -lt 10)) {
    Write-Host "Sleeping while waiting for challenge validation..."
    $challenge = $(Update-ACMEIdentifier $alias -VaultProfile $VaultName -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}
    Start-Sleep -Seconds 10
    $try = $try + 1    
} 

if ($challenge.Status -ne 'valid') {
    throw 'Failed to validate challenge'
}
#>
#Generate cert
$certName = $alias + "-cert"
New-ACMECertificate $alias -VaultProfile $VaultName -Generate -Alias $certName
Submit-ACMECertificate -CertificateRef $certName -VaultProfile $VaultName

#Wait until cert is ready
$cert = Update-ACMECertificate -CertificateRef $certName -VaultProfile $VaultName
while ([String]::IsNullOrEmpty($cert.IssuerSerialNumber)) {
    Write-Host "Waiting for certficate...."
    Start-Sleep -Seconds 10
    $cert = Update-ACMECertificate -CertificateRef $certName -VaultProfile $VaultName
}

if(!(Test-Path -Path "$pwd\cert")){
New-Item -Path "$pwd\cert" -ItemType Directory
}

if ([String]::IsNullOrEmpty($CertificatePath)) {
    $CertificatePath = "$pwd\cert\" + $certName + ".pfx"
}

#Export PFX file
Get-ACMECertificate $certName -ExportPkcs12 $CertificatePath -CertificatePassword (New-Object PSCredential "user",$CertificatePassword).GetNetworkCredential().Password -VaultProfile $VaultName

# #Bind the cert to the web app
# $binding = New-AzureRmWebAppSSLBinding `
#     -WebAppName $WebAppName `
#     -ResourceGroupName $ResourceGroupName `
#     -Name $Fqdn `
#     -CertificateFilePath $CertificatePath `
#     -CertificatePassword (New-Object PSCredential "user",$CertificatePassword).GetNetworkCredential().Password `
#     -SslState SniEnabled

# Write-Host "All done."