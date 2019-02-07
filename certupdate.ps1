
param(
    [String]$key,    
    [String]$certificate,
    [String]$pass="secret",
    [String]$serviceAccount
);

$ErrorActionPreference = "Stop"

function Write-Color ($msg, $color) {
    Write-ColorNB "$msg`n" $color
}

function Write-ColorNB ($msg, $color) {    
    $color = if ($color) {$color} else {"white"}
    Write-Host $msg -ForegroundColor $color -NoNewline
}

function Write-Field ($field, $value, $color) {
    Write-ColorNB $field $color; Write-Color $value
}
    
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
          [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin){Write-Color "`nPlease re-run as administrator... `n"; exit}
if (-not $key){Write-Color "`nError: missing private key path (-key)...`n"; exit}
if (-not $certificate){ Write-Color "`nMissing certificate path (-cert)...`n"; exit}



function Write-Certificate($cert){

    $san = (($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"}).Format(1)).Replace("DNS Name=","")
    $san = $san.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

    Write-Color "`nCertificate Details`n--------------------" "green"
    Write-Field "Thumbprint: " $cert.Thumbprint "darkyellow"
    Write-Field "Subject: " $cert.Subject "darkyellow"
    Write-Field "Issuer: " $cert.IssuerName.Name "darkyellow"
    Write-Field "Issued: " $cert.NotBefore.ToString('MM/dd/yyyy') "darkyellow"
    Write-Field "Expires: " $cert.NotAfter.ToString('MM/dd/yyyy') "darkyellow"
    Write-Field "Subject Alternative Names: " "" "darkyellow"
    foreach ($s in $san) {Write-ColorNB "  + " "blue"; Write-Color $s}
    Write-Color ""

}

function Get-CertByPrint (){
    return Get-ChildItem -Path cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.ThumbPrint -eq $thumbprint }  
}

function Add-NewSSLCert(){

    param(
        [String]$pfxPath,    
        [String]$pass,
        [String]$serviceAccount
    )

    function Set-CertificatePermission ($pfxThumbPrint, $serviceAccount) {

        $cert = Get-CertByPrint $pfxThumbPrint
        $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $serviceAccount,"Read,FullControl","Allow";
        $keyFullPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"

        $acl = Get-Acl -Path $keyFullPath
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $keyFullPath -AclObject $acl;
        Write-Color "Successfully set permissions on private key for: $serviceAccount"
    }

    function Import-SSLCert($pfxFilePath, $pfxPass){    
        
        Write-Color "Importing certificate to Local Machine\Personal store... "
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable;
        
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($pfxFilePath, $pfxPass, $flags)
       
        Write-Certificate $cert
                
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "MY", LocalMachine
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::"ReadWrite")
        $store.Add($cert)
        $store.Close()

        Write-Color "Successfully imported: $thumbprint"
        return $cert.Thumbprint
    }

    $thumbprint = Import-SSLCert $pfxPath $pass 
    if ($serviceAccount) { Set-CertificatePermission $thumbPrint $serviceAccount }
    Write-Color "Finished adding new certificate!"
    return $thumbprint
}

function Convert-PEMtoPFX(){

    param(
        [String]$key,    
        [String]$certificate,
        [String]$pass
    )

    Write-Color "Converting $($certificate.Split("\")[-1]) to PFX format... "
    $key = (Resolve-Path $key).Path
    $certificate = (Resolve-Path $certificate).Path   
    $pfxPath = $certificate.Replace("pem","pfx")
    openssl pkcs12 -export -out $pfxPath -inkey $key -in $certificate -password pass:$pass
    Write-Color "Conversion complete!"
    return $pfxPath
}

function Set-NewSSLCert(){

    param(
        [String]$cert
    )

    $cert | Set-Item -Path 'IIS:\SSLBindings\*!443'
    Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $cert.Thumbprint
    Set-AdfsSslCertificate -Thumbprint $cert.Thumbprint
    Restart-Service ADFSSRV
   
}

Write-Color "Initiate SSL certificate update with the following parameters:" "green"
Write-Color "---------------------------------------------------------------" "green"
Write-Color "Certificate: $certificate"
Write-Color "Private Key: $key"
Write-Color "Service account: $serviceAccount"
Write-Color "PFX password: $pass"
Write-Color "`nBegin update`n-------------" "green"

$pfxPath = Convert-PEMtoPFX -k $key -c $certificate -p $pass
$thumbprint = Add-NewSSLCert -pfx $pfxPath -pass $pass -s $serviceAccount



Write-Color ""



    