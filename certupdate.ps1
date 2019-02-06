
param(
    [String]$key,    
    [String]$certificate,
    [String]$pass="secret",
    [String]$serviceAccount
);
    
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
          [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin){Write-Host "`nPlease re-run as administrator... `n"; exit}
if (-not $key){Write-Host "`nError: missing private key path (-key)...`n"; exit}
if (-not $certificate){ Write-Host "`nMissing certificate path (-cert)...`n"; exit}

function Add-NewSSLCert(){

    param(
        [String]$pfxPath,    
        [String]$pass,
        [String]$serviceAccount
    )

    function Show-Certificate($cert){

        $san = (($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"}).Format(1)).Replace("DNS Name=","")
        $san = $san.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

        Write-Host "`nCertificate Details`n--------------------"

        Write-Host "Thumbprint: $($cert.Thumbprint)"
        Write-Host "Subject: $($cert.Subject)"
        Write-Host "Issuer: $($cert.IssuerName.Name)"
        Write-Host "Issued: $($cert.NotBefore.ToString('MM/dd/yyyy'))"
        Write-Host "Expires: $($cert.NotAfter.ToString('MM/dd/yyyy'))"
        Write-Host "Subject Alternative Names:"
        foreach ($s in $san) {Write-Host "  + $s"}
        Write-Host

    }

    function Set-CertificatePermission ($pfxThumbPrint, $serviceAccount) {

        $cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.ThumbPrint -eq $thumbprint }  
        $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $serviceAccount,"Read,FullControl","Allow";
        $keyFullPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"

        $acl = Get-Acl -Path $keyFullPath
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $keyFullPath -AclObject $acl;
        Write-Host "Successfully set permissions on private key for: $serviceAccount"
    }

    function Import-SSLCert($pfxFilePath, $pfxPass){    
        
        Write-Host "Importing certificate to Local Machine\Personal store... "
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable;
        
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($pfxFilePath, $pfxPass, $flags)
       
        Show-Certificate $cert
                
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "MY", LocalMachine
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::"ReadWrite")
        $store.Add($cert)
        $store.Close()

        Write-Host "Successfully imported: $thumbprint"
        return $cert.Thumbprint
    }

    $thumbprint = Import-SSLCert $pfxPath $pass 
    if ($serviceAccount) { Set-CertificatePermission $thumbPrint $serviceAccount }
    Write-Host "Finished adding new certificate!"
    return $thumbprint
}

function Convert-PEMtoPFX(){

    param(
        [String]$key,    
        [String]$certificate,
        [String]$pass
    )

    Write-Host "Converting $($certificate.Split("\")[-1]) to PFX format... "
    $key = (Resolve-Path $key).Path
    $certificate = (Resolve-Path $certificate).Path   
    $pfxPath = $certificate.Replace("pem","pfx")
    openssl pkcs12 -export -out $pfxPath -inkey $key -in $certificate -password pass:$pass
    Write-Host "Conversion complete!"
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

Write-Host "Initiate SSL certificate update with the following parameters:"
Write-Host "---------------------------------------------------------------"
Write-Host "Certificate: $certificate"
Write-Host "Private Key: $key"
Write-Host "Service account: $serviceAccount"
Write-Host "PFX password: $pass"
Write-Host "`nBegin update`n-------------"

$pfxPath = Convert-PEMtoPFX -k $key -c $certificate -p $pass
$thumbprint = Add-NewSSLCert -pfx $pfxPath -pass $pass -s $serviceAccount



Write-Host ""



    