
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

    function Get-Certificate($thumbprint){
        return Get-ChildItem -Path cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.ThumbPrint -eq $thumbprint; };    
    }

    function Set-CertificatePermission ($pfxThumbPrint, $serviceAccount) {

        $cert = Get-Certificate $pfxThumbPrint
        $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $serviceAccount,"Read,FullControl","Allow";
        $keyFullPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)"

        $acl = Get-Acl -Path $keyFullPath
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $keyFullPath -AclObject $acl;
    }

    function Import-SSLCert($pfxFilePath, $pfxPass){    
        
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor `
                 [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable;
        
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($pfxFilePath, $pfxPass, $flags)
                
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "MY", LocalMachine
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::"ReadWrite")
        $store.Add($cert)
        $store.Close()
        return $cert
    }

    $cert = Import-SSLCert $pfxPath $pass    
    if ($serviceAccount) { Set-CertificatePermission $cert.ThumbPrint $serviceAccount }
    return Get-Certificate $cert.ThumbPrint
}

function Convert-PEMtoPFX(){

    param(
        [String]$key,    
        [String]$certificate,
        [String]$pass
    )

    $key = (Resolve-Path $key).Path
    $certificate = (Resolve-Path $certificate).Path   
    $pfxPath = $certificate.Replace("pem","pfx")
    openssl pkcs12 -export -out $pfxPath -inkey $key -in $certificate -password pass:$pass
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

$pfxPath = Convert-PEMtoPFX -k $key -c $certificate -p $pass
$cert = Add-NewSSLCert -pfx $pfxPath -pass $pass -s $serviceAccount



    