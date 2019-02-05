
param(
    [String]$key,    
    [String]$certificate,
    [String]$pass
    );

    $certificate = "alldomains-02-2-4-2019\fullchain1.pem"
    $key = "alldomains-02-2-4-2019\privkey1.pem"
    $pass = "secret"

function Add-NewSSLCert($pfxPath, $pass){
    function Set-CertificatePermission ($pfxThumbPrint, $account) {

        $cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.ThumbPrint -eq $pfxThumbPrint; };    
        $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $account,"Read,FullControl","Allow";
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
        return $cert.Thumbprint
    }

    $thumbprint = Import-SSLCert $pfxPath $pass
    Set-CertificatePermission $thumbprint "Everyone"
}
function Convert-PEMtoPFX($key, $certificate, $pass){
    $key = (Resolve-Path $key).Path
    $certificate = (Resolve-Path $certificate).Path   
    $pfxPath = $certificate.Replace("pem","pfx")
    openssl pkcs12 -export -out $pfxPath -inkey $key -in $certificate -password pass:$pass
    return $pfxPath
}

$pfxPath = Convert-PEMtoPFX $key $certificate $pass
Add-NewSSLCert $pfxPath $pass

    