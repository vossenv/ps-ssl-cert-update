
param(
    [String]$key,    
    [String]$certificate,
    [String]$pass="secret",
    [String]$serviceAccount
);

function Write-Info  ($msg, $color) { Write-LogEntry $msg $color "INFO" }
function Write-Warn  ($msg, $color) { Write-LogEntry $msg "darkyellow" "WARN" }
function Write-Error ($msg, $color) {        
    try {
        Write-LogEntry $msg "red" "ERROR" 
        Write-LogEntry $msg.ScriptStackTrace "red" "ERROR"
    } catch {}
    exit
}


function Write-LogEntry($msg, $color, $level){  
    $color = if ($color) {$color} else {"white"}
    $entry = (Get-Date).toString("yyyy-mm-dd HH:mm:ss ") + "[ $level ] [ $([System.Net.Dns]::GetHostName()) ] ::: " + $msg  
    Write-Host $entry -ForegroundColor $color     
    $entry | Out-File 'ssl_update.log' -Append
     [Console]::Out.Flush()
}

function Write-Section($msg, $color){
    Write-Info ""
    Write-Info $msg $color
    Write-Info ("-" * $msg.length) $color
}

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
          [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin){Write-Error "Please re-run as administrator... "; exit}
if (-not $key){Write-Error "Error: missing private key path (-key)... "; exit}
if (-not $certificate){ Write-Error "Missing certificate path (-cert)... "; exit}
$ErrorActionPreference = "Stop"

function Write-Certificate($cert){

    $san = (($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"}).Format(1)).Replace("DNS Name=","")
    $san = $san.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)

    Write-Section "Certificate Details" "green"
    Write-Info "Thumbprint: $($cert.Thumbprint)" 
    Write-Info "Subject: $($cert.Subject)"
    Write-Info "Issuer: $($cert.IssuerName.Name)" 
    Write-Info "Issued: $($cert.NotBefore.ToString('MM/dd/yyyy'))"
    Write-Info "Expires: $($cert.NotAfter.ToString('MM/dd/yyyy'))" 
    Write-Info "Subject Alternative Names: "
    foreach ($s in $san) {Write-Info "  + $s"}
    Write-Info ""
}

function Get-CertByPrint ($thumbprint){
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
        
        if ((Get-Acl -Path $keyFullPath).AccessToString -ne $acl.AccessToString) { 
            Write-Warn "Error setting proper permissions on private key... "
        } else {
            Write-Info "Successfully set permissions on private key for: $serviceAccount"
        }
    }

    function Import-SSLCert($pfxFilePath, $pfxPass){    
        
        Write-Info "Importing certificate to Local Machine\Personal store... "
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

        if ((Get-CertByPrint $cert.Thumbprint) -ne $cert) {throw "Could not validate certificate entry: cause unknown!"}

        Write-Info "Successfully imported: $thumbprint"
        return $cert.Thumbprint
    }

    try {
        $thumbprint = Import-SSLCert $pfxPath $pass 
        if ($serviceAccount) { Set-CertificatePermission $thumbPrint $serviceAccount }
        Write-Info "Finished adding new certificate!" "green"
        return $thumbprint
    } catch { Write-Error $_  }
}

function Convert-PEMtoPFX(){

    param(
        [String]$key,    
        [String]$certificate,
        [String]$pass
    )

    try {
        Write-Info "Converting $($certificate.Split("\")[-1]) to PFX format... "
        $key = (Resolve-Path $key).Path
        $certificate = (Resolve-Path $certificate).Path   
        $pfxPath = $certificate.Replace("pem","pfx")
        openssl pkcs12 -export -out $pfxPath -inkey $key -in $certificate -password pass:$pass
        Write-Info "Conversion complete!"
        return $pfxPath 
    } catch { Write-Error $_  }
}



function Set-NewSSLCert($thumbprint){   

    function Update-IISCertificate($cert){
        Write-Info "Adding WebAdministration module..."
        Import-Module WebAdministration

        Write-Info "Setting SSL binding on *443..."
        $cert | Set-Item -Path 'IIS:\SSLBindings\*!443'

        Write-Info "Restart IIS"
        IISRESET /restart

        Write-Info "IIS certificate installed successfully!!" "green"
    }

    function Update-ADFSCertificate($cert){
        Write-Info "Setting ADFS communications certificate... "
        Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $cert.Thumbprint

        if ((get-adfscertificate -CertificateType Service-Communications).thumbprint -ne $cert.Thumbprint) {
            Write-Warn "Failed to update communcations certificate... please make this change manually!!"
        }

        Write-Info "Setting ADFS SSL certificate... "
        Set-AdfsSslCertificate -Thumbprint $cert.Thumbprint
  
        Write-Info "Restart ADFS service... "
        Restart-Service adfssrv

        foreach ($c in (get-adfssslcertificate)){
            if ($c.CertificateHash -ne $cert.Thumbprint) {Write-Warn "ADFS SSL binding may be incomplete: see get-adfssslcertificate for: " + $c.HostName}
        }

        Write-Info "ADFS certificate installed succesfully!!" "green"
    }

    try {
        Write-Section "Set new certificates" "green"
        $cert = Get-CertByPrint $thumbprint
        Update-ADFSCertificate $cert
        Update-IISCertificate $cert
        Write-Info "Certificate replacement completed!!" "Green"
    } catch { Write-Error $_  }

}

Write-Info ""
Write-Info "------------------------ Starting new log------------------------"
Write-Info ""
Write-Section "Initiate SSL certificate update with the following parameters:" "green"
Write-Info "Certificate: $certificate"
Write-Info "Private Key: $key"
Write-Info "Service account: $serviceAccount"
Write-Info "PFX password: $pass"
Write-Section "Begin update" "green"

$pfxPath = Convert-PEMtoPFX -k $key -c $certificate -p $pass
$thumbprint = Add-NewSSLCert -pfx $pfxPath -pass $pass -s $serviceAccount
Set-NewSSLCert $thumbprint


