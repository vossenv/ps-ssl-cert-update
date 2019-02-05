



param(
    [String]$sourcefolder=""
    )


$sourcefolder = "alldomains-02-2-4-2019"

$pass = "secret"
$certname = "fullchain1.pem"
$keyname = "privkey1.pem"

openssl pkcs12 -export -out "$sourcefolder\ssl.pfx" -inkey "$sourcefolder\$keyname" -in "$sourcefolder\$certname" -password pass:$pass
#$thumbprint = ((openssl x509 -in "$sourcefolder\$certname" -fingerprint -noout).Split("=")[1]).Replace(":","")

$thumbprint = (Import-PfxCertificate `
                -FilePath $sourcefolder\ssl.pfx `
                -CertStoreLocation Cert:\CurrentUser\My `
                -Password ($pass | convertto-securestring -asplaintext -force) `
                -Exportable).Thumbprint



Write-Host ""


