
if not "%1"=="" (
	powershell -command " while ($true) { Ping -n 1 127.1>nul;	$varRunning = get-process %1 | select ProcessName | findstr %1; $varRunning; if (($varRunning -eq $null) -or ($varRunning[0] -eq 'm')) { break} }"

)
