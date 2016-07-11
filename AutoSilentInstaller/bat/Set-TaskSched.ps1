

	param(
	 [Parameter(Mandatory=$True, HelpMessage="To schedule Task and Execute the Installatoin now? By default No. `r`n `
			Yes (Install without Reboot) /No (Install later via schedule) /Reboot (Reboot to install, recommended for RDSH) `r`n `
			/Clean (Delete the scheduled task) /Disable (Disable the scheduled task)")]
	 [AllowEmptyString()] [String]  $varExecuteNow,
	 [Parameter(Mandatory=$True, HelpMessage="Enter Computer Name patten to filter target, such as 'Agent7JPx86', support '*Agent*'.")]
	 [AllowEmptyString()] [String]  $vmName,
	 [Parameter(Mandatory=$True, HelpMessage="Enter InstallerType to filter target, it is defined by you in cfg-installertype.csv by default.")]
	 [AllowEmptyString()] [String]  $vmType 
	)

	# Specify your config file and the path to your XML files here
	$varCfgVMs = "..\config\cfg-vms.csv"
	$varTaskXMLPath = "..\config\TaskXML"

	
	# Log Output
	$varLogs = "..\logs\Set-TaskSched_cmd.log"
	$varBat = "..\logs\Set-TaskSched.bat"
	if (-Not (Test-Path "..\logs\")) {New-Item "..\logs\" -ItemType directory}
	Start-Transcript ("..\logs\Set-TaskSched.log") -Force

	if ( $varExecuteNow -eq "" ) { $varExecuteNow= "No"}
	if ($vmName -eq "") { $vmName = "*"}
	if ($vmType -eq "") { $vmType = "*"}

	# Read config file and get list of your XML files to customize
	$csvdata = import-csv $varCfgVMs
	$varComputers = $csvdata | Where-Object {$_.InstallerType -like ($vmType + "*")} | Where-Object {$_.ComputerName -like ($vmName +"*")}

	# Change old $varBat
	if (test-path $varBat){
		$oldBat = get-item -path $varBat
		$today = date -Format yyyyMMddHHmmss
		rename-item $oldBat ($oldBat.Name+"-"+$today)
	}
	if (test-path $varLogs){
		$oldLogs = get-item -path $varLogs
		$today = date -Format yyyyMMddHHmmss
		rename-item $oldLogs ($oldLogs.Name+"-"+$today)
	}
	# Schedule Task and Execute per $varExecuteNow
	foreach ($varComputer in $varComputers) {
		#$varSchtasks = $env:SystemRoot + "\system32\schtasks.exe"
		$varCMD = "/s {0} /u {1} /p {2}" -f  $varComputer.ComputerName,$varComputer.UserName,$varComputer.Password

		$varCMDCreateHorizonInstall = "schtasks.exe /create {0} /tn HorizonInstall /xml {1}\HorizonInstall.xml /ru {2} /rp {3} /F >> {4}" -f $varCMD,$varTaskXMLPath,$varComputer.UserName,$varComputer.Password, $varLogs
		$varCMDCreateHorizonReboot = "schtasks.exe /create {0} /tn HorizonReboot /xml {1}\HorizonReboot.xml /ru {2} /rp {3} /F >> {4}" -f $varCMD,$varTaskXMLPath,$varComputer.UserName,$varComputer.Password, $varLogs 
		$varCMDChangeHorizonReboot = "schtasks.exe /change {0} /tn HorizonReboot /st  {1} /ru {2} /rp {3} >> {4}" -f $varCMD,$varComputer.Time,$varComputer.UserName,$varComputer.Password, $varLogs

		$varCMDRunHorizonReboot = "schtasks.exe /run {0} /tn HorizonReboot >> {1}" -f $varCMD, $varLogs
		$varCMDRunHorizonInstall = "schtasks.exe /run {0} /tn HorizonInstall >> {1} " -f $varCMD, $varLogs
		
		$varCMDCleanHorizonInstall = "schtasks.exe /delete {0} /tn HorizonInstall /F >> {1}" -f $varCMD, $varLogs
		$varCMDCleanHorizonReboot = "schtasks.exe /delete {0} /tn HorizonReboot /F >> {1}" -f $varCMD, $varLogs

		$varCMDDisableHorizonInstall = "schtasks.exe /change {0} /tn HorizonInstall /Disable >> {1}" -f $varCMD, $varLogs
		$varCMDDisableHorizonReboot = "schtasks.exe /change {0} /tn HorizonReboot /Disable >> {1}" -f $varCMD, $varLogs
		
		##
		## & $varCMD does not work well; also start-process has problem to generate result. So we output to Set-TaskSched.bat file and execute via bat
		##
		switch ($varExecuteNow) {
			# Command if choose to Execute right after command, caution to use without any vmName & vmType filter, or the host would be very busy
			"Yes" {
			Add-Content $varBat $varCMDCreateHorizonInstall
			Add-Content $varBat $varCMDCreateHorizonReboot
			Add-Content $varBat $varCMDChangeHorizonReboot
			Add-Content $varBat $varCMDRunHorizonInstall
			}
			# Command if choose to Execute right after command after reboot, caution to use without any vmName & vmType filter, or the host would be very busy
			"Reboot" {
			Add-Content $varBat $varCMDCreateHorizonInstall
			Add-Content $varBat $varCMDCreateHorizonReboot
			Add-Content $varBat $varCMDChangeHorizonReboot
			Add-Content $varBat $varCMDRunHorizonReboot
			}
			#Command to delete the scheduled tasks on VM
			"Clean" {
			Add-Content $varBat $varCMDCleanHorizonInstall
			Add-Content $varBat $varCMDCleanHorizonReboot
			}
			#Command to disable the scheduled tasks on VM
			"Disable" {
			Add-Content $varBat $varCMDDisableHorizonInstall
			Add-Content $varBat $varCMDDisableHorizonReboot
			}
			#Command to create the tasks on VM and they are scheduled to execute on specified time, recommended to use. The good schedule will help to avoid host busy
			default {
			Add-Content $varBat $varCMDCreateHorizonInstall
			Add-Content $varBat $varCMDCreateHorizonReboot
			Add-Content $varBat $varCMDChangeHorizonReboot
			}
		}	
	}
	
	# Execute $varBat 
	Write-Host ("Execute {0} which log file is {1}!" -f $varBat,$varLogs)
	& $varBat

	# log End
	Stop-Transcript