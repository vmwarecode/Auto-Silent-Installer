#Script Name	: VAI
#Version		: 1.0
#License		: MIT
#Author			: tanp@vmware.com

########################################
###### Scripts Installation ############
########################################
param(
	[Parameter(Mandatory=$false)][AllowEmptyString()] [String]
	$cfgini,
	[Parameter(Mandatory=$false)][AllowEmptyString()] [String]
	$domainname,
	[Parameter(Mandatory=$false, HelpMessage="Enter InstallerType to filter target, it is defined by you in cfg-env.ini by default.")]
	[AllowEmptyString()] [String]  $vmType
	)
	# Initialize paras if no input from command
    if (($cfgini -eq "") -Or ($cfgini -eq $null))  { $cfgini = "..\config\cfg-env.ini"}
    if (($domainname -eq "") -Or ($domainname -eq $null)) { $domainname = "DefaultDomain"}
    if (($vmType -eq "" ) -Or ($vmType -eq $null)) { $vmType= "*"}
	# Import VAI Helper Module 
	Import-Module .\VAI.Helper.psm1
  
	# Read config file 
	$cfgdata = Get-IniContent $cfgini
	$mydomain =  $cfgdata.item($domainname)
	$varCfgVMs = $mydomain.TaskVMList
	$varUninstallExceptions = $mydomain.UninstallExceptions 

	# Install on localhost
	$vmName = hostname
	$varReinstallMark = $env:temp + "\Reinstall"
	
	# Log Output
	$MyLogFolder = Join-Path $mydomain.LogFolder $mydomain.Domain
	$MyInstallResults = Join-Path $MyLogFolder "InstallResults.csv"
	$lang = $vmName.Substring($vmName.Length-2)
	$myFolder = Join-Path $MyLogFolder $lang
	
	if (-Not (Test-Path $myFolder)) {New-Item $myFolder -ItemType directory}
	$today = Set-TimeNow
	$myLog = $vmName + "-Installer-"+ $today +".log"
	$varLogs = Join-Path $myFolder $myLog
	Start-Transcript $varLogs -Force

	$varvarComputer, $myInstallCollection = Get-VAIConfig $vmType $vmName $cfgdata $mydomain
	$varTime = $varvarComputer.Time
	if (($varvarComputer.DependOnHostAndPort -eq '') -or ($varvarComputer.DependOnHostAndPort -eq $null)){
		$varServerName = ''
	} else {
		$varServerName = $varvarComputer.DependOnHostAndPort.split(':')[0]
	}
	
	# Return Code
	$isInstallSuccess = $false
	$countInstalled = 0
	foreach ($myInstall in $myInstallCollection) {
		
		$varPreInstall = $myInstall.PreInstall
		$varPostInstall = $myInstall.PostInstall
		# Get correct Installer file x64 or x86
		$myName = hostname
		$myBit = Get-WmiObject win32_processor -ComputerName $myName | Select-Object AddressWidth
		if ($myBit.AddressWidth -eq 64) {
			$varInstallerPatten = $myInstall.InstallerPatten64
		} else {
			$varInstallerPatten = $myInstall.InstallerPatten32
		}
		$varInstalledName = $myInstall.InstalledName
		$varInstallerCert = $myInstall.InstallerCert
		$varInstallerLicense = $myInstall.InstallerLicense
		$varInstallerArg = $myInstall.InstallerArg
		$varReInstallArg = $myInstall.ReInstallArg		
		
		Set-VAILog ("Working on {0} Product {1}" -f $myName, $myInstall.InstallerType)
		
		if ($varTime -ne "rm") {
			Set-VAILog ("Check if we are going to do PreInstall per `$varPreInstall which is {0}" -f $varPreInstall)
			Start-VAIPrePostInstall($varPreInstall)
		}
		
		$varFileName = Get-VAIFileName $varInstallerFiles $varInstallerPatten	
		Set-VAILog ("We get installer file from {0}" -f $varFileName)
		$varFileName,$varInstallerCert,$varInstallerLicense = Start-CopyInstaller $varFileName $varInstallerCert $varInstallerLicense
		
		Set-VAILog ("Now we get local installer file {0}" -f $varFileName)
		$varFileVer,$varInstalledVer,$varIdentifyingNumber = Get-VAIVersions $varFileName $varInstalledName
		Set-VAILog ("Version of Installer is {0}!" -f $varFileVer)
		Set-VAILog ("Version of Installed is {0}!" -f $varInstalledVer)

		if (($varInstalledVer -ne "None") -and (($varTime -eq "rm") -or ($varFileVer -ne $varInstalledVer))) {
			Set-VAILog ("We will do uninstallation if `$varTime is 'rm' or File Version is not same as Installed Version")
			# Output a mark to indicate reinstallation, will be removed once do installation
			Add-Content $varReinstallMark "Reinstall"
			Start-VAIUninstall $varInstalledName $varUninstallExceptions
		}
		
		if (($varTime -ne "rm") -and ($varFileVer -ne $varInstalledVer)) {
			Set-VAILog ("Now we are going to do installation!" -f $varTime)
			if (test-path $varReinstallMark) {
				Remove-Item $varReinstallMark -Force
				# Note, this is reinstall
				Start-VAIInstall $varFileName $varReInstallArg $varInstallerCert $varServerName
			} else {
				# Note, this is install
				Start-VAIInstall $varFileName $varInstallerArg $varInstallerCert $varServerName
			}		
		}

		
		if ($varFileVer -eq $varInstalledVer) {
			Set-VAILog ("Installed version {0} is same as the one to install from {1}!" -f $varInstalledVer,$varFileName)
			$isInstallSuccess = $true
		}
		
		if ($varTime -eq "rm") {
			Set-VAILog ("Product {0} uninstalled!`r`n`r`n`r`n" -f $varFileName)
			$isInstallSuccess = $true
		}
		
		# Verify installation and Do Post Installation
		if ($varTime -ne "rm") {
			Set-VAILog ("Now Verify the installation result:" -f $varFileName)
			$varFileVer,$varInstalledVer,$varIdentifyingNumber = Get-VAIVersions $varFileName $varInstalledName
			Set-VAILog ("Version of Installer is {0}!" -f $varFileVer)
			Set-VAILog ("Version of Installed is {0}!" -f $varInstalledVer)
			if (($varInstalledVer -ne "") -or ($varInstalledVer -ne $null)){
				Set-VAILog ("We will do PostInst per `$varPostInstall which value is {0}" -f $varPostInstall)
				Start-VAIPrePostInstall($varPostInstall)
				if ($varFileVer -ne $varInstalledVer){
					Set-VAILog ("All DONE, but we need to check why Installed version is not same as expected even certain version installed.")
					$isInstallSuccess = $false
				} else {
					Set-VAILog ("We installed expected version from Installer. Let's report to Control Center via log in {0} and kill scheduled tasks." -f $MyLogFolder)
					$isInstallSuccess = $true
				}
			} else {
				Set-VAILog ("Error Occurred. No version installed, please double check.")
				$isInstallSuccess = $false
			}

		}

		# increase countInstalled +1
		$countInstalled += 1
	}
	
	# disable the task since installation is done and expected version installed
	if (($countInstalled -eq $myInstallCollection.count) -and $isInstallSuccess) {
		$scriptPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
		Set-VAILog ("Script Path: {0}" -f $scriptPath)
		Set-TaskSched $mydomain "disable" $scriptPath $varvarComputer.ComputerName $vmType
	}
	# log End
	Stop-Transcript

	

  
