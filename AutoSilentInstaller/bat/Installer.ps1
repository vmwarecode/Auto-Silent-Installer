param(
	 [Parameter(Mandatory=$True, HelpMessage="Enter InstallerType to filter target, it is defined by you in cfg-installertype.csv by default.")]
	 [AllowEmptyString()] [String]  $vmType 
	)

	# Specify your config files here
	$varCfgVMs = "..\config\cfg-vms.csv"
	$varCfgTypes = "..\config\cfg-installertype.csv"

	
	
########################################
######## Functions Used ################
########################################

	# 00 Read config file
function ReadConfig($vmType, $vmName, $varCfgVMs, $varCfgTypes) {

	$csvdata = import-csv $varCfgVMs
	$varComputers = $csvdata | Where-Object {$_.InstallerType -like ("*" + $vmType + "*")} | Where-Object {$_.ComputerName -like ($vmName + ".*")}
	# Incase the IP Address used for computername
	If ($varComputers -eq $null) {
		$varComputers = $csvdata | Where-Object {$_.InstallerType -like ("*" + $vmType + "*")} | Where-Object {$_.ComputerName -eq $vmName}
	}

	# Set Vars, pick first one if multi line
	$varTime = $varComputers[0].Time
	$varInstallerFolder = $varComputers[0].InstallerFolder
	$varServerName = $varComputers[0].ServerName
	$varServerDB = $varComputers[0].ServerDB
	$varServerUser = $varComputers[0].ServerUser
	$varServerPassword = $varComputers[0].ServerPassword
	$varLicenseFile = $varComputers[0].LicenseFile
	# We support multiType for InstallerType
	$varMultiTypes = $varComputers[0].InstallerType.Split(',')

	# Determin Install Type and save to collection
	$myInstallCollection = @()
	
	$csvdataType = import-csv $varCfgTypes
	foreach ($varOneType in $varMultiTypes) {
	    $myInstallItem = "" | Select-Object PreInstall,InstallerPatten,InstalledName,InstallerCert,InstallerArg        
		$varInstallArg = $csvdataType | Where-Object {$_.InstallerType -like $varOneType}
		# Set Vars per $varType
		$myInstallItem.PreInstall = $varInstallArg[0].PreInstall
		if ([environment]::Is64BitOperatingSystem) {
			$myInstallItem.InstallerPatten = $varInstallArg[0].InstallerPatten64
		} else {
			$myInstallItem.InstallerPatten = $varInstallArg[0].InstallerPatten32
		}
		$myInstallItem.InstalledName = $varInstallArg[0].InstalledName
		$myInstallItem.InstallerCert = $varInstallArg[0].InstallerCert
		$myInstallItem.InstallerArg = $varInstallArg[0].InstallerArg
		$myInstallCollection+=$myInstallItem
	}
	return $varTime, $varInstallerFolder, $varServerName, $varServerDB, $varServerUser, $varServerPassword,$varLicenseFile, `
			$myInstallCollection
}

	# 01 PreInstall : install prerequirement one by one
function PreInstall($varPreInstall) {
	if ($varPreInstall -ne "") {
		$preInst = $varPreInstall.split(',')
		if ($preInst.count -gt 0) {
			$preInst | foreach-object { 
				Write-Output " $(Get-Date -format 'u') Add-WindowsFeature `"$_`"." 
				if ($_ -eq "RDS-RD-Server") {
					Import-Module Servermanager
					Add-WindowsFeature $_ -Restart
				}   
				else {
					dism /online /enable-feature /featurename:$_ /Quiet
				}
			}
		}

	}
}

	# 02 Get Installer File via $varInstallerPatten and $varInstallerFolder
function GetFileName($varInstallerFiles, $varInstallerPatten) {
	$varInstallerFiles = Get-ChildItem $varInstallerFolder -Recurse -Include $varInstallerPatten
	# If no new installer files found, exit instavarInstallerPattenllation
	if ($varInstallerFiles -eq $null) {
		Write-Output " No Installer File found, cancel the task!"
		exit(1)
	} else {
		Write-Host ("{0} Installer File(s) found, will pick the last one!" -f $varInstallerFiles.Count)
		$varFileName = $varInstallerFiles[$varInstallerFiles.Count -1].FullName
		Write-Host ("Installer File is {0}!" -f $varFileName)
		return $varFileName
	}
}

	# 03 Version Check : Compare Version of File and Installed one
function GetVersions($varFileName, $varInstalledName) {
	$varFileVer = (dir $varFileName).versioninfo | select ProductVersion
	$varFileVer = $varFileVer.ProductVersion.substring(6)
	Write-Host ("Version of Installer is {0}!" -f $varFileVer)

	Wait-OtherInstaller("msiexec")
	$varInstalledProduct = Get-WmiObject -Class win32_product | Where-Object {$_.name -like $varInstalledName.split(',')[0]}
    if ($varInstalledProduct -ne $null){
	    $varInstalledVer = $varInstalledProduct.Version.substring(6)
        $varIdentifyingNumber = $varInstalledProduct.identifyingNumber 
    } else {
        $varInstalledVer ="None"
        $varIdentifyingNumber = "None"
    }
	
	Write-Host ("Version of Installed is {0}!" -f $varInstalledVer)
	return $varFileVer,$varInstalledVer,$varIdentifyingNumber
}
	
	# 04 Uninstall
function Uninstall($varInstalledName) {
	foreach ($varInstalled in $varInstalledName.split(',')){
	Wait-OtherInstaller("msiexec")
	Write-Host ("Uninstalling {0}!" -f $varInstalled)
	$varInstalledProduct = Get-WmiObject -Class win32_product | Where-Object {$_.name -like $varInstalled }
	$varUninstall = $varInstalledProduct.Uninstall()
	Write-Host ("Uninstall result is {0}!" -f $varUninstall)
	}
}

	# 05 Installation
function Install($varFileName, $varInstallerArg, $varServerDB, $varServerUser, $varServerPassword,$varLicenseFile) {
	certutil -f -addstore "TrustedPublisher" $varInstallerCert

	# Replace the placeholder via Variables, such as ServerName,ServerDB,ServerUser,ServerPassword,LicenseFile
	$varInstallerArg = $varInstallerArg.Replace("ServerName", $varServerName)
    $varInstallerArg = $varInstallerArg.Replace("ServerDB", $varServerDB)
    $varInstallerArg = $varInstallerArg.Replace("ServerUser", $varServerUser)
    $varInstallerArg = $varInstallerArg.Replace("ServerPassword", $varServerPassword)
    $varInstallerArg = $varInstallerArg.Replace("LicenseFile", $varLicenseFile)
	
	Wait-OtherInstaller("msiexec")
	Write-Host ("Installing {0} {1}!" -f $varFileName,$varInstallerArg)
	$varInstall = Start-Process -FilePath $varFileName -ArgumentList $varInstallerArg -wait -NoNewWindow
	Write-Host ("Install result is {0}!" -f $varInstall)
}

	# ** Wait for msiexec to avoid conflict
function Wait-OtherInstaller($procName) {
	Start-Process -FilePath VerifyOtherInstaller.bat -ArgumentList $procName -wait -NoNewWindow
}
	
	
	
########################################
######## Scripts Used ################
########################################
		
	
	# Install on localhost
	$vmName = hostname
	if ($vmType -eq "") { $vmType = "*"}
	
	# Log Output
	if (-Not (Test-Path "..\logs\")) {New-Item "..\logs\" -ItemType directory}
	$today = date -Format yyyyMMddHHmmss
	Start-Transcript ("..\logs\" + $vmName + "-Set-TaskSched-"+ $today +".log") -Force


	$varTime, $varInstallerFolder, $varServerName, $varServerDB, $varServerUser, $varServerPassword,$varLicenseFile, $myInstallCollection = ReadConfig $vmType $vmName $varCfgVMs $varCfgTypes 
	
	foreach ($myInstall in $myInstallCollection) {
		
		$varPreInstall = $myInstall.PreInstall
		$varInstallerPatten = $myInstall.InstallerPatten
		$varInstalledName = $myInstall.InstalledName
		$varInstallerCert = $myInstall.InstallerCert
		$varInstallerArg = $myInstall.InstallerArg
		$today = date -Format yyyyMMddHHmmss
		Write-Host ("{0} Working on Product {1}`r`n`r`n`r`n" -f $today,$myInstall)
		
		if ($varTime -ne "rm") {
			PreInstall($varPreInstall)
		}

		$varFileName = GetFileName $varInstallerFiles $varInstallerPatten	
		$varFileVer,$varInstalledVer,$varIdentifyingNumber = GetVersions $varFileName $varInstalledName
		
		if (($varInstalledVer -ne "None") -and (($varTime -eq "rm") -or ($varFileVer -ne $varInstalledVer))) {
			Uninstall $varInstalledName
		}
		
		if (($varTime -ne "rm") -and ($varFileVer -ne $varInstalledVer)) {
			Install $varFileName $varInstallerArg $varServerDB $varServerUser $varServerPassword $varLicenseFile
		}
		
		if ($varFileVer -eq $varInstalledVer) {
			Write-Host ("Installed version {0} is same as the one to install from {1}!`r`n`r`n`r`n" -f $varInstalledVer,$varFileName)
		}
		
		if ($varTime -eq "rm") {
			Write-Host ("Product {0} uninstalled!`r`n`r`n`r`n" -f $varFileName)
		}
	}
	
	# log End
	Stop-Transcript

