#Script Module : VAI.Helper
#Version       : 1.0
#License       : MIT
#Author        : tanp@vmware.com


########################################
######## Common Function ###############
########################################

# Module: to read json file
function Get-JsonContent {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SpecFile
  )
  if (test-path $SpecFile)
  {
    return Get-Content -Raw $specFile | ConvertFrom-Json
  } else {
	write-error "Unable to find json file [$specFile], $_" 
  }
}

# Module: to read ini file (from Github)
Function Get-IniContent {
    <#
    .Synopsis
        Gets the content of an INI file

    .Description
        Gets the content of an INI file and returns it as a hashtable

    .Notes
        Author	: Oliver Lipkau <oliver@lipkau.net>
	Source	: https://github.com/lipkau/PsIni
                      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
        Version	: 1.0.0 - 2010/03/12 - OL - Initial release
                      1.0.1 - 2014/12/11 - OL - Typo (Thx SLDR)
                                              Typo (Thx Dave Stiff)
                      1.0.2 - 2015/06/06 - OL - Improvment to switch (Thx Tallandtree)
                      1.0.3 - 2015/06/18 - OL - Migrate to semantic versioning (GitHub issue#4)
                      1.0.4 - 2015/06/18 - OL - Remove check for .ini extension (GitHub Issue#6)
                      1.1.0 - 2015/07/14 - CB - Improve round-tripping and be a bit more liberal (GitHub Pull #7)
                                           OL - Small Improvments and cleanup
                      1.1.1 - 2015/07/14 - CB - changed .outputs section to be OrderedDictionary
                      1.1.2 - 2016/08/18 - SS - Add some more verbose outputs as the ini is parsed,
                      		            allow non-existent paths for new ini handling,
                      		            test for variable existence using local scope,
                      		            added additional debug output.

        #Requires -Version 2.0

    .Inputs
        System.String

    .Outputs
        System.Collections.Specialized.OrderedDictionary

    .Parameter FilePath
        Specifies the path to the input file.

    .Parameter CommentChar
        Specify what characters should be describe a comment.
        Lines starting with the characters provided will be rendered as comments.
        Default: ";"

    .Parameter IgnoreComments
        Remove lines determined to be comments from the resulting dictionary.

    .Example
        $FileContent = Get-IniContent "C:\myinifile.ini"
        -----------
        Description
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent

    .Example
        $inifilepath | $FileContent = Get-IniContent
        -----------
        Description
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent

    .Example
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini"
        C:\PS>$FileContent["Section"]["Key"]
        -----------
        Description
        Returns the key "Key" of the section "Section" from the C:\settings.ini file

    .Link
        Out-IniFile
    #>

    [CmdletBinding()]
    [OutputType(
        [System.Collections.Specialized.OrderedDictionary]
    )]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$FilePath,
        [char[]]$CommentChar = @(";"),
        [switch]$IgnoreComments
    )

    Begin
    {
        Write-Debug "PsBoundParameters:"
        $PSBoundParameters.GetEnumerator() | ForEach { Write-Debug $_ }
        if ($PSBoundParameters['Debug']) { $DebugPreference = 'Continue' }
        Write-Debug "DebugPreference: $DebugPreference"

        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"

        $commentRegex = "^([$($CommentChar -join '')].*)$"
        Write-Debug ("commentRegex is {0}." -f $commentRegex)
    }

    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"

        $ini = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)

        if (!(Test-Path $Filepath))
        {
            Write-Verbose ("Warning: `"{0}`" was not found." -f $Filepath)
            return $ini
        }

        $commentCount = 0
        switch -regex -file $FilePath
        {
            "^\s*\[(.+)\]\s*$" # Section
            {
                $section = $matches[1]
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding section : $section"
                $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                $CommentCount = 0
                continue
            }
            $commentRegex # Comment
            {
                if (!$IgnoreComments)
                {
                    if (!(test-path "variable:local:section"))
                    {
                        $section = $script:NoSection
                        $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                    }
                    $value = $matches[1]
                    $CommentCount++
                    Write-Debug ("Incremented CommentCount is now {0}." -f $CommentCount)
                    $name = "Comment" + $CommentCount
                    Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding $name with value: $value"
                    $ini[$section][$name] = $value
                }
                else { Write-Debug ("Ignoring comment {0}." -f $matches[1]) }

                continue
            }
            "(.+?)\s*=\s*(.*)" # Key
            {
                if (!(test-path "variable:local:section"))
                {
                    $section = $script:NoSection
                    $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                }
                $name,$value = $matches[1..2]
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding key $name with value: $value"
                $ini[$section][$name] = $value
                continue
            }
        }
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"
        Return $ini
    }

    End
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}
}

# Module: to verify net connection to server
Function Wait-ServerConnection {
    Param(
    [ValidateNotNullOrEmpty()] [String]  $myServer,
	[AllowEmptyString()] [String]  $timeretry,
	[AllowEmptyString()] [String]  $timeout
    )
	$isconnected = $false
	$timeused = 0
	# We give up if >= 7200s
	if ($timeout -eq '') {$timeout = 7200}
	
	$dependonHost = $myServer.split(':')[0]
	$dependonPort = $myServer.split(':')[1]
	if ($dependonPort -eq $null) {$dependonPort = '443'}			

	if ($timeretry -eq '') {$timeretry = 60}
	
	while ((-Not $isconnected) -And ($timeused -lt $timeout)) { 
	$varRunning = Test-NetConnection -ComputerName $dependonHost -Port $dependonPort
	$isconnected = $varRunning.TcpTestSucceeded
	if (-not $isconnected){
		Start-Sleep $timeretry
		$timeused += $timeretry
	} else {
		# Need to use Write-Output since invoked by Workflow
		$today = Set-TimeNow
		Write-Output ("{0} [Info]: Connected to {1} at port {2} in {3}s" -f $today,$dependonHost,$dependonPort,$timeused)
	}
	if (-not ($timeused -lt $timeout)){
		# Need to use Write-Output since invoked by Workflow
		$today = Set-TimeNow
		Write-Output ("{0} [Error]: Failed to Connect to {1} at port {2} in {3}s" -f $today,$dependonHost,$dependonPort,$timeout)
	}
	
	}
} 

# Module: to write log
Function Set-VAILog {  
    <#  
    .Synopsis  
        Write the log with content  
          
    .Description  
        Write the log with content to add more information   
          
    .Notes  
        Author        : Peter Tan <tanp@vmware.com>  
        Blog        : 
        Source        : 
        Version        : 1.0 - 2016/11/16 - Initial release  

        #Requires -Version 2.0  
          
    .Inputs  
        System.String  
          
    .Outputs  
        System.String

    .Parameter LogString
        Specifies the log string.  
	
    .Parameter LogLevel
        Specifies the log level (Info, Warning, Error).  
		
    .Parameter LogFile
        Specifies whether to send log to log file.  
        
    .Example  
        Set-VAILog "This is Error Message" "Error" "C:\mylogfile.log" 
        -----------  
        Description  
        Writes the log to c:\mylogfile.log with specified content and Error level
        
    .Example  
        Set-VAILog "This is Info Message"
        -----------  
        Description  
        Writes the log to console with specified content and Info leve (default)
      
    .Example  
        $logstring | Set-VAILog 
        -----------  
        Description  
        Writes the log to console with passed through the pipe  
         
    .Link  
        None  
    #>  
      
    [CmdletBinding()]  
    Param(  
		[ValidateNotNullOrEmpty()]  
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]  
        [string]$LogString,
		
		[AllowEmptyString()]  
        [Parameter(ValueFromPipeline=$False,Mandatory=$False)]  
        [string]$LogLevel,

		[AllowEmptyString()]  
        [Parameter(ValueFromPipeline=$False,Mandatory=$False)]  
        [string]$LogFile
    )  
      
    Begin  
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"}  
          
    Process  
    {  
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing string: $LogString"  
		
		# Set Default LogLeve to Info
		if (($LogLevel -eq "") -or ($LogLevel -eq $null)) {$LogLevel = "Info"}

		# Add TimeStamp
		$today = Set-TimeNow
		
		# Format Log String
		$mystring = "{0} [{1}]: {2}" -f $today, $LogLevel, $LogString
		
		if (($LogFile -eq "") -or ($LogFile -eq $null)) { 
			Write-Host $mystring 
		}else {
			# Create Log file if not existing
			if (-Not (Test-Path $LogFile)) {
				New-Item $LogFile -ItemType file -Force
			}
			# Write to Log file
			Write-Host $mystring >> $LogFile
		}
		
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing string: $LogString"  
    }  
          
    End  
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}  
} 

# Module: to set current time with format
Function Set-TimeNow {
	$mytime = date -Format yyyyMMdd-HHmmss
	return $mytime
}

########################################
###### Functions Used by Installer #####
########################################

	# 00 Read config file
Function Get-VAIConfig($vmType, $vmName, $cfgdata, $mydomain) {

	$varCfgVMs = $mydomain.TaskVMList
	$csvdata = import-csv $varCfgVMs
	$ips = Get-WmiObject win32_networkadapterconfiguration | where{($_.Ipaddress.length -gt 0) -and ($_.DefaultIPGateway.length -gt 0)} 
	$vmip = $ips.Ipaddress[0]
	# Get config via Hostname or IP Address
	$varComputers = $csvdata | Where-Object {$_.InstallerType -like ("*" + $vmType + "*")} | Where-Object {($_.ComputerName -like ($vmName + ".*")) -or ($_.ComputerName -eq $vmip)}

    if ($varComputers -eq $null) {
    	Set-VAILog " No Config Entry found, cancel the task!"
		exit(1)
    }

	# Set Vars, pick last one if multi line
    if ($varComputers.Count -ne $null) { $varComputers = $varComputers[$varComputers.Count -1]}

	# We support multiType for InstallerType
	$varMultiTypes = $varComputers.InstallerType.Split(',')

	# Determin Install Type and save to collection
	$myInstallCollection = @()
	foreach ($varOneType in $varMultiTypes) {
	    #$myInstallItem = "" | Select-Object PreInstall,PostInstall,InstallerPatten,InstalledName,InstallerCert,InstallerLicense,InstallerArg,ReInstallArg      
		$varInstallArg = $cfgdata[$varOneType]
        
		# Set Vars per $varType, Skip if could not find the type
        if ($varInstallArg -ne $null) { 
		<# $myInstallItem.PreInstall = $varInstallArg.PreInstall
		$myInstallItem.PostInstall = $varInstallArg.PostInstall
		$myName = hostname
		$myBit = Get-WmiObject win32_processor -ComputerName $myName | Select-Object AddressWidth
		if ($myBit.AddressWidth -eq 64) {
		$myInstallItem.InstallerPatten = $varInstallArg.InstallerPatten64
		} else {
		$myInstallItem.InstallerPatten = $varInstallArg.InstallerPatten32
		}
		$myInstallItem.InstalledName = $varInstallArg.InstalledName
		$myInstallItem.InstallerCert = $varInstallArg.InstallerCert
		$myInstallItem.InstallerLicense = $varInstallArg.InstallerLicense
		$myInstallItem.InstallerArg = $varInstallArg.InstallerArg
		$myInstallItem.ReInstallArg = $varInstallArg.ReInstallArg #>
			$myInstallCollection+=$varInstallArg
		}
	}
	return $varComputers,$myInstallCollection
}

	# 01 PreInstall : install prerequirement one by one
Function Start-VAIPrePostInstall($varPrePostInstall) {
	if ($varPrePostInstall -ne "") {
	$prepostInst = $varPrePostInstall.split(',')
	if ($prepostInst.count -gt 0) {
		$prepostInst | foreach-object { 
		if (test-path $_){
			# It is script file, such as ..\tools\SVIPreInstall\SVIPreInstall.bat or CSPostInstall\CSPostInstall.bat
			# We copy whole folder to temp and execute
			Set-VAILog "Customized Installation via Script: `"$_`"." 
			$scriptfile = $_.split('\')[-1]
		    $folderItem = Split-Path $_
			$scriptfolder = $folderItem.split('\')[-1]  
			Copy-Item $folderItem $env:temp -Force -Recurse
			$varPrePostInstall = ("{0}\{1}\{2}" -f $env:temp,$scriptfolder,$scriptfile) 
			Set-VAILog "Customized Installation via Script: `"$varPrePostInstall`"." 
			& $varPrePostInstall
		}elseif ($_ -eq "RDS-RD-Server") {
			Set-VAILog "Add-WindowsFeature via PS: `"$_`"." 
			Import-Module Servermanager
			Add-WindowsFeature $_ -Restart
		}
		else {
			Set-VAILog "Add-WindowsFeature via DISM: `"$_`"." 
			dism /online /enable-feature /all /featurename:$_ /Quiet
		}
		}
	}

	}
}

	# 02 Get Installer File via $varInstallerPatten and $varInstallerFolder
Function Get-VAIFileName($varInstallerFiles, $varInstallerPatten) {
	$varInstallerFiles = Get-ChildItem .. -Recurse -Include $varInstallerPatten
	# If no new installer files found, exit instavarInstallerPattenllation    
	if ($varInstallerFiles -eq $null) {
	Set-VAILog " No Installer File found, cancel the task!"
	exit(1)
	} 
    
    if ($varInstallerFiles.Count -ne $null) { $varInstallerFiles = $varInstallerFiles[$varInstallerFiles.Count -1]}
	$varFileName = $varInstallerFiles.FullName

	return $varFileName
}

	# 03 Version Check : Compare Version of File and Installed one
Function Get-VAIVersions($varFileName, $varInstalledName) {
	$varFileVer = (dir $varFileName).versioninfo | select ProductVersion
	$varFileVer = $varFileVer.ProductVersion.substring(6)

	Wait-OtherInstaller("msiexec")
	$varInstalledProduct = Get-WmiObject -Class win32_product | Where-Object {$_.name -like $varInstalledName.split(',')[0]}
    if ($varInstalledProduct -ne $null){
	    $varInstalledVer = $varInstalledProduct.Version.substring(6)
        $varIdentifyingNumber = $varInstalledProduct.identifyingNumber 
    } else {
        $varInstalledVer ="None"
        $varIdentifyingNumber = "None"
    }
	
	return $varFileVer,$varInstalledVer,$varIdentifyingNumber
}

	# 04 Uninstall
Function Start-VAIUninstall($varInstalledName, $varUninstallExceptions) {
	foreach ($varInstalled in $varInstalledName.split(',')){
	    if ($varUninstallExceptions -notcontains $varInstalled){
		Wait-OtherInstaller "msiexec"
		Set-VAILog ("Uninstalling {0}!" -f $varInstalled)
		$varInstalledProduct = Get-WmiObject -Class win32_product | Where-Object {$_.name -like $varInstalled }
		$varUninstall = $varInstalledProduct.Uninstall()
		Set-VAILog ("Uninstall result is {0}!" -f $varUninstall)
	}
	}
}

	# 05 Installation
Function Start-VAIInstall($varFileName, $varInstallerArg, $varInstallerCert, $varServerName) {

	# Replace the placeholder via Variables, such as ServerName
	$varInstallerArg = $varInstallerArg.Replace("ServerName", $varServerName)
	# Import Publisher Certificate to avoid security popup during installation
	certutil -f -addstore "TrustedPublisher" $varInstallerCert

	Wait-OtherInstaller "msiexec"
	Set-VAILog ("Installing {0} {1}!" -f $varFileName,$varInstallerArg)
	# Write command to bat
	$varBat = $varFileName + ".bat"
	if (Test-Path $varBat) {Remove-Item $varBat -Force}
    
    $varCMD = $varFileName +" "+ $varInstallerArg
   	Add-Content $varBat $varCMD
	$varInstall = Start-Process -FilePath $varBat -wait -NoNewWindow
	Set-VAILog ("Install result is {0}!" -f $varInstall)
}

	# 06 Module: to wait for other process to avoid conflict
Function Wait-OtherInstaller ($procName) {
	if ($procName -eq '') { $procName = 'msiexec' } 
	while ($true) { 
	Start-Sleep 1
	try {
		$varRunning = get-process $procName -ErrorAction SilentlyContinue | select ProcessName | findstr $procName 
		if (($varRunning -eq $null) -or ($varRunning[0] -eq 'm')) { break} 
	} catch {}

	}
}

	# 07 Module: to copy all required files to local
Function Start-CopyInstaller ($varFileName, $varInstallerCert, $varInstallerLicense) {
		# Copy to Temp folder to ensure execution speed
		Set-VAILog ("Coping Installer File {0}" -f $varFileName)
		$fileItem = Get-Item $varFileName
		Copy-Item $fileItem $env:temp -Force
		$varFileName = Join-Path $env:temp $fileItem.Name
		Set-VAILog ("Copied Installer File to {0}" -f $varFileName)

		# Also copy Cert if required
		if (($varInstallerCert -ne "") -and ($varInstallerCert -ne $null)){
			if (test-path $varInstallerCert) {
				Set-VAILog ("Coping Cert File {0}" -f $varInstallerCert)
				$certItem = Get-Item $varInstallerCert
				Copy-Item $certItem $env:temp -Force
				$varInstallerCert = Join-Path  $env:temp $certItem.Name
				Set-VAILog ("Copied Cert File to {0}" -f $varInstallerCert)
			} else {
				Set-VAILog ("Unable to locale License File from {0}" -f $varInstallerCert)
			}
		}

		# Also copy license if required
		if (($varInstallerLicense -ne "") -and ($varInstallerLicense -ne $null)){
			if (test-path $varInstallerLicense) {
				Set-VAILog ("Coping License File {0}" -f $varInstallerLicense)
				$licItem = Get-Item $varInstallerLicense
				Copy-Item $licItem $env:temp -Force
				$varInstallerLicense = Join-Path $env:temp $licItem.Name
				Set-VAILog ("Copied License File to {0}" -f $varInstallerLicense)
			} else {
				Set-VAILog ("Unable to locale License File from {0}" -f $varInstallerLicense)
			}
		}
				
		Return $varFileName, $varInstallerCert, $varInstallerLicense
}



########################################
###### Functions Used by TaskSched #####
########################################

# Module: to write config value to template xml file which used for Windows Task Scheduler
Function Set-TaskXML {
  param(
    [Parameter(Mandatory = $true)]
    $cfgini,
    [Parameter(Mandatory = $true)]
	[AllowEmptyString()] [String]
    $domainname
  )
	if (($cfgini -eq "") -or ($cfgini -eq $null)) { $cfgini = "..\config\cfg-env.ini"}
	if (($domainname -eq "") -or ($domainname -eq $null)){ $domainname = "DefaultDomain"}

	# Read config file and get list of your XML files to customize
	$cfgdata = Get-IniContent $cfgini
	$mydomain =  $cfgdata.item($domainname)
	$MyUserwithDomain = $mydomain.Domain + "\" + $mydomain.Username	
	
	$varTaskXMLPath = $mydomain.TaskXMLTemplate 
	$varXMLFiles =  (dir $varTaskXMLPath | select Name)
	
	# Specify your config file and the path to your XML files here
	# Search and Replace to customize Task XML
	# Replace the login info which is used to connect network path (for installer file access )
	# \\Win7JPAuto.viewdep.g11n\share601 ca$hc0w /user:viewdep\administrator
	# (\\\\[^ ]{1,}\\[^ ]{1,}) ([^ ]{1,}) /user:([^ ]{1,}) 
	Set-VAILog ("Customize Task Definiation XML files in {0}!" -f $varTaskXMLPath)
	foreach ($varXMLFile in $varXMLFiles) {
	$varFilePath = $varTaskXMLPath + "\" + $varXMLFile.Name
	(Get-Content $varFilePath) -replace `
		"(\\\\[^ ]{1,}\\[^ ]{1,}) ([^ ]{1,}) /user:([^ ]{1,})", "$($mydomain.DomainShareFolder) $($mydomain.Password) /user:$($MyUserwithDomain)" |
		Out-File $varFilePath
	}

}

# Module: to distribute Windows Task to each VM
Function Set-TaskSched ($mydomain, $executenow, $scriptPath, $vmName, $vmType) {

	if (($mydomain -eq $null) -or ($mydomain -eq "")) {
	$cfgini = "..\config\cfg-env.ini"
	$cfgdata = Get-IniContent $cfgini
	$mydomain =  $cfgdata.DefaultDomain 
	}
	if (($executenow -eq $null) -or ( $executenow -eq "" )) { $executenow= "No"}
	if (($vmName -eq $null) -or ($vmName -eq "")) { $vmName = "*"}
	if (($vmTye -eq $null) -or ($vmType -eq "")) { $vmType = "*"}
	if (($scriptPath -eq $null) -or ($scriptPath -eq "")) { $scriptPath = $pwd}

	# Get list of your XML files to customize
	$MyLogFolder = Join-Path $mydomain.LogFolder $mydomain.Domain
    $MyUserwithDomain = $mydomain.Domain + "\" + $mydomain.Username
	$varTaskXMLPath = $mydomain.TaskXMLTemplate 
	$varCfgVMs = $mydomain.TaskVMList

	# Read config file and get list of your XML files to customize
	$csvdata = import-csv $varCfgVMs
	$varComputers = $csvdata | Where-Object {$_.InstallerType -like ($vmType + "*")} | Where-Object {$_.ComputerName -like ($vmName +"*")}

	# Schedule Task and Execute per $varExecuteNow
	Set-VAILog ("Start Workflow to distribute Tasks to {0} VMs List in {1}!" -f $varComputers.count,$varCfgVMs)
	Set-VAITasksWF $mydomain $executenow $varComputers $scriptPath
}

workflow Set-VAITasksWF ($mydomain, $executenow, $varComputers, $scriptPath) {
	foreach -parallel ($varComputer in $varComputers) {
		Set-VAITaskFunc $mydomain $executenow $varComputer $scriptPath
	}
}

Function Set-VAITaskFunc ($mydomain, $executenow, $varComputer, $scriptPath) {

	# Import VAI Helper Module 
	Import-Module .\VAI.Helper.psm1
	# Log Output
	$MyLogFolder = Join-Path $mydomain.LogFolder $mydomain.Domain
	$MyInstallResults = Join-Path $MyLogFolder "InstallResults.csv"
	
	$MyUserwithDomain = $mydomain.Domain + "\" + $mydomain.Username
	$varTaskXMLPath = $mydomain.TaskXMLTemplate 
	$myFolder = Join-Path $MyLogFolder $varComputer.ComputerName
	# Switch folder back to current path
	$today = Set-TimeNow
	cd $scriptPath
	# Need to use Write-Output since invoked by Workflow
	Write-Output ("{0} [Info]: Current Path: {1}" -f $today,$pwd)
	if (-Not (Test-Path $myFolder)) {New-Item $myFolder -ItemType directory}
	$myLog = "Set-TaskSched" + $varComputer.ComputerName + ".log"
	$myBat = "Set-TaskSched" + $varComputer.ComputerName + ".bat"
	$varLogs = Join-Path $myFolder $myLog
	$varBat = Join-Path $myFolder $myBat

	# Change old $varBat & $varLogs
	if (test-path $varBat){
		$oldBat = get-item -path $varBat
		rename-item $oldBat ($oldBat.Name+"-"+$today)
	}
	if (test-path $varLogs){
		$oldLogs = get-item -path $varLogs
		rename-item $oldLogs ($oldLogs.Name+"-"+$today)
	}
	
	#$varSchtasks = $env:SystemRoot + "\system32\schtasks.exe"
	$vmName = hostname
	$vmFullName = $vmName + "." + $mydomain.Domain
	$ips = Get-WmiObject win32_networkadapterconfiguration | where{($_.Ipaddress.length -gt 0) -and ($_.DefaultIPGateway.length -gt 0)} 
	$vmip = $ips.Ipaddress[0]
	if (($vmip -eq $varComputer.ComputerName) -or ($vmFullName -eq $varComputer.ComputerName)){
		$varCMD = ""
	} else {
		$varCMD = "/s {0} /u {1} /p {2}" -f  $varComputer.ComputerName,$MyUserwithDomain,$mydomain.Password
	}
	$varCMDCreateHorizonInstall = "schtasks.exe /create {0} /tn HorizonInstall /xml {1}\HorizonInstall.xml /ru {2} /rp {3} /F >> {4}" -f $varCMD,$varTaskXMLPath,$MyUserwithDomain,$mydomain.Password, $varLogs
	$varCMDCreateHorizonReboot = "schtasks.exe /create {0} /tn HorizonReboot /xml {1}\HorizonReboot.xml /ru {2} /rp {3} /F >> {4}" -f $varCMD,$varTaskXMLPath,$MyUserwithDomain,$mydomain.Password, $varLogs 
	$varCMDChangeHorizonReboot = "schtasks.exe /change {0} /tn HorizonReboot /st  {1} /ru {2} /rp {3} >> {4}" -f $varCMD,$varComputer.Time,$MyUserwithDomain,$mydomain.Password, $varLogs

	$varCMDRunHorizonReboot = "schtasks.exe /run {0} /tn HorizonReboot >> {1}" -f $varCMD, $varLogs
	$varCMDRunHorizonInstall = "schtasks.exe /run {0} /tn HorizonInstall >> {1} " -f $varCMD, $varLogs
	
	$varCMDCleanHorizonInstall = "schtasks.exe /delete {0} /tn HorizonInstall /F >> {1}" -f $varCMD, $varLogs
	$varCMDCleanHorizonReboot = "schtasks.exe /delete {0} /tn HorizonReboot /F >> {1}" -f $varCMD, $varLogs

	$varCMDDisableHorizonInstall = "schtasks.exe /change {0} /tn HorizonInstall /Disable >> {1}" -f $varCMD, $varLogs
	$varCMDDisableHorizonReboot = "schtasks.exe /change {0} /tn HorizonReboot /Disable >> {1}" -f $varCMD, $varLogs
	
	##
	## output to Set-TaskSched.bat file and execute via bat
	##
	switch ($executenow) {
		# Command if choose to Execute right after command, caution to use without any vmName & vmType filter, or the host would be very busy
		"force" {
		Add-Content $varBat $varCMDCreateHorizonInstall
		Add-Content $varBat $varCMDCreateHorizonReboot
		Add-Content $varBat $varCMDChangeHorizonReboot
		Add-Content $varBat $varCMDRunHorizonInstall
		}
		# Command if choose to Execute right after command, caution to use without any vmName & vmType filter, or the host would be very busy
		"yes" {
		Add-Content $varBat $varCMDCreateHorizonInstall
		Add-Content $varBat $varCMDCreateHorizonReboot
		Add-Content $varBat $varCMDChangeHorizonReboot
		if (($varComputer.DependOnHostAndPort -eq "") -or ($varComputer.DependOnHostAndPort -eq $null)) {
			Add-Content $varBat $varCMDRunHorizonInstall
		} else {
			Wait-ServerConnection $varComputer.DependOnHostAndPort
			Add-Content $varBat $varCMDRunHorizonInstall
		}
		}
		# Command if choose to Execute right after command after reboot, caution to use without any vmName & vmType filter, or the host would be very busy
		"reboot" {
		Add-Content $varBat $varCMDCreateHorizonInstall
		Add-Content $varBat $varCMDCreateHorizonReboot
		Add-Content $varBat $varCMDChangeHorizonReboot
		Add-Content $varBat $varCMDRunHorizonReboot
		}
		#Command to delete the scheduled tasks on VM
		"clean" {
		Add-Content $varBat $varCMDCleanHorizonInstall
		Add-Content $varBat $varCMDCleanHorizonReboot
		}
		#Command to disable the scheduled tasks on VM
		"disable" {
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

	# Execute $varBat 
	# Need to use Write-Output since invoked by Workflow
	Write-Output ("{0} [Info]: Execute {1} which log file is {2}!" -f $today,$varBat,$varLogs)
	& $varBat
	
	# Let's monitor the progress if Yes or Force
	if (($executenow -eq "force") -or ($executenow -eq "yes")) {
			Write-Output ("{0} [Info]: Set Execution Status of {1} to monitor file {2}!" -f $today,$varComputer.ComputerName,$MyInstallResults)
			$ReportHeader = "ComputerName,TaskStatus,StartedAt,CompletedAt,TimeUsed"
			$varCMD = "/s {0} /u {1} /p {2}" -f  $varComputer.ComputerName,$MyUserwithDomain,$mydomain.Password

			$mytaskstatus = Get-TaskStatus $varComputer.ComputerName $MyUserwithDomain $mydomain.Password
			#$mytaskstatus
			$ReportEntry = ("{0},{1},{2},{3},{4}" -f $varComputer.ComputerName,$mytaskstatus,$today,"","")
			if (-not (Test-Path $MyInstallResults))	{
				Add-Content $MyInstallResults $ReportHeader
			}
			Add-Content $MyInstallResults $ReportEntry
	}

}
# Module: to get Task status of HorizonInstall
Function Get-TaskStatus {
param(
    [Parameter(Mandatory = $false)] $ComputerName,
	[Parameter(Mandatory = $false)] $UserName,
	[Parameter(Mandatory = $false)] $Password,
	[Parameter(Mandatory = $false)] $TaskName
  )
  
   	if (($TaskName -eq $null) -or ( $TaskName -eq "" )) { $TaskName= "HorizonInstall"}
	# By Default, WinRM is not enabled by Windows 7/10, use schtasks instead
 	if (($ComputerName -eq $null) -or ( $ComputerName -eq "" )) {
		# Query task on local host
		$varCMD = "schtasks /query /tn {1} | findstr {1}" -f  $ComputerName,$UserName,$Password,$TaskName
	} else {
		# Query task on remote host
		$varCMD = "schtasks /s {0} /u {1} /p {2} /query /tn {3} | findstr {3}" -f  $ComputerName,$UserName,$Password,$TaskName
	}
	$myscptTaskStatus = [scriptblock]::Create($varCMD)	
	$mystatus = Invoke-Command -ScriptBlock $myscptTaskStatus
	$mystatus=$mystatus.trimend().split(" ")[-1]
	Return $mystatus
}


# Module: to add certain host to VM list
Function Set-TaskVMs {
param(
    [Parameter(Mandatory = $true)] $ComputerName,
	[Parameter(Mandatory = $false)] $InstallerType,
    [Parameter(Mandatory = $false)] $DependOnHostAndPort,
    [Parameter(Mandatory = $false)] $Time,
	[Parameter(Mandatory = $false)] $cfgini,
    [Parameter(Mandatory = $false)] $executenow,
	[Parameter(Mandatory = $false)] $domainname
  )
 	if (($ComputerName -eq $null) -or ( $ComputerName -eq "" )) {
		Set-VAILog " No ComputerName set, cancel the task!"
		return
	} 
   	if (($InstallerType -eq $null) -or ( $InstallerType -eq "" )) { $InstallerType= "Agent"}
  	if (($Time -eq $null) -or ( $Time -eq "" )) { $Time= "03:00"}
	if (($cfgini -eq $null) -or ($cfgini -eq "")) { $cfgini = "..\config\cfg-env.ini"}
	if (($executenow -eq $null) -or ($executenow -eq "")) { $executenow = "no"}
	if (($DependOnHostAndPort -eq $null) -or ($DependOnHostAndPort -eq "")) { $DependOnHostAndPort = ""}
	if (($domainname -eq "") -or ($domainname -eq $null)){ $domainname = "DefaultDomain"}

	# Read config file and get list of your XML files to customize
	$cfgdata = Get-IniContent $cfgini
	$mydomain =  $cfgdata.item($domainname)
	$varCfgVMs = $mydomain.TaskVMList
	$varVMInfo = ("{0},{1},{2},{3}" -f $Time,$ComputerName,$InstallerType,$DependOnHostAndPort)
	# Backup
	$today = Set-TimeNow
	Copy-Item $varCfgVMs ($varCfgVMs+"-"+$today) -Force
	# Add new VM row, Sort and Remove Duplicated Rows
	Add-Content $varCfgVMs $varVMInfo
	Get-Content $varCfgVMs | sort -Descending -Unique | Set-Content -Path $varCfgVMs

}


Export-ModuleMember Set-TaskXML, Set-TaskSched, Set-TaskVMs, Set-VAILog, Set-TimeNow, `
	Get-IniContent, Get-JsonContent, Get-TaskStatus, Get-VAIConfig, Get-VAIFileName, Get-VAIVersions, `
	Start-VAIPrePostInstall, Start-VAIUninstall, Start-VAIInstall, Start-CopyInstaller, `
	Wait-OtherInstaller, Wait-ServerConnection
