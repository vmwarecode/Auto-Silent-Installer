#Script Name	: VAI
#Version		: 1.0
#License		: MIT
#Author			: tanp@vmware.com

########################################
###### Scripts Installation ############
########################################
param(
  [Parameter(Mandatory=$True)][AllowEmptyString()] [String]
  $executenow,
  [Parameter(Mandatory=$True)][AllowEmptyString()] [String]
  $vmName,
  [Parameter(Mandatory=$True)][AllowEmptyString()] [String]
  $vmType,
  [Parameter(Mandatory=$False)][AllowEmptyString()] [String]
  $cfgini,
  [Parameter(Mandatory=$False)][AllowEmptyString()] [String]
  $domainname
  )
  
  # Initialize paras if no input from command
  if (($cfgini -eq "") -Or ($cfgini -eq $null))  { $cfgini = "..\config\cfg-env.ini"}
  if (($domainname -eq "") -Or ($domainname -eq $null)) { $domainname = "DefaultDomain"}
  if (($executenow -eq "" ) -Or ($executenow -eq $null)) { $executenow= "no"}
  
  
  # Import VAI Helper Module 
  Import-Module .\VAI.Helper.psm1

  # Read Config
  $cfgdata = Get-IniContent $cfgini
  $mydomain =  $cfgdata.item($domainname)
  $MyLogFolder = $mydomain.LogFolder

  # Log Output
  $myhost = hostname
  $myFolder = Join-Path $MyLogFolder $myhost
  if (-Not (Test-Path $myFolder)) {New-Item $myFolder -ItemType directory}
  $today = Set-TimeNow
  $myLog = $myhost + "-VAITasks-"+ $today +".log"
  $varLogs = Join-Path $myFolder $myLog
  Start-Transcript $varLogs -Force
  
  # Cusomize Task Defination in XML
  # Also create Scheduled task 
  Set-TaskXML $cfgini $domainname
  
  $scriptPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
  Set-VAILog ("Script Path: {0}" -f $scriptPath)
  Set-TaskSched $mydomain $executenow $scriptPath $vmName $vmType

  # log End
  Stop-Transcript
