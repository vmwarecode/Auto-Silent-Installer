Requiements:
	Controller PC: Windows 2012R2 or Windows 2008R2 with Powershell 3.0 or later
	Target VMs/PCs: Windows 7 or later

Note: Please ensure All running PCs could access each other. It is recommended for All PCs in the same Domain or Firewall configured.

Config:
*********************************
1, Customize config\cfg-env.ini
[DefaultDomain]
LogFolder = ..\logs
DomainShareFolder = \\10.117.163.217\share\vai
DomainController = 10.117.160.41
Domain = g11nqe.vmware.com
Username = viewadmin
Password = a
TaskXMLTemplate = ..\config\TaskXML
TaskVMList = ..\config\cfg-vms.csv
UninstallExceptions = VMwareVDMDS

*********************************
2, Customize Installer Type via adding sections in config\cfg-env.ini
[SVI]
InstallerType = SVI			>> Specify the name of installation type, such as Horizon Composer, I named as SVI.
PreInstall = SVIPreInstall  >> Preinstall Script (Name is like *PreInstall which invoke bat\*PreInstall.bat, you can easily extend your own PreInstall script) or It is a list of Windows Pre-insallation which could be added by Powershell one line command. "dism /online /get-features /format:table" could help you to find the list.
PostInstall = .\SetSSPassword.bat >> PostInstall Script, always invoke bat\*, for this case, it is bat\SetSSPassword.bat
InstallerPatten32 = *VMware*composer*.exe	>> Name Patten to find 32bit installer file
InstallerPatten64 = *VMware*composer*.exe	>> Name Patten to find 64bit installer file
InstalledName = *Horizon*Composer*			>> Name Patten to find Product Installed Name, used for installation verification
InstallerCert = ..\config\TrustedCert\VMwareInstaller.cer	>> If any Cert to import to avoid security alert
InstallerArg = /s /v /qn RebootYesNo=Yes DB_DSN=svi DB_USERNAME=sa DB_PASSWORD=Passw0rd		>> 	Normal Silent Installation Args
ReInstallArg = /s /v /qn RebootYesNo=Yes DB_DSN=svi DB_USERNAME=sa DB_PASSWORD=Passw0rd		>> 	Silent Re-Installation Args

*********************************
3, Add the Computer List
A: config\cfg-vms.csv is to list Computers for operation.
B: Below is the sample
  
Sample:
Time,UserName,Password,ComputerName,InstallerType,InstallerFolder,ServerName,ServerDB,ServerUser,ServerPassword,LicenseFile
Time,ComputerName,InstallerType,DependOnHostAndPort
02:00,zzhuocs.g11nqe.vmware.com,CS,
rm,RDSH2012.g11nqe.vmware.com,RDSH,zzhuocs.g11nqe.vmware.com:443
03:00,SVI2016.g11nqe.vmware.com,SVI,

** a: Time
*1** If nomal time specified, the installation task happen on that time, note: You MUST specify like 02:30 which is 24hour-Format.
*2** if 'rm' specified, the uninstallation task will be execute next time 

** b: InstallType
You can spedify one ore more instal type as you want, use ',' as seperator. Like: "Agent,Client"


IMPORTANT NOTES: to balance the workload of hosts, it is strongly recommended for you to specify reasonable Time for each entry.


Execute:
*********************************
1, Distribute Tasks to VMs and execute per schedule
bat\VAI-Tasks.bat

2, Distribute Tasks to VMs and execute now
bat\VAI-Tasks.bat force

3, Distribute Tasks to VMs and execute after reboot
bat\VAI-Tasks.bat yes


