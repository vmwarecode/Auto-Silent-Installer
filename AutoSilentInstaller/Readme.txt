Note: Please ensure All running PCs could access each other. It is recommended for All PCs in the same Domain or Firewall configured.


1, Shared Folder: which hold builds and the scripts
A:  \\MyServer.Domain.com\MyShare	(Do not use PC, use a Server OS if more than 20 PCs to install)
B: Specify access info in config file "cfg-share.csv" and Execute bin\Set-TaskXML.bat 


2, Distribute Scheduled Tasks
A: Execute Set-TaskSched.bat
B: Check Logs\Set-TaskSched_cmd.log for results


3, Add the Installer support
A: config\cfg-installertype.csv is extend Installation Type.
InstallerType	Specify the name of installation type, such as Horizon Agent, I named as Agent.
PreInstall	It is a list of Windows Pre-insallation which could be added by Powershell one line command. "dism /online /get-features /format:table" could help you to find the list.
InstallerPatten32	Installer Patten for 32bit OS
InstallerPatten64	Installer Patten for 64bit OS
InstalledName	The Product Name patten after installation
InstallerCert	If any Software Vendor Certification which could be imported to ensure success of silent install
InstallerArg	Silent Installation Arguments


4, Add the Computer List
A: config\cfg-vms.csv is to list Computers for operation.
B: Below is the sample
   
Sample:
Time,UserName,Password,ComputerName,InstallerType,InstallerFolder,ServerName,ServerDB,ServerUser,ServerPassword,LicenseFile
02:30,g11nqe.vmware.com\viewadmin,a,Agent10CN2.g11nqe.vmware.com,"Agent,Client",..\build\,CS2k8JP.g11nqe.vmware.com,,,,
rm,g11nqe.vmware.com\viewadmin,a,RDSH2k8JP.g11nqe.vmware.com,RDSH,..\build\,CS2k8JP.g11nqe.vmware.com,,,,

** a: Time
*1** If nomal time specified, the installation task happen on that time, note: You MUST specify like 02:30 which is 24hour-Format.
*2** if 'rm' specified, the uninstallation task will be execute next time 

** b: username/password(escapeby^)
*1**  Such as $ whicho should be ^$

** c: InstallType
You can spedify one ore more instal type as you want, use ',' as seperator. Like: "Agent,Client"


IMPORTANT NOTES: to balance the workload of hosts, it is strongly recommended for you to specify reasonable Time for each entry.


