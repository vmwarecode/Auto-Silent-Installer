# Specify your config file and the path to your XML files here
$varCfgShare = "..\config\cfg-share.csv"
$varTaskXMLPath = "..\config\TaskXML"

# Read config file and get list of your XML files to customize
$csvdata = import-csv $varCfgShare
$varXMLFiles =  (dir $varTaskXMLPath | select Name)

# Search and Replace to customize Task XML
foreach ($varXMLFile in $varXMLFiles) {

$varFilePath = $varTaskXMLPath + "\" + $varXMLFile.Name

# Replace to login info which is used to connect network path (for installer file access )
# \\Win7JPAuto.viewdep.g11n\share601 ca$hc0w /user:viewdep\administrator
# (\\\\[^ ]{1,}\\[^ ]{1,}) ([^ ]{1,}) /user:([^ ]{1,}) 

(Get-Content $varFilePath) -replace `
	"(\\\\[^ ]{1,}\\[^ ]{1,}) ([^ ]{1,}) /user:([^ ]{1,})", "$($csvdata.Folder) $($csvdata.Password) /user:$($csvdata.UserName)" |
	Out-File $varFilePath


}

