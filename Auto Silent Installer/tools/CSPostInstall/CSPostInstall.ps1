$myName = hostname
$tempLog = $env:temp + "\" + $myName + ".txt"
tzutil /g >$tempLog
tzutil /s UTC

$sspassword = '1'
$broker= hostname
$ctime = get-date -format u
$ctime = $ctime.replace('-','').replace(':','').replace(' ','').replace('Z','.0Z')

$obj = [adsi]('LDAP://localhost:389/cn='+ $broker +',ou=server,ou=properties,dc=vdi,dc=vmware,dc=int')
$obj.put('pae-SecurityServerPairingPasswordLastChangedTime',$ctime)
$obj.put('pae-SecurityServerPairingPassword',$sspassword)
$obj.put('pae-SecurityServerPairingPasswordTimeout','86400')
$obj.setInfo()

$obj = [adsi]('LDAP://localhost:389/cn=common,ou=global,ou=properties,dc=vdi,dc=vmware,dc=int')
$obj.put('pae-BypassIPSecSS','1')
$obj.setInfo()

$ctimezone = type $tempLog
tzutil /s $ctimezone

#Add License for H7
& 'C:\Program Files\VMware\VMware View\Server\extras\PowerShell\add-snapin.ps1'

Set-License -Key xxxxx-xxxxx-xxxxx-xxxxx-xxxxx