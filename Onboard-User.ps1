$username = "luser"
$firstname = "l"
$lastname = "user"
$domain = "@email.com"
$office = "Office/Branch Location"
$jobtitle = "Test Dummy"
$telephonenumber = "(XXX)XXX-XXXX"
$description = "Title or Info"
$logonscript = "filename.ps1"
$homedriveletter = "Drive Letter"
$homedirpath = "\\pathtohome\share\"
$mirrorgroupsfrom = "User to inherit AD groups from."

New-ADUser -Name "$username" -GivenName "$firstname" -Surname "$lastname" `
-Path "OU=end,OU=to,OU=start,DC=internal,DC=domain,DC=com" `
-EmailAddress ("$username" + "$domain") `
-OfficePhone ($telephonenumber) `
-AccountPassword (Read-Host -AsSecureString "AccountPassword") `
-Office ($office) `
-Title ($jobtitle) `
-Description ($description) `
-ScriptPath ($logonscript) `
-HomeDrive ($homedriveletter) `
-HomeDirectory ("$homedirpath" + "$username") `
-UserPrincipalName ("$username" + "$domain") `
-PassThru | Enable-ADAccount
Get-ADUser -Identity ("$mirrorgroupsfrom") -Properties memberof |`
Select-Object -ExpandProperty memberof |`
Add-ADGroupMember -Members ("$username")
