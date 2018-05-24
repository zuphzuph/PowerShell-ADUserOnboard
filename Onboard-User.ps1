$username = "luser"
$firstname = "l"
$lastname = "user"
$domain = "@email.com"
$office = "Office/Branch Location"
$jobtitle = "Test Dummy"
$telephonenumber = "(XXX)XXX-XXXX"
$description = "Desc for Account in AD"
$logonscript = "Runs upon login, often inclues mapped shares."
$homedriveletter = "Drive Letter"
$homedirpath = "\\pathtohome\share"

New-ADUser -Name "$username" -GivenName "$firstname" -Surname "$lastname" `
-Path "OU=end,OU=to,OU=start,DC=www,DC=google,DC=com" `
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
-PassThru | Enable-ADAccount `
