# Set-RestrictedDesktopAccess

This script is used to change the access control on a user's desktop folder so that only the administrator can modify it. The user can still open/execute shortcuts but not change the
content of the desktop folder.

## Details

The file receive the name of a local user as an argument. There is autocompletion to avoid bad entries. **The execution needs to be done as admin**

Then the function resolve the user desktop folder, will get the list of files and sub folders and change the ACLs, and remove the inheritance.

## Reset-AccessRights

This function will revert the changes done by ```Set-RestrictedDesktopAccess``` by re-enabling inheritance and purging the added acls.

## How To Use

### to *test* before **-WhatIF**
```
    # This is for a TEST (will not change anything) -- RECOMMENDED BEFORE DOING SOMETHING MORE  
    $Changed = .\Set-RestrictedDesktopAccess.ps1 -UserName JohnDoe -WhatIf -Verbose
    # List the changes
    $Changed
```


```
    # as administrator
    $Changed = .\Set-RestrictedDesktopAccess.ps1 -UserName JohnDoe
```

## On Error or to reset the access rights

```
	$Path = "c:\Users\JohnDoe\Desktop"
    .\Reset-AccessRights.ps1 -Paths $Objects -Owner Johndoe
```  


## DEMO

![Demo](https://raw.githubusercontent.com/arsscriptum/PowerShell.Reddit.Support/main/SetDesktopRights/img/demo.gif)