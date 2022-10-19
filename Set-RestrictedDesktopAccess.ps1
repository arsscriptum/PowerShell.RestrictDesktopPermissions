<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>




<#
.SYNOPSIS
Limits the access rights on the Desktop of a given user

.DESCRIPTION
Sets the access rights on the Desktop of a given user so that he can open shortcuts, but not modify the desktop

.PARAMETER UserName
The username to change

.OUTPUTS
The list of the files and folders that have been changed (their acls)

.EXAMPLE
  # This is for a TEST (will not change anything) -- RECOMMENDED BEFORE DOING SOMETHING MORE  
  $Changed = .\Set-RestrictedDesktopAccess.ps1 -UserName JohnDoe -WhatIf -Verbose
  # LIst the changes
  $Changed
.EXAMPLE
  $Changed = .\Set-RestrictedDesktopAccess.ps1 -UserName JohnDoe

#>

[CmdletBinding(SupportsShouldProcess)]
     param(
        # Build task(s) to execute
        [parameter(ParameterSetName = 'UserName', position = 0)]
        [ArgumentCompleter( {
            param($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)
            switch ($Parameter) {
                'UserName' {
                    if ([string]::IsNullOrEmpty($WordToComplete)) {

                        (Get-LocalUser).Name -replace '(.*\s.*)',"'`$1'"
                    }
                    else {
                        (Get-LocalUser).Name -replace '(.*\s.*)',"'`$1'" | Where-Object { $_.StartsWith($WordToComplete) }
                    }
                }
                Default {
                }
            }
        })]
        [string]$UserName = "$ENV:USERNAME"
    )

#requires -runasadministrator

function Get-LocalAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        $ComputerName = "$ENV:COMPUTERNAME"
    )
    Process {
        Foreach ($Computer in $ComputerName) {
            Try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Computer)
                $UserPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($PrincipalContext)
                $Searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
                $Searcher.QueryFilter = $UserPrincipal
                $Searcher.FindAll() | Where-Object {$_.Sid -Like "*-500"}
            }
            Catch {
                Write-Warning -Message "$($_.Exception.Message)"
            }
        }
    }
}

function Get-AdminAccountName{
    [CmdletBinding(SupportsShouldProcess)]
    param ()  

    $admin_name = (Get-LocalAdmin).Name
    if($Null -ne $admin_name){
        Write-Verbose "Admin name found 1 $admin_name"
        return $admin_name
    }
    $admin_name = (Get-LocalUser | Where Name -match "Admin").Name
    if($Null -ne $admin_name){
        Write-Verbose "Admin name found 2 $admin_name"
        return $admin_name
    }

    $culture_id = (Get-Culture).LCID
    Write-Verbose "culture lcid $culture_id"
    $admin_usr = "Administrator"
    switch($culture_id){
        # LCID = local administrator name
        # Finnish
        11    { $admin_usr = "Järjestelmänvalvoja"}
        1035  { $admin_usr = "Järjestelmänvalvoja"}
        # French
        12    { $admin_usr = "Administrateur"}
        1036  { $admin_usr = "Administrateur"}
        1033  { $admin_usr = "Administrateur"}
        # Hungarian
        14    { $admin_usr = "Rendszergazda"}
        1038  { $admin_usr = "Rendszergazda"}
        # Portuguese
        22    { $admin_usr = "Administrador"}
        1046  { $admin_usr = "Administrador"}
        2070  { $admin_usr = "Administrador"}
        # Russian
        25    { $admin_usr = "Администратор"}
        1049  { $admin_usr = "Администратор"}
        # Spanish
        10    { $admin_usr = "Administrador"}
        3082  { $admin_usr = "Administrador"}
        # Swedish
        29    { $admin_usr = "Administratör"}
        1053  { $admin_usr = "Administratör"}
        # Default, assumes "Administrator"
        default { $admin_usr = "Administrator"}
    }
    try{
        $admin_name = (Get-LocalUser | Where Name -match $admin_usr).Name
        if($Null -eq $admin_name)   {  throw "cannot get admin account name" }
        Write-Verbose "Admin name found 3 $admin_name"
        return $admin_name
    }catch{
        Write-Error $_
    }
}

function Set-RestrictedAccessRights{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [Alias('p', 'f','File')]
        [string[]]$Paths,
        [Parameter(Mandatory=$true,Position=1)]
        [Alias('u')]
        [ValidateScript({
            if ([string]::IsNullOrEmpty($_)) {
                throw "Invalid username specified `"$1`""
            }
            else {
                $Owner = $_
                $UsrOrNull = (Get-LocalUser -ErrorAction Ignore).Name  | Where-Object { $_ -match "$Owner"}
                if ([string]::IsNullOrEmpty($UsrOrNull)) {
                    throw "Invalid username specified `"$Owner`""
                }
            }
            return $true 
        })]
        [string]$Owner
    )
    Begin{
        $is_admin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
        if($False -eq $is_admin)   { throw "Administrator privileges required" } 
        $object_count = $Paths.Count
        $username = (Get-LocalUser).Name -replace '(.*\s.*)',"'`$1'" | Where-Object { $_ -match "$Owner"}
        Write-Verbose "Set-RestrictedAccessRights for owner $Owner. Num $object_count paths"

        $admin_account_name = Get-AdminAccountName
        Write-Verbose "Get-AdminAccountName => $admin_account_name"

    }
    Process{
      try{

        $usr_allow  = "$ENV:USERDOMAIN\$username"           , 'ReadAndExecute,Synchronize'  , 'none, none'  , 'None', 'Allow'
        $adm_allow  = "$ENV:USERDOMAIN\$admin_account_name"   , 'FullControl'                 , 'none, none'  , 'None', 'Allow'

        $secobj_admin_allow = New-Object System.Security.AccessControl.FileSystemAccessRule $adm_allow 
        $secobj_user_allow  = New-Object System.Security.AccessControl.FileSystemAccessRule $usr_allow 
        if($Null -eq $secobj_admin_allow)   { throw "Error on FileSystemAccessRule creation $adm_allow" }
        if($Null -eq $secobj_user_allow)    { throw "Error on FileSystemAccessRule creation $usr_allow" }
        [system.collections.arraylist]$results = [system.collections.arraylist]::new()
        ForEach($obj in $Paths){
            $userobject = New-Object System.Security.Principal.NTAccount("$ENV:USERDOMAIN", "$username")
            $acl = Get-Acl -Path $obj
            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetAccessRule($secobj_user_allow)
            $acl.AddAccessRule($secobj_admin_allow)
            $acl.SetOwner($userobject)
            Write-Verbose "Save the access rules for `"$obj`""
            # Save the access rules to disk:
            try{
                $acl | Set-Acl $obj -ErrorAction Stop
                #Write-Host "Set-RestrictedAccessRights `"$obj`""
                [void]$results.Add($obj)
            }catch{
                Write-Host "Set-Acl ERROR `"$obj`" $_" -f Red
            }
        }
        Write-Verbose "$($results.Count) paths modified"
        $results
      }catch{
        Write-Error $_
      }
    }
}

    

try{
    # From the specified user, get the desktop path
    $Path = (Resolve-Path "$HOME\..\$UserName\Desktop" -ErrorAction Ignore).Path
    if(-not(Test-Path $Path -PathType Container -ErrorAction Ignore)){  throw "could not locate Desktop for user $UserName" }

    # Get all the files to change
    $Objects = (gci $Path -recurse -File).FullName
    $Objects += (gci $Path -recurse -Directory).FullName
    $Objects += $Path

    Set-RestrictedAccessRights -p $Objects -o $UserName

}catch{
    Write-Error $_
}
