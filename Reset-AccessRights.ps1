<#
#̷𝓍   𝓐𝓡𝓢 𝓢𝓒𝓡𝓘𝓟𝓣𝓤𝓜
#̷𝓍   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇬​​​​​🇺​​​​​🇮​​​​​🇱​​​​​🇱​​​​​🇦​​​​​🇺​​​​​🇲​​​​​🇪​​​​​🇵​​​​​🇱​​​​​🇦​​​​​🇳​​​​​🇹​​​​​🇪​​​​​.🇶​​​​​🇨​​​​​@🇬​​​​​🇲​​​​​🇦​​​​​🇮​​​​​🇱​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#>

 

    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [Alias('p', 'f','File')]
        [string]$BasePath,
        [Parameter(Mandatory=$true,Position=1)]
        [Alias('u')]
        [ValidateScript({
            if ([string]::IsNullOrEmpty($_)) {
                throw "Invalid UserName specified `"$1`""
            }
            else {
                $Owner = $_
                $UsrOrNull = (Get-LocalUser -ErrorAction Ignore).Name  | Where-Object { $_ -match "$Owner"}
                if ([string]::IsNullOrEmpty($UsrOrNull)) {
                    throw "Invalid UserName specified `"$Owner`""
                }
            }
            return $true 
        })]
        [string]$Owner
    )

#requires -runasadministrator

function Get-AdminAccountName{
    [CmdletBinding(SupportsShouldProcess)]
    param ()  
    $admin_name = (Get-LocalUser | Where Name -match "Admin").Name
    if($Null -ne $admin_name){
        Write-Verbose "Admin name found 1 $admin_name"
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
    $admin_name = (Get-LocalUser | Where Name -match $admin_usr).Name
    Write-Verbose "Admin name found 2 $admin_name"
    return $admin_name
}



function Reset-AccessRights{
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
        Write-Verbose "Reset-AccessRights for owner $Owner. Num $object_count paths"

        $admin_account_name = Get-AdminAccountName
        Write-Verbose "Get-AdminAccountName => $admin_account_name"

    }
    Process{
      try{

        $usr_allow  = "$ENV:USERDOMAIN\$username"               , 'FullControl'  , "none, none","none","Allow"
        $secobj_user_allow  = New-Object System.Security.AccessControl.FileSystemAccessRule $usr_allow 
        $i = 0
        Write-Progress -Activity 'Reset-AccessRights' -Status "Done $i on $object_count.  $per %" -PercentComplete 0
        if($Null -eq $secobj_user_allow)    { throw "Error on FileSystemAccessRule creation $usr_allow" }
        [system.collections.arraylist]$results = [system.collections.arraylist]::new()
        ForEach($obj in $Paths){
            if($obj.Contains('[') ){ Write-Host "$_" ; continue;  }
            $userobject = New-Object System.Security.Principal.NTAccount("$ENV:USERDOMAIN", "$username")
            $acl = Get-Acl -Path $obj
            #foreach ($aceToRemove in $acl.Access){
            #    $r= $acl.RemoveAccessRule($aceToRemove)
            #}
            
            $acl.SetAccessRuleProtection($false, $false)
            $acl.SetAccessRule($secobj_user_allow)
           
            $acl.SetOwner($userobject)

            Write-Verbose "Save the access rules for `"$obj`""
            # Save the access rules to disk:
            try{
                $acl | Set-Acl $obj -ErrorAction Stop
                [int]$per=[math]::Round($i / $object_count * 100)
                Write-Progress -Activity 'Reset-AccessRights' -Status "Done $i on $object_count.  $per %" -PercentComplete $per
                #[void]$results.Add($obj)
                $i++
            }catch{
                Write-Host "Set-Acl ERROR `"$obj`" $_" -f Red
            }
        }
        Write-Progress -Activity 'Reset-AccessRights' -Complete
        Write-Verbose "$($results.Count) paths modified"
        $results
      }catch{
        Write-Error $_
      }
    }
}

Write-Host "Fetching all sub files from base path... " -n
$Objects = (gci $BasePath -recurse -File).FullName
Write-Host "$($Objects.Count) files"
Write-Host "Fetching all subfolders from base path... " -n
$Objects += (gci $BasePath -recurse -Directory).FullName
Write-Host "$($Objects.Count) subfolders"

$Objects += $BasePath

Reset-AccessRights -p $Objects -u $Owner