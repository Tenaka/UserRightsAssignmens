

Write-Host " "
Write-Host "Starting User Rights Assignments" -foregroundColor Green
sleep 5

    $VulnReport = "C:\SecureReport"
    $OutFunc = "URA" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $secEditPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.Inf"
    $secEditOutPath = "C:\SecureReport\output\$OutFunc\" + "URAOut.txt"
    
    $hn = hostname

    $URALookup =[ordered]@{
        "Access this computer from the network" = "SeNetworkLogonRight","Access this computer from the network"
        "Add workstations to domain" = "SeMachineAccountPrivilege","Add workstations to domain"
        "Back up files and directories" = "SeBackupPrivilege", "Back up files and directories"
        "Bypass traverse checking" = "SeChangeNotifyPrivilege", "Bypass traverse checking"
        "Change the system time" = "SeSystemtimePrivilege", "Change the system time"
        "Create a pagefile" = "SeCreatePagefilePrivilege", "Create a pagefile"
        "Force shutdown from a remote system" = "SeRemoteShutdownPrivilege", "Force shutdown from a remote system"
        "Generate security audits" = "SeAuditPrivilege", "Generate security audits" 
        "Adjust memory quotas for a process" = "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"
        "Increase scheduling priority" = "SeIncreaseBasePriorityPrivilege","Increase scheduling priority"
        "Load and unload device drivers" = "SeLoadDriverPrivilege", "Load and unload device drivers"
        "Log on as a batch job" = "SeBatchLogonRight", "Log on as a batch job"
        "Log on as a service" = "SeServiceLogonRight", "Log on as a service" 
        "Allow log on locally" = "SeInteractiveLogonRight", "Allow log on locally" 
        "Manage auditing and security log" = "SeSecurityPrivilege", "Manage auditing and security log"
        "Modify firmware environment values" = "SeSystemEnvironmentPrivilege","Modify firmware environment values"  
        "Profile single process" = "SeProfileSingleProcessPrivilege", "Profile single process" 
        "Profile system performance" = "SeSystemProfilePrivilege", "Profile system performance"
        "Replace a process level token" = "SeAssignPrimaryTokenPrivilege", "Replace a process level token" 
        "Restore files and directories" = "SeRestorePrivilege","Restore files and directories" 
        "Shut down the system" = "SeShutdownPrivilege", "Shut down the system"
        "Take ownership of files or other objects" = "SeTakeOwnershipPrivilege", "Take ownership of files or other objects"
        "Deny access to this computer from the network"   = "SeDenyNetworkLogonRight", "Deny access to this computer from the network" 
        "Deny log on as a batch job" = "SeDenyBatchLogonRight", "Deny log on as a batch job"
        "Deny log on as a service" = "SeDenyServiceLogonRight", "Deny log on as a service" 
        "Deny log on locally" = "SeDenyInteractiveLogonRight", "Deny log on locally" 
        "Remove computer from docking station" = "SeUndockPrivilege","Remove computer from docking station" 
        "Perform volume maintenance tasks" = "SeManageVolumePrivilege", "Perform volume maintenance tasks"
        "Deny log on through Remote Desktop Services" = "SeRemoteInteractiveLogonRight","Deny log on through Remote Desktop Services" 
        "Impersonate a client after authentication" = "SeImpersonatePrivilege", "Impersonate a client after authentication" 
        "Create global objects" = "SeCreateGlobalPrivilege", "Create global objects"
        "Increase a process working set" = "SeIncreaseWorkingSetPrivilege","Increase a process working set" 
        "Change the time zone" = "SeTimeZonePrivilege", "Change the time zone" 
        "Create symbolic links" = "SeCreateSymbolicLinkPrivilege","Create symbolic links" 
        "Obtain an impersonation token for another user in the same session"  = "SeDelegateSessionUserImpersonatePrivilege","Obtain an impersonation token for another user in the same session" 
        }

    #Export Security Settings inc User Rights Assignments with secedit.exe
    secEdit.exe /export /cfg $secEditPath
   
    $URA = get-content -path  $secEditPath |  Select-String  -Pattern 'S-1'
    set-content -Path $secEditOutPath -Value " "
   foreach ($uraLine in $URA)
   {
   
    $uraItem = $uraLine.ToString().split("*").split("=") #.replace(",","")
    #write-host $uraItem -ForegroundColor Yellow
 
        foreach ($uralookupName in $URALookup.Values)
        {
        $uraItemTrim = $uraItem[0].trim()
        $uralookupTrim = $uralookupName.trim()[0]

            if ($uralookuptrim -eq $uraItemTrim)
                {
                   $uraDescripName = $uralookupName.trim()[1]
                   Write-Host $uraDescripName -ForegroundColor Cyan
                   Add-Content $secEditOutPath -Value " "  -encoding UTF8
                   
                   $uraDescripName + " " + "`(" +$uraItem.trim()[0] +"`)" | Out-File $secEditOutPath -Append -encoding UTF8

                }
        }
       
       $uraItemTrimStart = ($uraItem | where {$_ -like "S-1*"}).replace(",","")

       $objSid=@()
      

       foreach($uraSidItems in $uraItemTrimStart)
       {
       $objSid = New-Object System.Security.Principal.SecurityIdentifier("$uraSidItems")
       $objUserName = $objSID.Translate( [System.Security.Principal.NTAccount])
       Write-Host $objUserName.Value -ForegroundColor Magenta
       
       "   " + $objUserName.Value  | Out-File $secEditOutPath -Append  -encoding UTF8

       }
   }
