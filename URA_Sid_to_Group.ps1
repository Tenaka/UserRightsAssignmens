    
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Working Directory C:\SecureReport
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    #Enable detection of PowerShell or ISE, enable to run from both
    #Script name has been defined and must be saved as that name.
    $secureReport = "C:\SecureReport"
    $secureReporOutPut = "$($secureReport)\output\"
    $secureReportError = "$($secureReporOutPut)\Errorlog.log" 
    
    $ptRand = Get-Random -Minimum 100 -Maximum 999
    $tpSecRrpt = test-path $secureReport
        if ($tpSecRrpt -eq $true)
            {
                Rename-Item $secureReport -NewName "$secureReport$($ptRand)" -Force
                New-Item -Path $secureReport -ItemType Directory -Force
                New-Item -path $secureReportError -ItemType File -Force
            }
        else
            {
                New-Item -Path $secureReport -ItemType Directory -Force
                New-Item -path $secureReportError -ItemType File -Force
            }

    #Current working path
        if($psise -ne $null)
            {
                $ISEPath = $psise.CurrentFile.FullPath
                $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
                $pwdPath = $ISEPath.TrimEnd("$ISEDisp")
            }
        else
            {
                $pwdPath = split-path -parent $MyInvocation.MyCommand.Path
            }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                   Functions
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    function SecureReportError
        {
            Write-Host "$($SecCheck)" -foregroundColor yellow
            Write-Host "$($SecErrorComment)" -ForegroundColor Cyan
            if ([string]::IsNullorEmpty($exceptionMessage) -ne "$true")
                {
                    Add-Content -Path $secureReportError -value $SecCheck
                    Add-Content -Path $secureReportError -value "     Error: $exceptionMessage"
                    Write-Host "Error: $exceptionMessage" -ForegroundColor Cyan
                }

            if ([string]::IsNullorEmpty($exceptionCMD) -ne "$true")
                {
                    Add-Content -Path $secureReportError -value $exceptionCMD
                    Add-Content -Path $secureReportError -value "     Error: $exceptionCMD"
                    write-Host $exceptionCMD -ForegroundColor Cyan   
                }          
        }

    function TestConfigOutputPath
        {
            try
                {
                    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
                    Get-Item -path $SecureReportConfig -ErrorAction Stop                
                }
            catch
                {
                    New-Item -Path $SecureReportConfig -ItemType Directory -Force
                }           
        }
  
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  User Rights Assignments (URA)
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    $SecCheck = "User Rights Assignments (URA)"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "URA"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    $secEditPath = "$($SecureReportConfig)\$OutFunc.Inf"
    $secEditOutPath = "$($SecureReportConfig)\URAOut.txt"
    $secEditImpPath = "$($SecureReportConfig)\URAImport.txt"
    Set-Content -Path $secEditOutPath -Value " "
    Set-Content -Path $secEditImpPath -Value " "
    
    $hn = hostname

    $URALookup =[ordered]@{
            "Access Credential Manager as a trusted caller"="SeTrustedCredManAccessPrivilege","Access Credential Manager as a trusted caller | Set Blank"
            "Access this computer from the network" = "SeNetworkLogonRight","Access this computer from the network | Administrators, Remote Desktop Users"
            "Act as part of the operating system"="SeTcbPrivilege","Act as part of the operating system | Set Blank"
            "Add workstations to domain" = "SeMachineAccountPrivilege","Add workstations to domain"
            "Adjust memory quotas for a process" = "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"
            "Allow log on locally" = "SeInteractiveLogonRight", "Allow log on locally | Administrators, Users | Administrators, Users" 
            "Allow log on through Remote Desktop Services"="SeRemoteInteractiveLogonRight","Allow log on through Remote Desktop Services"
            "Back up files and directories" = "SeBackupPrivilege", "Back up files and directories | Administrators"
            "Bypass traverse checking" = "SeChangeNotifyPrivilege", "Bypass traverse checking"
            "Change the system time" = "SeSystemtimePrivilege", "Change the system time"
            "Change the time zone" = "SeTimeZonePrivilege", "Change the time zone" 
            "Create a pagefile" = "SeCreatePagefilePrivilege", "Create a pagefile | Administrators"
            "Create a token object"="SeCreateTokenPrivilege","Create a token object | Set Blank"
            "Create global objects" = "SeCreateGlobalPrivilege", "Create global objects | Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE"
            "Create permanent shared objects"="SeCreatePermanentPrivilege","Create permanent shared objects | Set Blank"
            "Create symbolic links" = "SeCreateSymbolicLinkPrivilege","Create symbolic links" 
            "Debug programs" = "SeDebugPrivilege", "Debug programs | Administrators (Prefer setting Blank)"
            "Deny Access to this computer from the network"   = "SeDenyNetworkLogonRight", "Deny Access to this computer from the network | NT AUTHORITY\Local Account" 
            "Deny log on as a batch job" = "SeDenyBatchLogonRight", "Deny log on as a batch job"
            "Deny log on as a service" = "SeDenyServiceLogonRight", "Deny log on as a service" 
            "Deny log on locally" = "SeDenyInteractiveLogonRight", "Deny log on locally" 
            "Deny log on through Remote Desktop Services" = "SeRemoteInteractiveLogonRight","Deny log on through Remote Desktop Services | NT AUTHORITY\Local Account" 
            "Enable computer and user accounts to be trusted for delegation"="SeEnableDelegationPrivilege","Enable computer and user accounts to be trusted for delegation | Set Blank"
            "Force shutdown from a remote system" = "SeRemoteShutdownPrivilege", "Force shutdown from a remote system | Administrators"
            "Generate security audits" = "SeAuditPrivilege", "Generate security audits" 
            "Impersonate a client after authentication" = "SeImpersonatePrivilege", "Impersonate a client after authentication | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE" 
            "Increase a process working set" = "SeIncreaseWorkingSetPrivilege","Increase a process working set" 
            "Increase scheduling priority" = "SeIncreaseBasePriorityPrivilege","Increase scheduling priority"
            "Load and unload device drivers" = "SeLoadDriverPrivilege", "Load and unload device drivers | Administrators"
            "Lock pages in memory"="SeLockMemoryPrivilege","Lock pages in memory | Set Blank"
            "Log on as a batch job" = "SeBatchLogonRight", "Log on as a batch job"
            "Log on as a service" = "SeServiceLogonRight", "Log on as a service" 
            "Manage auditing and security log" = "SeSecurityPrivilege", "Manage auditing and security log | Administrators"
            "Modify an object label"="SeRelabelPrivilege","Modify an object label"
            "Modify firmware environment values" = "SeSystemEnvironmentPrivilege","Modify firmware environment values | Administrators"  
            "Obtain an impersonation token for another user in the same session" = "SeDelegateSessionUserImpersonatePrivilege","Obtain an impersonation token for another user in the same session" 
            "Perform volume maintenance tasks" = "SeManageVolumePrivilege", "Perform volume maintenance tasks | Administrators"
            "Profile single process" = "SeProfileSingleProcessPrivilege", "Profile single process  | Administrators" 
            "Profile system performance" = "SeSystemProfilePrivilege", "Profile system performance"
            "Remove computer from docking station" = "SeUndockPrivilege","Remove computer from docking station" 
            "Replace a process level token" = "SeAssignPrimaryTokenPrivilege", "Replace a process level token" 
            "Restore files and directories" = "SeRestorePrivilege","Restore files and directories | Administrators" 
            "Shut down the system" = "SeShutdownPrivilege", "Shut down the system"
            "Synchronize directory service data"="SeSyncAgentPrivilege","Synchronize directory service data"
            "Take ownership of files or other objects" = "SeTakeOwnershipPrivilege", "Take ownership of files or other objects | Administrators"
        }

    $URACommonPath = "Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assingments\" 

    #Export Security Settings inc User Rights Assignments with secedit.exe
    secEdit.exe /export /cfg $secEditPath
   
    $URA = get-content -path  $secEditPath |  Select-String  -Pattern 'S-1'
    $fragURA=@()
    foreach ($uraLine in $URA)
       {
            $uraItem = $uraLine.ToString().split(",").split("=").replace("*","").replace(" ","") #.replace(",","")
            #write-host $uraItem -ForegroundColor Yellow

            foreach ($uralookupName in $URALookup.Values)
                {
                    $uraItemTrim = $uraItem[0].trim()
                    $uralookupTrim = $uralookupName.trim()[0]

                        if ($uralookuptrim -eq $uraItemTrim)
                            {
                               try
                                   {
                                       $uraDescripName = $uralookupName.trim()[1].split("|")[0]
                                       $uraMSRecom = $uralookupName[1].split("|")[1].trim()
                                       $URAGPOPath = $URACommonPath + $uraDescripName
                                   }catch{}

                               Add-Content $secEditOutPath -Value " " -encoding UTF8

                               $uraDescripName + " " + "`(" +$uraItem.trim()[0] +"`)" | Out-File $secEditOutPath -Append -encoding UTF8
                               $uraDescripName = "<div title=$uraMSRecom>$uraDescripName"

                               $uraTrimDescrip = "<div title=$URAGPOPath>$uraItemTrim"
                            }
                    }
           Write-Host $uraItem -ForegroundColor Cyan
           $uraItemTrimStart = ($uraItem | where {$_ -ne "$uraItemTrim"}).replace(",","")

           $objSid=@()
     
           Set-Content -Path $secEditImpPath -Value " "
           $NameURA=@()
           foreach($uraSidItems in $uraItemTrimStart)
               {
                    if ($uraSidItems -match "S-1-")
                        {
                            $objSid = New-Object System.Security.Principal.SecurityIdentifier("$uraSidItems")
                            $objUserName = $objSID.Translate([System.Security.Principal.NTAccount])  
                            "   " + $objUserName.Value  | Out-File $secEditOutPath -Append  -encoding UTF8  
                            [string]$NameURA += $objUserName.Value + ", "
                        }
                    else
                        {
                            $objUserName = $uraSidItems
                            "   " + $objUserName | Out-File $secEditOutPath -Append  -encoding UTF8 
                            [string]$NameURA += $objUserName + ", "   
                        }                                       
               }
        }
        start notepad $secEditOutPath
