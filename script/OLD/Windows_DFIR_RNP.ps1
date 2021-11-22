<#
Live Response Using PowerShell (LRUP) 
Author: Sajeev.Nair - Nair.Sajeev@gmail.com
Este script foi extraido do seu artigo elaborado para SANS for Sajeev Nair, foram feitas algumas modificações muito específicas
Em contato com Sajeev Nair, ele informou que não mantém mais atualizações desse script, mas ele continua extremamente funcional
Version : 2.01a 
Script para extração informações volatils em sistema Microsoft Windows  
Como usar:
c:\powershell.exe -ExecutionPolicy Bypass .\windows_DFIR_RNP.ps1
#>
write-host ""
Write-host "[*] - SCRIPT STARTED "
Write-host "[*] - Its will demands some minutes, please waiting..."
write-host ""



# Global Variables used in this script
$CompName = (gi env:\Computername).Value
$UserDirectory = (gi env:\userprofile).value
$User = (gi env:\USERNAME).value
$Date = (Get-Date).ToString('MM.dd.yyyy')
$Folder_Report = "LIVEFORENSICS_REPORT-$Date"
$Path_Report = "$UserDirectory\desktop\$Folder_Report" 

if (!(Test-Path -LiteralPath $UserDirectory\desktop\$Folder_Report ))
{
    New-Item -ItemType directory -Path $UserDirectory\desktop\$Folder_Report
}

$head = '<style> BODY{font-family:caibri; background-color:Aliceblue;}
TABLE{border-width: 1px;border-style: solid;border-color: black;bordercollapse: collapse;}
TH{font-size:1.1em; border-width: 1px;padding: 2px;borderstyle: solid;border-color: black;background-color:PowderBlue}
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;backgroundcolor:white}
</style>'

$OutLevel1 = "$Path_Report\$CompName-$User-$Date-REPORT_Level1.html"

$TList = @(tasklist /V /FO CSV | ConvertFrom-Csv)

$ExecutableFiles = @("*.EXE","*.COM","*.BAT","*.BIN", "*.JOB","*.WS",".WSF","*.PS1",".PAF","*.MSI","*.CGI","*.CMD","*.JAR","*.JSE","* .SCR","*.SCRIPT","*.VB","*.VBE","*.VBS","*.VBSCRIPT","*.DLL")

# Setting HTML report format
Write-host "[*] - Setting HTML report format"
ConvertTo-Html -Head $head -Title " DFIR Live Response script for $CompName.$User Author: Sajeev.Nair - Nair.Sajeev@gmail.com" -Body "<a href=`"https://www.sans.com`" target=`"_blank`"> <img src=`"DFIR.png`"> </a> <h1> DFIR Live Forensics Script <p> Computer Name : $CompName &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp User ID : $User </p> </h1>" >$OutLevel1

# Main Routine
# Record start time of collection

date | select DateTime | ConvertTo-html -Body "<H2> Current Date and Time </H2>" >> $OutLevel1

openfiles /local on

Write-host "[+] - Extracting  - System Infomartion"
systeminfo /FO CSV | ConvertFrom-Csv | select-object * -ExcludeProperty 'Hotfix(s)','Network Card(s)' | ConvertTo-html -Body "<H2> System Information </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - User accounts and current login Information"
gwmi -ea 0 Win32_UserProfile | select LocalPath, SID,@{NAME='last used';EXPRESSION={$_.ConvertToDateTime($_.lastusetime)}} | ConvertTo-html -Body "<H2> User accounts and current login Information </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Network Configuration Information"
gwmi -ea 0 Win32_NetworkAdapterConfiguration |where{$_.IPEnabled -eq 'True'} |select DHCPEnabled,@{Name='IpAddress';Expression={$_.IpAddress -join ';'}},@{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join ';'}},DNSDomain | ConvertTo-html -Body "<H2> Network Configuration Information</H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Startup Applications"
gwmi -ea 0 Win32_StartupCommand | select command,user,caption | ConvertTo-html -Body "<H2> Startup Applications </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Startup Applications - Additional for 64 bit Systems"
gp -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

gp -ea 0 'hklm:\software\Wow6432Node\Microsoft\windows\CurrentVersion\Policies\Explorer\Run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

gp -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\runonce'| select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

gp -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

gp -ea 0 'hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1

gp -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Startup Applications - Additional for 64 bit Systems </H2>" >> $OutLevel1


Write-host "[+] - Extracting - Running Processes sorted by ParentProcessID"
$cmd = netstat -nao | select-string "ESTA"

foreach ($element in $cmd)
{
$data = $element -split ' ' | where {$_ -ne ''}

New-Object -TypeName psobject -Property @{
'Local IP : Port#'=$data[1];
'Remote IP : Port#'=$data[2];
'Process ID'= $data[4];
'Process Name'=((Get-process |where {$_.ID -eq $data[4]})).Name
'Process File Path'=((Get-process |where {$_.ID -eq $data[4]})).path
'Process Start Time'=((Get-process |where {$_.ID -eq $data[4]})).starttime

#'Process File Version'=((Get-process |where {$_.ID -eq $data[4]})).FileVersion

'Associated DLLs and File Path'=((Get-process |where {$_.ID -eq $data[4]})).Modules |select @{Name='Module';Expression={$_.filename -join '; '} } |out-string

 } | ConvertTo-html -Property 'Local IP : Port#', 'Remote IP : Port#','Process ID','Process Name','Process Start Time','Process File Path','Associated DLLs and File Path' -Body "<H2> </H2>" >> $OutLevel1
}

gwmi -ea 0 win32_process | select processname,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},ProcessId,ParentProcessId,CommandLine,sessionID |sort ParentProcessId -desc | ConvertTo-html -Body "<H2> Running Processes sorted by ParentProcessID </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Running SVCHOST and associated Processes"
gwmi -ea 0 win32_process | where {$_.name -eq 'svchost.exe'} | select ProcessId | foreach-object {$P = $_.ProcessID ;gwmi win32_service |where {$_.processId -eq $P} | select processID,name,DisplayName,state,startmode,PathName} | ConvertTo-html -Body "<H2> Running SVCHOST and associated Processes </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Running Services - Sorted by State"
gwmi -ea 0 win32_Service | select Name,ProcessId,State,DisplayName,PathName | sort state | ConvertTo-html -Body "<H2> Running Services - Sorted by State </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Drivers running, Startup mode and Path - Sorted by Path"
driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select 'Display Name','Start Mode', Path | sort Path | ConvertTo-html -Body "<H2> Drivers running, Startup mode and Path - Sorted by Path </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Last 50 DLLs created - Sorted by CreationTime"
gci -r -ea 0 c:\ -include *.dll | select Name,CreationTime,LastAccessTime,Directory | sort CreationTime -desc | select -first 50 | ConvertTo-html -Body "<H2> Last 50 DLLs created - Sorted by CreationTime </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Open Shares"
openfiles /query > "$Path_Report\$CompName-$User-$Date-OpenFiles.txt"

gwmi -ea 0 Win32_Share | select name,path,description | ConvertTo-html -Body "<H2> Open Shares </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Mapped Drives"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Mapped Drives </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Scheduled Jobs"
gwmi -ea 0 Win32_ScheduledJob | ConvertTo-html -Body "<H2> Scheduled Jobs </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Scheduled task events"
Get-WinEvent -ea 0 -logname Microsoft-Windows-Task-Scheduler-Operational | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Scheduled task events </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - HotFixes applied"
Get-HotFix -ea 0| Select HotfixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending | ConvertTo-html -Body "<H2> HotFixes applied - Sorted by Installed Date </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Installed Applications"
gp -ea 0 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | Sort InstallDate -Desc | ConvertTo-html -Body "<H2> Installed Applications - Sorted by Installed Date </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Link File Analysis Last 5 days"
gwmi -ea 0 Win32_ShortcutFile | select FileName,caption,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},@{NAME='LastAccessed';EXPRESSION={$_.ConvertToDateTime($_.LastAccessed)}},@{NAME='LastModified';EXPRESSION={$_.ConvertToDateTime($_.LastModified)}},Target | Where-Object {$_.lastModified -gt ((Get-Date).addDays(-5)) }| sort LastModified -Descending | ConvertTo-html -Body "<H2> Link File Analysis - Last 5 days </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Compressed files"
gci -Path C:\ -r -ea 0 -include $ExecutableFiles | Where {$_.Attributes -band [IO.FileAttributes]::Compressed} | ConvertTo-html -Body "<H2> Compressed files </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Encrypted files"
gci -Path C:\ -r -force -ea 0 -include $ExecutableFiles | Where {$_.Attributes -band [IO.FileAttributes]::Encrypted} | ConvertTo-html -Body "<H2> Encrypted files </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - ShadowCopy List"
gwmi -ea 0 Win32_ShadowCopy | select DeviceObject,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.InstallDate)}} | ConvertTo-html -Body "<H2> ShadowCopy List </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Prefetch Files"
gci -path C:\windows\prefetch\*.pf -ea 0 | select Name,LastAccessTime,CreationTime | sort LastAccessTime | ConvertTo-html -Body "<H2>Prefetch Files </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - DNS Cache"
ipconfig /displaydns | select-string 'Record Name' | Sort | ConvertTo-html -Body "<H2> DNS Cache </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Event log - DNS failed resolution events"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=1014} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - DNS failed resolution events </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - List of available logs"
Get-WinEvent -ea 0 -ListLog * | Where-Object {$_.IsEnabled} | Sort-Object -Property LastWriteTime -Descending | select LogName, FileSize, LastWriteTime | ConvertTo-html -Body "<H2> List of available logs </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Temporary Internet Files - Last 5 days"
$la = $env:LOCALAPPDATA ;gci -r -ea 0 $la\Microsoft\Windows\'Temporary Internet Files' | select Name, LastWriteTime, CreationTime,Directory| Where-Object{$_.lastwritetime -gt ((Get-Date).addDays(-5)) } | Sort creationtime -Desc | ConvertTo-html -Body "<H2> Temporary Internet Files - Last 5 days - Sorted by CreationTime </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Cookies"
$a = $env:APPDATA;gci -r -ea 0 $a\Microsoft\Windows\cookies | select Name|foreach-object {$N = $_.Name ;get-content -ea 0 $a\Microsoft\Windows\cookies\$N | select-string '/'} | ConvertTo-html -Body "<H2> Cookies </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Typed URLs"
gp -ea 0 'hkcu:\Software\Microsoft\Internet Explorer\TypedUrls' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Typed URLs </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - Internet Settings"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - Internet Settings </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - Intern"
gci -ea 0 'hkcu:SOFTWARE\Microsoft\Windows\CurrentVersion\InternetSettings\ZoneMap\EscDomains' | select PSChildName | ConvertTo-html -Body "<H2>et Trusted DomainsImportant Registry keys - Intern </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - AppInit_DLLs"
gp -ea 0 'hklm:\Software\Microsoft\Windows NT\CurrentVersion\Windows' | select AppInit_DLLs | ConvertTo-html -Body "<H2> Important Registry keys - AppInit_DLLs </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - UAC Group Policy Settings"
gp -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\policies\system' |
select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - UAC Group Policy Settings </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - UAC Group Policy Settings"
gp -ea 0 'HKLM:\Software\Microsoft\Active Setup\Installed Components\*' |
select ComponentID,'(default)',StubPath | ConvertTo-html -Body "<H2>Important Registry keys - Active setup Installs </H2>" >> $OutLevel1


Write-host "Extract - Important Registry keys - APP Paths keys"
gp -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\App Paths\*' | select PSChildName, '(default)' | ConvertTo-html -Body "<H2> Important Registry keys - APP Paths keys </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - DLLs loaded by Explorer.exe shell"
gp -ea 0 'hklm:\software\microsoft\windows nt\CurrentVersion\winlogon\*\*' |
select '(default)',DllName | ConvertTo-html -Body "<H2> Important Registry keys - DLLs loaded by Explorer.exe shell </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys -shell and UserInit values"
gp -ea 0 'hklm:\software\microsoft\windows nt\CurrentVersion\winlogon' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys -shell and UserInit values </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry Keys - Security center SVC values"
gp -ea 0 'hklm:\software\microsoft\security center\svc' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry Keys - Security center SVC values </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - Desktop Address bar history"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - Desktop Address bar history </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registry keys - RunMRU keys"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\RunMru' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - RunMRU keys </H2>" >> $OutLevel1


Write-host "[+] - Extracting  - Important Registrykeys - Start Menu"
gp -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\explorer\Startmenu' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registrykeys - Start Menu </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - Programs Executed By Session Manager"
gp -ea 0 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - Programs Executed By Session Manager </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - Shell Folders"
gp -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\explorer\ShellFolders' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2>Important Registry keys - Shell Folders </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - User Shell Folders"
gp -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\ShellFolders' | select startup | ConvertTo-html -Body "<H2> Important Registry keys - User Shell Folders 'Startup' </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - Approved Shell Extentions"
gp -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellExtensions\Approved' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - Approved Shell Extentions </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - AppCert DLLs"
gp -ea 0 'hklm:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - AppCert DLLs </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - EXE File Shell Command Configured"
gp -ea 0 'hklm:\SOFTWARE\Classes\exefile\shell\open\command' | select * -ExcludeProperty PS* | ConvertTo-html -Body "<H2> Important Registry keys - EXE File Shell Command Configured </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - EXE File Shell Command Configured"
gp -ea 0 'hklm:\SOFTWARE\Classes\HTTP\shell\open\command' | select '(default)' | ConvertTo-html -Body "<H2> Important Registry keys - Shell Commands </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - EXE File Shell Command Configured"
gp -ea 0 'hklm:\BCD00000000\*\*\*\*' | select Element |select-string 'exe' | select Line | ConvertTo-html -Body "<H2> Important Registry keys - BCD Related</H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - LSA Packages loaded"
gp -ea 0 'hklm:\system\currentcontrolset\control\lsa' | select * -ExcludeProperty PS*| ConvertTo-html -Body "<H2> Important Registry keys - LSA Packages loaded </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - Browser Helper Objects"
gp -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | select '(default)'| ConvertTo-html -Body "<H2> Important Registry keys - Browser Helper Objects </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - Browser Helper Objects"
gp -ea 0 'hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | select '(default)' | ConvertTo-html -Body "<H2> Important Registry keys - Browser Helper Objects 64 Bit </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Important Registry keys - IE Extensions"
gp -ea 0 'hkcu:\Software\Microsoft\Internet Explorer\Extensions\*' | select ButtonText, Icon | ConvertTo-html -Body "<H2> Important Registry keys - IE Extensions </H2>" >> $OutLevel1

gp -ea 0 'hklm:\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\*' | select ButtonText, Icon | ConvertTo-html -Body "<H2> Important Registry keys - IE Extensions </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - List of USB devices"
gp -ea 0 'hklm:\system\currentcontrolset\enum\usbstor\*\*' | select FriendlyName,PSChildName,ContainerID | ConvertTo-html -Body "<H2> List of USB devices </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - File Timeline Executable Files - Past 30 days"
gci -Path C:\ -r -force -ea 0 -include $ExecutableFiles | Where-Object {-not $_.PSIsContainer -and $_.lastwritetime -gt ((Get-Date).addDays(-30)) } | select fullname,lastwritetime,@{N='Owner';E={($_ | Get-ACL).Owner}} | sort lastwritetime -desc | ConvertTo-html -Body "<H2> File Timeline Executable Files - Past 30 days </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Downloaded executable files"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4624} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Account logon </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - An account failed to log on"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4625} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - An account failed to log on </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - The system time was changed"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4616} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - The system time was changed </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - Application crashes"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='application';ID=1002} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Application crashes </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - Process execution"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4688} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Process execution </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - A user account was created"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4720} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - A user account was created </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - A logon was attempted using explicit credentials" 
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4648} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - A logon was attempted using explicit credentials </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - Privilege use 4672"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4672} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Privilege use 4672 </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - Privilege use 4673"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4673} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Privilege use 4673 </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - Privilege use 4674"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4674} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Privilege use 4674 </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - Service Control Manager events"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=7036} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - Service Control Manager events </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Event log - WFP events"
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=64001} | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Event log - WFP events </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Application inventory events"
Get-winevent -ea 0 -logname Microsoft-Windows-Application-Experience/ProgramInventory | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Application inventory events </H2>" >> $OutLevel1

Write-host "[+] - Extracting  - Terminal services events"
Get-winevent -ea 0 -logname Microsoft-Windows-TerminalServicesLocalSessionManager | select TimeCreated,ID,Message | ConvertTo-html -Body "<H2> Terminal services events </H2>" >> $OutLevel1

# Record end time of collection

Write-host "[+] - Extracting  - Current Date and Time"
date | select DateTime | ConvertTo-html -Body "<H2> Current Date and Time</H2>" >> $OutLevel1

# extracting informations from process and they DLL
write-host "[+] - Extracting informations from process and they DLL "
tasklist /m > "$Path_Report\$CompName-$User-$Date-Processes_and_DLL.txt"

# Extracting Network connections informations
write-host "[+] - Extracting Network connections informations"
netstat -nabo > "$Path_Report\$CompName-$User-$DateNetworkConnections.txt"

# Copying Hosts file
write-host "[+] - Extracting Copying Hosts file "
gc $env:windir\system32\drivers\etc\hosts > "$Path_Report\$CompName-$User-$Date-HostsFile.txt"

# Audit Policy
write-host "[+] - Extracting Audit Policy information"
auditpol /get /category:* | select-string 'No Auditing' -notmatch > "$Path_Report\$CompName-$User-$Date-AuditPolicy.txt"

# Firewall Config
write-host "[+] - Extracting Firewall Config information "
netsh firewall show config > "$Path_Report\$CompName-$User-$DateFirewallConfig.txt"

# Dumps of all Firewall rules
write-host "[+] - Extracting Dumps of all Firewall rules actived"
netsh advfirewall firewall show rule name=all > "$Path_Report\$CompName-$User-$Date-FirewallAllRules.txt"

write-host ""

Write-host "[+] - DFIR - The Live Forensic Extract was completed - Sounds Great!"

# Popup message upon completion
write-host "[*] - Popup message upon completion"
(New-Object -ComObject wscript.shell).popup("*** Finally Script Completed ***")