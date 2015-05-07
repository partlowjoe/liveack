<#
RQLabs Live Acquisition Script for Desktop Forensics
Tested on: Win 7, Win 8, Server 2008 R2, Win 10
Run like this with admin privs: powershell.exe -noprofile -executionpolicy unrestricted -file .\liveack.ps1 
#>

#***************** All Functions *****************
function startup {
$CompName = (Get-Item env:\Computername).Value
$WinVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
$PSVersion = (get-host).Version.Major
#$UserDirectory = (Get-Item env:\userprofile).value
$User = (Get-Item env:\USERNAME).value
$Date = (Get-Date).ToString('MM.dd.yyyy')
$head = '<style> BODY{font-family:caibri; background-color:Aliceblue;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-
collapse: collapse;} TH{font-size:1.1em; border-width: 1px;padding: 2px;border-
style: solid;border-color: black;background-color:PowderBlue} TD{border-width:
1px;padding: 2px;border-style: solid;border-color: black;background-
color:white} </style>'
$TList = @(tasklist /V /FO CSV | ConvertFrom-Csv)
$ExecutableFiles = @("*.EXE","*.COM","*.BAT","*.BIN","*.JOB","*.WS",".WSF","*.PS1",".PAF",
"*.MSI","*.CGI","*.CMD","*.JAR","*.JSE","*.SCR","*.SCRIPT","*.VB","*.VBE","*.VBS","*.VBSCRIPT","*.DLL")
$InterestingFiles = @("*.plist","*.mdbackup","*.mddata","*.mdinfo","*.sqlite","*.ps1","*.7z","*.zip")
$outfolder = Read-Host 'What is the output report folder path?'
$copytask = Read-Host 'Copy files found as well as list them (Y/N)?'
If ($copytask = 'Y') { $copyvar = 'Y'}
If ($copytask = 'N') { $copyvar = 'N'}
else {write-host -ForegroundColor red "Invalid Selection"  
	sleep 5  
	startup 
    } 

# Setting HTML report format
Start-Transcript "$outfolder\Transcript_$CompName-$Date.txt"
$ReportStep1 = "$outfolder\$CompName-$Date.html"
ConvertTo-Html -Head $head -Title "Live Response script for $CompName.$User" -Body "<h1> Live Forensics Script<p>Computer Name: $CompName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;User ID: $User</p></h1>" > $ReportStep1

date | select DateTime | ConvertTo-html -Body "<H2> Current Date and Time</H2>" >> $ReportStep1 

mainmenu
}
  
function mainmenu {  
	cls  
	echo "---------------------------------------------------------"  
 	echo " RQ Live Acquisition Forensic Script"  
 	echo ""  
 	echo "    1. Memory Dump"  
 	echo "    2. Export Live System Snapshot Items"
	echo "    3. Export Startup Items"
	echo "    4. Export Browsing Items" 
 	echo "    5. Export Registry Keys"
	echo "    6. Export File Items" 
	echo "    7. Export Event Logs" 
 	echo "    8. Auto-Snag (Do everything above here)"  
	echo "    9. IOC Search and Export" 
	echo "    10. Get All Files From X Date" 
	echo "    11. Get All Files From X User (including ntuser.dat)" 
	echo "    12. Dump Network Traffic" 
	echo "    13. Dump Entire Disk" 
 	echo "    14. Exit"  
 	echo ""  
 	echo "---------------------------------------------------------"  
$answer = read-host "Please Make a Selection"  
if ($answer -eq 1){memdump}  
if ($answer -eq 2){sysconfig runningproc}  
if ($answer -eq 3){startupinfo} 
if ($answer -eq 4){browseinfo} 
if ($answer -eq 5){regsearch} 
if ($answer -eq 6){filesysteminfo} 
if ($answer -eq 7){securityevents} 
if ($answer -eq 8){memdump sysconfig startupinfo runningproc browseinfo regsearch filesysteminfo securityevents}  
if ($answer -eq 9){iocsearch} 
if ($answer -eq 10){getfiles} 
if ($answer -eq 11){getuserinfo} 
if ($answer -eq 12){netdump} 
if ($answer -eq 13){diskdump} 
if ($answer -eq 14){confirmation} 
else {write-host -ForegroundColor red "Invalid Selection"  
	sleep 5  
	mainmenu  
    }  
}  

function memdump {
Write-host "**** Pulling Memory Dump ****"
& .\DumpIt.exe
}

function sysconfig {
Write-host "**** Pulling System Configuration ****"
$os = gwmi win32_operatingsystem
$os.ConvertToDateTime($os.installDate) | 
ConvertTo-html -Body "<H2>OS Install Date</H2>" >> $ReportStep1

openfiles /local on 
openfiles /query /FO CSV /v | ConvertFrom-Csv | select-object * -ExcludeProperty 'Hotfix(s)','Network Card(s)' | 
ConvertTo-html -Body "<H2>Open Files</H2>" >> $ReportStep1

Get-WmiObject -ea 0 Win32_UserProfile | select LocalPath, SID,@{NAME='lastused';EXPRESSION={$_.ConvertToDateTime($_.lastusetime)}} | 
ConvertTo-html -Body "<H2>User accounts and current login Information</H2>" >> $ReportStep1

Get-WmiObject -ea 0 Win32_NetworkAdapterConfiguration |where{$_.IPEnabled -eq 'True'} |
select DHCPEnabled,@{Name='IpAddress';Expression={$_.IpAddress -join ';'}},@{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join ';'}},DNSDomain  | 
ConvertTo-html -Body "<H2>Network Configuration Information</H2>" >> $ReportStep1

openfiles /query > "$outfolder\$CompName-$User-$Date-OpenFiles.txt"
Get-WmiObject -ea 0 Win32_Share | select name,path,description | 
ConvertTo-html -Body "<H2>Open Shares</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Mapped Drives</H2>" >> $ReportStep1

# need to add extended description
Get-HotFix  -ea 0| Select HotfixID, Description, InstalledBy, InstalledOn -first 10 | Sort-Object InstalledOn -Descending | 
ConvertTo-html -Body "<H2> HotFixes applied - Sorted by Installed Date</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | Sort InstallDate -Desc  | 
ConvertTo-html -Body "<H2>Installed Applications - Sorted by Installed Date</H2>" >> $ReportStep1

$colItems = Get-WmiObject -class "Win32_NetworkAdapterConfiguration" -computername $SCHost | Where {$_.IPEnabled -Match "True"} | Select $objItem.MACAddress,$objItem.IPAddress,$objItem.IPEnabled,$objItem.DNSServerSearchOrder | 
ConvertTo-html -Body "<H2>IP Addresses</H2>" >> $ReportStep1

# Copying Environment Parms
Get-Childitem -ea 0 env: | ConvertTo-html -Body "<H2>Environmental Variables</H2>" >> $ReportStep1

# Copying Hosts file
if ($copyvar = 'c') {
Copy-Item -ea 0 $env:windir\system32\drivers\etc\hosts "$outfolder\$CompName-$User-$Date_Hosts.txt" }

# Audit Policy
if ($copyvar = 'c') {
auditpol /get /category:* | select-string 'No Auditing' -notmatch > "$outfolder\$CompName-$User-$Date-AuditPolicy.txt" }

# Firewall Config
if ($copyvar = 'c') {
netsh advfirewall firewall show config > "$outfolder\$CompName-$User-$Date-FirewallConfig.txt" }
}

function startupinfo {
Write-host "**** Pulling Startup information ****"
Get-WmiObject -ea 0 Win32_StartupCommand | select command,user,caption | 
ConvertTo-html -Body "<H2>Startup Applications</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\run' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Startup Applications - Additional for 64 bit Systems</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Startup Applications - Additional for 64 bit Systems</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\runonce' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Startup Applications - Additional for 64 bit Systems</H2>" >> $ReportStep1
}

function runningproc {
Write-host "**** Pulling Running Processes ****"
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
 'Associated DLLs and File Path'=((Get-process |where {$_.ID -eq
$data[4]})).Modules |select @{Name='Module';Expression={$_.filename -join '; '
} } | out-string   } | 
ConvertTo-html -Property 'Local IP : Port#', 'Remote IP :
Port#','Process ID','Process Name','Process Start Time','Process File
Path','Associated DLLs and File Path' -Body "<H2>Running Processes</H2>" >> $ReportStep1
}

Get-WmiObject -ea 0 win32_process | select processname,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},
ProcessId,ParentProcessId,CommandLine,sessionID |sort ParentProcessId - desc | 
ConvertTo-html -Body "<H2>Running Processes sorted by ParentProcessID</H2>" >> $ReportStep1

Get-WmiObject -ea 0 win32_process | where {$_.name -eq 'svchost.exe'} | select ProcessId |foreach-object 
{$P = $_.ProcessID ;gwmi win32_service |where {$_.processId -eq $P} | select processID,name,DisplayName,state,startmode,PathName} | 
ConvertTo-html -Body "<H2> Running SVCHOST and associated Processes </H2>" >> $ReportStep1

Get-WmiObject -ea 0 win32_Service  | select Name,ProcessId,State,DisplayName,PathName | sort state | 
ConvertTo-html  -Body "<H2>Running Services - Sorted by State</H2>" >> $ReportStep1

driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select 'Display Name','Start Mode', Path | sort Path | 
ConvertTo-html -Body "<H2>Drivers running, Startup mode and Path - Sorted by Path</H2>" >> $ReportStep1

Get-ChildItem -path $env:systemdrive\ -recurse -force -ea 0 -include *.dll | select Name,CreationTime,LastAccessTime,Directory | sort CreationTime -desc | select -first 50 | 
ConvertTo-html -Body "<H2>Last 50 DLLs created - Sorted by CreationTime</H2>" >> $ReportStep1

Get-WmiObject -ea 0 Win32_ScheduledJob | ConvertTo-html -Body "<H2>Scheduled Jobs</H2>" >> $ReportStep1

get-winevent -ea 0 -logname Microsoft-Windows-TaskScheduler/ Operational | select TimeCreated,ID,Message | 
ConvertTo-html  -Body "<H2>Scheduled task events</H2>" >> $ReportStep1
}

function browseinfo {
Write-host "**** Pulling Browser Information ****"
ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0 -include $ExecutableFiles} | foreach {$P = $_.fullname; get-item $P -Stream *} |where {$_.Stream -match "Zone.Identifier"} | select filename, stream, @{N='LastWriteTime';E={(dir $P).LastWriteTime}} | 
ConvertTo-html -Body "<H2> Downloaded executable files </H2>" >> $ReportStep1

ipconfig /displaydns | select-string 'Record Name' | 
ConvertTo-html -Body "<H2>DNS Cache</H2>" >> $ReportStep1

Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=1014} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - DNS failed resolution events</H2>" >> $ReportStep1

Get-WinEvent -ea 0 -ListLog * | Where-Object {$_.IsEnabled} | Sort-Object -Property LastWriteTime -Descending | select LogName, FileSize, LastWriteTime | 
ConvertTo-html -Body "<H2> List of available logs</H2>" >> $ReportStep1

$la = $env:LOCALAPPDATA ;Get-ChildItem -r -ea 0 $la\Microsoft\Windows\'Temporary InternetFiles' | select Name, LastWriteTime, CreationTime,Directory | Where-Object {$_.lastwritetime -gt ((Get-Date).addDays(-5)) }| Sort creationtime -Desc  |
ConvertTo-html -Body "<H2>Temporary Internet Files - Last 5 days - Sorted by CreationTime</H2>" >> $ReportStep1

$a = $env:APPDATA ;Get-ChildItem -r -ea 0 $a\Microsoft\Windows\cookies | select Name | foreach-object {$N = $_.Name ;get-content -ea 0 $a\Microsoft\Windows\cookies\$N | select-string '/'} | 
ConvertTo-html -Body "<H2>Cookies</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Internet Explorer\TypedUrls' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Typed URLs</H2>" >>$ReportStep1
}

function regsearch {
Write-host "**** Pulling Registry Keys ****"
Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - Internet Settings</H2>" >> $ReportStep1

Get-ChildItem -ea 0 'hkcu:SOFTWARE\Microsoft\Windows\CurrentVersion\InternetSettings\ZoneMap\EscDomains' | select PSChildName | 
ConvertTo-html -Body "<H2>Important Registry keys - Internet Trusted Domains</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Microsoft\Windows NT\CurrentVersion\Windows' | select AppInit_DLLs | 
ConvertTo-html -Body "<H2>Important Registry keys - AppInit_DLLs</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\policies\system' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - UAC Group Policy Settings</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'HKLM:\Software\Microsoft\Active Setup\Installed Components\*' | select ComponentID,'(default)',StubPath  | 
ConvertTo-html -Body "<H2>Important Registry keys - Active setup Installs</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\App Paths\*' | select PSChildName, '(default)'  | 
ConvertTo-html  -Body "<H2>Important Registry keys - APP Paths keys</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\software\microsoft\windows nt\CurrentVersion\winlogon\*\*' | select '(default)',DllName | 
ConvertTo-html -Body "<H2>Important Registry keys - DLLs loaded by Explorer.exe shell</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\software\microsoft\windows nt\CurrentVersion\winlogon' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - shell and UserInit values</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\software\microsoft\security center\svc' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry Keys - Security center SVC values</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' | select * -ExcludeProperty PS* | 
ConvertTo-html  -Body "<H2>Important Registry keys - Desktop Address bar history</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\RunMru' | select * -ExcludeProperty PS* | 
ConvertTo-html  -Body "<H2>Important Registry keys - RunMRU keys</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\explorer\Startmenu' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - Start Menu</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2> Important Registry keys - Programs Executed By Session Manager</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Microsoft\Windows\CurrentVersion\explorer\ShellFolders' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - Shell Folders</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\ShellFolders' | select startup | 
ConvertTo-html -Body "<H2>Important Registry keys - User Shell Folders 'Startup'</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellExtensions\Approved' | select * -ExcludeProperty PS* |
ConvertTo-html  -Body "<H2>Important Registry keys - Approved Shell Extentions</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - AppCert DLLs</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Classes\exefile\shell\open\command' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - EXE File Shell Command Configured</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Classes\HTTP\shell\open\command' | select '(default)' |
ConvertTo-html -Body "<H2>Important Registry keys - Shell Commands</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\BCD00000000\*\*\*\*' | select Element |select-string 'exe' | select Line | 
ConvertTo-html -Body "<H2>Important Registry keys - BCD Related</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\system\currentcontrolset\control\lsa' | select * -ExcludeProperty PS* | 
ConvertTo-html -Body "<H2>Important Registry keys - LSA Packages loaded</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | select '(default)'| 
ConvertTo-html -Body "<H2>Important Registry keys - Browser Helper Objects</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | select '(default)' | 
ConvertTo-html -Body "<H2>Important Registry keys - Browser Helper Objects 64 Bit</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Internet Explorer\Extensions\*' | select ButtonText, Icon | 
ConvertTo-html -Body "<H2>Important Registry keys - IE Extensions </H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Microsoft\Internet Explorer\Extensions\*' | select ButtonText, Icon | 
ConvertTo-html -Body "<H2>Important Registry keys - IE Extensions</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions\*' | select ButtonText, Icon | 
ConvertTo-html -Body "<H2>Important Registry keys - IE Extensions</H2>" >> $ReportStep1
}

function filesysteminfo {
Write-host "**** Pulling File System Info ****"
Get-WmiObject -ea 0 Win32_ShortcutFile | select FileName,caption,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},@{NAME='LastAccessed';EXPRESSION={$_.ConvertToDateTime($_.LastAccessed)}},@{NAME='LastModified';EXPRESSION={$_.ConvertToDateTime($_.LastModified)}},Target | 
Where-Object  {$_.lastModified -gt ((Get-Date).addDays(-5)) } | sort LastModified -Descending | 
ConvertTo-html  -Body "<H2>Link File Analysis - Last 5 days</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | Where {$_.Attributes -band [IO.FileAttributes]::Compressed} | 
ConvertTo-html -Body "<H2>Compressed files</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | Where {$_.Attributes -band [IO.FileAttributes]::Encrypted} | 
ConvertTo-html -Body "<H2>Encrypted files</H2>" >> $ReportStep1

Get-WmiObject -ea 0 Win32_ShadowCopy | select DeviceObject,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.InstallDate)}} | 
ConvertTo-html -Body "<H2>ShadowCopy List</H2>" >> $ReportStep1

Get-ChildItem -path $env:systemroot\prefetch\*.pf -ea 0 | select Name, LastAccessTime,CreationTime | sort LastAccessTime | 
ConvertTo-html -Body "<H2>Prefetch Files</H2>" >> $ReportStep1

Get-ChildItem -path $env:systemroot\prefetch\ag*.db -ea 0 | select Name, LastAccessTime,CreationTime | sort LastAccessTime | 
ConvertTo-html -Body "<H2>Superfetch Files</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | % { Get-Item $_.FullName -stream * } | where stream -ne ':$Data' | 
ConvertTo-html -Body "<H2>Files with ADS</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -Include $InterestingFiles -recurse -Force -ea 0} | foreach-object {$_.Fullname} |
ConvertTo-html -Body "<H2>Interesting Files</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | Where-Object {$_.extension.length -le 1}
ConvertTo-html -Body "<H2>Files with no Extension</H2>" >> $ReportStep1

Get-ItemProperty -ea 0 'hklm:\system\currentcontrolset\enum\usbstor\*\*' | select FriendlyName,PSChildName,ContainerID | 
ConvertTo-html -Body "<H2>List of USB devices</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -include $ExecutableFiles -ea 0} | Where-Object  {-not $_.PSIsContainer -and $_.lastwritetime -gt ((Get-Date).addDays(-7)) } | select fullname,lastwritetime,@{N='Owner';E={($_ | Get-ACL).Owner}} | sort lastwritetime -desc | 
ConvertTo-html -Body "<H2>File Timeline Executable Files - Past 7 days</H2>" >> $ReportStep1

ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | ? {$_.lastwritetime -gt (Get-Date).AddDays(-7)} | 
ConvertTo-html -Body "<H2>Files modified in last 7 days</H2>" >> $ReportStep1
}

function securityevents {
Write-host "**** Pulling Top 50 Security Events ****"
$EID = @(4624,528,540)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='Application';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Account logon</H2>" >> $ReportStep1

$EID = @(4625,529,530,531,532,533,534,535,536,537,539)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - An account failed to log on</H2>" >> $ReportStep1

$EID = @(4616,520)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=4616,520} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - The system time was changed</H2>" >> $ReportStep1

$EID = @(1102,517)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Log Cleared</H2>" >> $ReportStep1

$EID = @(1002)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='application';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Application crashes</H2>" >> $ReportStep1

$EID = @(4688,592)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Process execution</H2>" >> $ReportStep1

$EID = @(4720,624)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - A user account was created</H2>" >> $ReportStep1

$EID = @(4648,552)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - A logon was attempted using explicit credentials</H2>" >> $ReportStep1

$EID = @(4672,576)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Privilege use 4672</H2>" >> $ReportStep1

$EID = @(4673,577)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Privilege use 4673</H2>" >> $ReportStep1

$EID = @(4674,578)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='security';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Privilege use 4674</H2>" >> $ReportStep1

$EID = @(7036)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - Service Control Manager events</H2>" >> $ReportStep1

$EID = @(64001)
Get-WinEvent -max 50 -ea 0 -FilterHashtable @{Logname='system';ID=$EID} | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Event log - WFP events</H2>" >> $ReportStep1

get-winevent -ea 0 -logname Microsoft-Windows-Application-Experience/Program-Inventory | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Application inventory events</H2>" >> $ReportStep1

get-winevent -ea 0 -logname Microsoft-Windows-TerminalServices-LocalSessionManager | select TimeCreated,ID,Message | 
ConvertTo-html -Body "<H2>Terminal services events</H2>" >> $ReportStep1
}

function iocsearch {
# Find all files in the IOC list
Import-CSV IOC_files.csv | Foreach-Object {
	If ( Test-Path $_.file ) {select $_.description, $_.file| 
	ConvertTo-html -Body "<H2>Files for known IOC values</H2>" >> $ReportStep1 }
	}
	
# Find all registry keys in the IOC list
Import-CSV IOC_reg.csv | Foreach-Object {
	If ( Test-Path $_.regkey ) {select $_.description, $_.regkey | 
	ConvertTo-html -Body "<H2>Registry Paths for known IOC values</H2>" >> $ReportStep1}
	}
	
# Find all registry values in the IOC list
Import-CSV IOC_reg.csv | Foreach-Object {
	If (Test-RegValue -Path $_.regkey -Value $_.regvalue) {select $_.description, $_.regkey, $_.regvalue | 
	ConvertTo-html -Body "<H2>Registry Values for known IOC values</H2>" >> $ReportStep1}
	}
	
function Test-RegValue {
param (
 [parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Path,
[parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]$Value
)
try {
Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
 return $true
 }
catch {
return $false
}
}
}

function getfiles {
$startdate = Read-Host 'What is the Starting date to pull files for? (mm/dd/yy)'
$enddate = Read-Host 'What is the Ending date to pull files for? (mm/dd/yy)'
ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | Where-Object {$_.lastwritetime -ge $startdate -AND $_.lastwritetime -le $enddate} > "$outfolder\$CompName-$User-$Date-FilesFromDate\" 
}

function getuserinfo {
Write-host "**** Pulling User-owned files and event log activity ****"
$Owner = Read-Host 'What is the username to pull infomation for?'
$ODate = Read-Host 'What is the starting date to pull infomation for? (mm-dd-yy)'
$SID = (Get-ADUser $Owner).sid
ForEach-Object {Get-Childitem ($_.DeviceID + "\") -recurse -Force -ea 0} | where { (Get-Acl $_).sddl -like "O:$SID*" } | select *,@{l='Owner';e={$Owner}} | 
ConvertTo-html -Body "<H2>Files Owned by User</H2>" >> $ReportStep1

Get-EventLog -ea 0 -LogName Security | Where-Object { $_.message -match $Owner -AND $_.Time -ge $ODate } | 
ConvertTo-html -Body "<H2>Security Event Logs by User</H2>" >> $ReportStep1

Get-EventLog -ea 0 -LogName Application | Where-Object { $_.User -eq $Owner -AND $_.Time -ge $ODate } | 
ConvertTo-html -Body "<H2>Application Event Logs by User</H2>" >> $ReportStep1

Get-EventLog -ea 0 -LogName System | Where-Object { $_.User -eq $Owner -AND $_.Time -ge $ODate } | 
ConvertTo-html -Body "<H2>System Event Logs by User</H2>" >> $ReportStep1

# copy registry hive for shellbag analysis
if ($copyvar = 'c') {
Copy-Item -ea 0 $env:systemdrive\users\$owner\ntuser.dat $outputfolder\$CompName-$owner-$Date_NTUSER.dat
Copy-Item -ea 0 $env:systemdrive\Users\$owner\AppData\Local\Microsoft\Windows\ $outputfolder\$CompName-$owner-$Date_USRCLASS.dat }
}

function netdump {
& .\tcpdump -D
$interface = Read-Host 'What is the above interface number to listen on?'
$pcapsize = Read-Host 'What is the max file size of the pcap files (MB)?'
& .\tcpdump -i $interface -C $pcapsize -vvv -w "$outfolder\$CompName-$Date_netdump.pcap"
}

function confirmation {$confirmation = read-host "Are you sure you want to exit? (y/n)"  
	if ($confirmation -eq "y"){finish}  
       if ($confirmation -eq "n"){mainmenu}  
           else {write-host -foregroundcolor red "Invalid Selection"   
                 confirmation  
                }  
 }
 
function diskdump {
$ddoutput = Read-Host 'What is the location for the DD copy?'
$ddrive = Read-Host 'What is drive to copy?'
.\dcfldd if=$ddrive hash=md5,sha256 hashwindow=10G md5log=$ddoutput\md5.txt sha256log=$ddoutput\sha256.txt \
       hashconv=after bs=512 conv=noerror,sync split=10G splitformat=aa of=$ddoutput\driveimage.dd
}

function finish {
# Popup message upon completion
(New-Object -ComObject wscript.shell).popup("Script Completed")

# Record end time of collection
date | select DateTime | ConvertTo-html -Body "<H2> Current Date and Time</H2>" >> $ReportStep1

Stop-Transcript
exit
}

startup
