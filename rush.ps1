# 
#	This script does simple things but oh so well :) 
#	@Author: Rebel
#
#Set-ExecutionPolicy RemoteSigned
#./MpCmdRun.exe -Scan -ScanType 2
#https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/command-line-arguments-windows-defender-antivirus
Write-Verbose -Message "**********"
Write-Verbose -Message "TRY HARDER"
Write-Verbose -Message "**********"

function build_wall{
	$choice = '33'
	#while(1){
		Write-Verbose -Message "Putting old rules into rules.txt!!!!"
		Get-NetFirewallRule | Out-File -FilePath "C:\Users\$($env:USERNAME)\Desktop\Storage\rules.txt" -NoClobber
		Write-Verbose -Message "Restoring firewall rules to default"
		#might be worth setting up as a schedule  task
		netsh advfirewall reset
		netsh advfirewall set allprofiles state on
		netsh advfirewall firewall delete rule name=all
		netsh advfirewall set allprofiles firewallpolicy,blockinbound,blockoutbound
		Write-Verbose -Message "allow chrome!"
		netsh advfirewall firewall add rule Name="Chrome in" Program="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" Action=allow Dir=in
		netsh advfirewall firewall add rule Name="Chrome out" Program="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" Action=allow Dir=Out
		#Remove-NetFirewallRule -All 
		netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:any,any dir=in action=allow
		netsh advfirewall firewall add rule name="Allow ICMP out" protocol=icmpv4:any,any dir=out action=allow
		netsh advfirewall firewall add rule name="Open Port 53" dir=in action=allow protocol=UDP localport=53
		netsh advfirewall firewall add rule name="Open Port 53" dir=out action=allow protocol=UDP localport=53
		netsh advfirewall firewall add rule name="Open Port 53" dir=in action=allow protocol=TCP localport=53
		netsh advfirewall firewall add rule name="Open Port 53" dir=out action=allow protocol=TCP localport=53
		netsh advfirewall firewall add rule name="Open Port 67" dir=in action=allow protocol=UDP localport=67
		netsh advfirewall firewall add rule name="Open Port 67" dir=out action=allow protocol=UDP localport=67
		netsh advfirewall firewall add rule name="Open Port 68" dir=in action=allow protocol=UDP localport=68
		netsh advfirewall firewall add rule name="Open Port 68" dir=out action=allow protocol=UDP localport=68
		
		if($choice -eq '1'){
		
		}
		
		if($choice -eq '2'){
		
		}
		
	Write-Verbose -Message "Configuring logs."
	netsh advfirewall set currentprofile logging filename "C:\Users\$($env:USERNAME)\Desktop\Storage\firewall.log"
	netsh advfirewall set currentprofile logging maxfilesize 4096
	netsh advfirewall set currentprofile logging droppedconnections enable
	netsh advfirewall set currentprofile logging allowedconnections enable
	
}

function stop_process{ 
	Write-Verbose -Message "Dummping running processes into proccess.txt"
	tasklist | Out-File "C:\Users\$($env:USERNAME)\Desktop\Storage\processes.txt"
	$tasklist = tasklist.exe
	$tasklist = $tasklist.Split(" ") 
	$truetaskList =  @()

	ForEach($task in $tasklist){
		if (($task -match '.exe' -OR -$task -match '.py' -OR $task -match '.ps1') -and -Not($truetaskList.Contains($task)) -and -Not($task -match 'powershell')){
			$truetaskList += $task
		}
	}

	ForEach($task in $truetaskList){
		Try{
			$truetask = $task.Substring(0,$task.Length-4)
            if($truetask -eq "powershell.exe" -OR $truetask -eq "rush.ps1"){
                continue
            }
			Write-Verbose -Message "Stopping: $truetask"
			Stop-Process -Name $truetask 
		}
		Catch{
			continue 
		}
	}
}

function process_poker{
	Write-Verbose -Message "Dumping current processes"
	Get-Service | Out-File "C:\Users\$($env:USERNAME)\Desktop\services.txt"
}

function change_users{
	$Accounts =  Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount = True"
	$ListUsers = @()
	$currentuser = $env:USERNAME
	$Accounts = $Accounts -split ' '
	ForEach($account in $Accounts){
		$stringAccount = [string]$account -split '"'
        $user = $stringAccount[3]
        $ListUsers += $user
	}
	#Disable-LocalUser -Name $username
	$Password = (ConvertTo-SecureString -AsPlainText "IHateKiwis!" -Force)
	ForEach($user in $ListUsers){
		Try{
			Write-Verbose -Message "Changing password for User: $user"
			$User | Set-LocalUser -Password $Password
			Write-Verbose -Message "Successfully changed password for $User"
		}
		Catch{
			$string_err = $_ | Out-String
			Write-Verbose -Message $string_err
			continue
		}
	}
}

function scan{
	Write-Verbose -Message "Starting quick scan!!!!!!!"
	Set-MpPreference -EnableNetworkProtection Enabled
	Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent Always
	Set-MpPreference -ScanParameters 2 -ScanScheduleDay 0 -ScanScheduleQuickScanTime 1 -UnknownThreatDefaultAction "Quarantine" -SevereThreatDefaultAction "Quarantine" -HighThreatDefaultAction "Quarantine" -LowThreatDefaultAction "Quarantine" -ModerateThreatDefaultAction "Quarantine" -CheckForSignaturesBeforeRunningScan 1 -DisableRealtimeMonitoring 0
	Try{
		Add-MpPreference -AttackSurfaceReductionRules_Ids '3B576869-A4EC-4529-8536-B80A7769E899' -AttackSurfaceReductionRules_Actions Enabled
		Add-MpPreference -AttackSurfaceReductionRules_Ids '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' -AttackSurfaceReductionRules_Actions Enabled
		Add-MpPreference -AttackSurfaceReductionRules_Ids 'D3E037E1-3EB8-44C8-A917-57927947596D' -AttackSurfaceReductionRules_Actions Enabled
	}
	Catch{
		Add-MpPreference -AttackSurfaceReductionRules_Ids '3B576869-A4EC-4529-8536-B80A7769E899' -AttackSurfaceReductionRules_Actions enable
		Add-MpPreference -AttackSurfaceReductionRules_Ids '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' -AttackSurfaceReductionRules_Actions enable
		Add-MpPreference -AttackSurfaceReductionRules_Ids 'D3E037E1-3EB8-44C8-A917-57927947596D' -AttackSurfaceReductionRules_Actions enable
	}
	(IWR -Uri "https://raw.githubusercontent.com/Bad3r/IRSEC2019-BlueTeam/master/policy.xml?token=AIVA5C4WFLR4QBWEJSB5OUC4YIU66" -UseBasicParsing).Content | Out-File policy.xml
	New-CIPolicy -Level FilePublisher -FilePath policy.xml -OmitPaths "C:\Windows\WinSxs\" -ScanPath C:\ -UserPEs -Fallback Hash
	Try{
		Start-MpScan -ThrottleLimit 0 -ScanType 1
		#Write-Verbose -Message "Sleeping for 30 seconds then running full scan!"
		#Start-Sleep 30
		#Start-MpScan -ThrottleLimit 0 -ScanType 2
	}
	Catch{
		Try{
			C:\"Program Files"\"Windows Defender"\MpCmdRun.exe -Scan -ScanType 1
			#Write-Verbose -Message "Sleeping for 60 seconds then running full scan!"
			#Start-Sleep 30
			#C:\"Program Files"\"Windows Defender"\MpCmdRun.exe -Scan -ScanType 2
		 }
		 Catch{
			$string_err = $_ | Out-String
            Write-Verbose -Message $string_err
		 }
	}
}

function dump_tasks{
	$cur = $env:USERNAME
	Write-Verbose "Putting scheduledtasks into tasks.txt"
	tasklist | Out-File "C:\Users\$($cur)\Desktop\Storage\tasks.txt"
	Write-Verbose "Putting scheduledtask information into tasksinfo.txt"
	Get-ScheduledTask | ? state -eq running | Get-ScheduledTaskInfo | Out-File "C:\Users\$($cur)\Storage\running_scheduled_tasks.txt"
}

function app_lock{
	Set-Service -Name "AppIDSvc" -StartupType Automatic
	Start-Service -Name "AppIDSvc"
	#make sure to start the service or all will be in vein
	Try{
		(IWR -Uri "https://raw.githubusercontent.com/MotiBa/AppLocker/master/Policies/AppLocker-Block-Paths.xml" -UseBasicParsing).Content | Out-File first.xml
		(IWR -Uri "https://raw.githubusercontent.com/MotiBa/AppLocker/master/Policies/AppLocker-Block-Publishers.xml" -UseBasicParsing).Content | Out-File second.xml
		Get-ChildItem C:\Windows\System32\*.exe | Get-AppLockerFileInformation | New-AppLockerPolicy -RuleType Path -User Everyone -Optimize -ServiceEnforcement Enabled -XML | Out-File deny.xml
		Get-ChildItem C:\Windows\System32\*.exe | Get-AppLockerFileInformation | New-AppLockerPolicy -RuleType Path -User "$($env:USERNAME), Kiwi" -Optimize -ServiceEnforcement Enabled -XML  | Out-File allow.xml
		#Add Kiwi
		Write-Verbose -Message "Setting first.xml\n\n"
		Set-AppLockerPolicy -XMLPolicy first.xml
		Write-Verbose -Message "Setting second.xml\n\n"
		Set-AppLockerPolicy -XMLPolicy second.xml -User Everyone
		Write-Verbose -Message "Setting deny.xml\n\n"
		Set-AppLockerPolicy -XMLPolicy deny.xml 
		Write-Verbose -Message "Setting allow.xml"
		Set-AppLockerPolicy -XMLPolicy allow.xml 
	}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
	# make sure app locker is running!
	#IWR(-Uri "http://tinyurl.com/y5fwusjg" -MaximumRedirection 2).Content
	#Write-Verbose -Message "Dumping local policy info" -Verbose
	#Get-AppLockerPolicy -Local | Out-File "applocker_info.txt" 
	#Write-Verbose -Message "dumping system32 applocker file info" -Verbose
	#Get-AppLockerFileInformation -Directory C:\Windows\System32\ -Recurse -FileType Exe, Script | Out-File "sys32 info"
	#Write-Verbose -Message "Applying new app locker policy for google"  -Verbose
	#Get-AppLockerFileInformation -Directory "C:\Program Files (x86)\Google\" -Recurse -FileType Exe,DLL | New-AppLockerPolicy -RuleType Publisher, Path -User Everyone -XML -Optimize -IgnoreMissingFileInformation| Out-File "google.xml" | Set-AppLockerPolicy -XMLPolicy "google.xml"
	#Write-Verbose -Message "Applying new app locker policy for scripts in user John folder"  -Verbose
	#Get-AppLockerFileInformation -Directory C:\Users\John -Recurse -FileType Script | New-AppLockerPolicy -RuleType Publisher, Path -User Everyone -IgnoreMissingFileInformation -XML -Optimize| Out-File "ps_policy.xml" | Set-AppLockerPolicy -XMLPolicy "ps_policy.xml"
}

function install_packages{	
	$currentuser = $env:USERNAME
	$chrome_path = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
	choco feature enable -n=allowGlobalConfirmation
	# remove prompt
	if([System.IO.File]::Exists($path) -eq $false){
		#if chrome exists don't waste time installing it again
		choco install googlechrome
	}
	choco install sysinternals
	choco install malwarebytes
	#Get-ChildItem -Path x 
	#choco install splunk-universalforwarder

	#choco install notepadplusplus
	choco install processhacker
}

function install_chocolate{
	Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function fruit_user{
	Write-Verbose -Message "Adding user kiwi!"
	$Password = (ConvertTo-SecureString -AsPlainText "KiwisAreNotFun" -Force)
	New-LocalUser "Kiwi" -Password $Password -FullName "Kiwi" -Description "Eats fruit, likes Ben Delpy"
	Add-LocalGroupMember -Group "Administrators" -Member "kiwi"
}

function read_history{
    $Accounts =  Get-WmiObject -Class Win32_UserAccount -filter "LocalAccount = True"
	$ListUsers = @()
	$currentuser = $env:USERNAME
	$Accounts = $Accounts -split ' '
	ForEach($account in $Accounts){
		$stringAccount = [string]$account -split '"'
        $user = $stringAccount[3]
        $ListUsers += $user
	}
	$orig_path = "C:\Users\x\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
	ForEach($user in $ListUsers){
		Try{
			Write-Host "User: $user"
			$path = $orig_path.replace('x',[string]$user)
			$filename = "$($user)_history.txt"
			Write-Verbose -Message "Dumping: $user"
			Get-Content $path | Out-File $filename
			Move-Item -Path $path -Destination "C:\$($env:USERNAME)\Desktop\Storage"
			}
		Catch{
			$string_err = $_ | Out-String
            Write-Verbose -Message $string_err
			continue
		}
	}
}

function stop_scripts{
	$path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
	Try{
		New-ItemProperty -Path $path -Name "Enabled" -Value 0 -PropertyType "DWord"
	}
	Catch{
		Try{
			Set-ItemProperty -Path $path -Name "Enabled" -Value 0
			# if name already exists just set the value from 1 to 0

		}
		Catch{
			Write-Verbose -Message "Could not change registry value for Windows Script Host do it manually here! $path"
			Write-Host "Could not change registry value for Windows Script Host do it manually here! $path"

		}
	}
}

function lockdown_pol{
	Write-Verbose -Message "Setting lockdown policy" -verbose
	Try{
		[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
	}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
}

function harden{
	$UserAccount = Get-LocalUser -Name "Administrator"
	Try{
		Write-Verbose -Message "Disabling SMB1" -Verbose
		Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart 
		#Write-Verbose -Message "Disabling SMB2" -Verbose
		#Set-SmbServerConfiguration -EnableSMB2Protocol $false
		#Write-Verbose -Message"Disabling SMB3" -Verbose
		#Set-SmbServerConfiguration -EnableSMB3Protocol $false 
	}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
	Write-Verbose -Message "Disabling RDP!!!" -verbose
	Try{
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
			Write-Verbose -Message "RDP Disabled"
		}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
	Write-Verbose -Message "Removing Powershellv2" -verbose
	Try{
		Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart
	}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
	Try{
			Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
	}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
	$systemroot = "C:\Windows"
	ftype htafile="$($systemroot)\system32\NOTEPAD.EXE" "%1"
	ftype WSHFile="$($systemroot)\system32\NOTEPAD.EXE" "%1"
	ftype batfile="$($systemroot)\system32\NOTEPAD.EXE" "%1"
	#General OS hardening
    #Disables DNS multicast, netbios
    #Enables UAC and sets to always notify
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
	net stop WinRM
	wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
	
    #Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
    #Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2	
	#Harden lsass to help protect against credential dumping (mimikatz)
    #Configures lsass.exe as a protected process and disabled wdigest
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
	
	#Enable Windows Firewall and configure some advanced options
	#Block Win32 binaries from making netconns when they shouldn't
	netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="$($systemroot)\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
	netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="$($systemroot)\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
	netsh advfirewall firewall add rule name="Block calc.exe netconns" program="$($systemroot)\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
	netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="$($systemroot)\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
	netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="$($systemroot)\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
	netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="$($systemroot)\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
	netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="$($systemroot)\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
}


function main{
	# New-CIPolicy -Level FilePublisher -FilePath C:\MyCIPolicy\My_Initial_CI_Policy.xml -ScanPath C:\ -UserPEs -Fallback Hash
	Clear
	#-Scope LocalMachine
	# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
	# (IWR -Uri "http://tinyurl.com/y5fwusjg" -MaximumRedirection 2 -UseBasicParsing).Content | IEX
	#[CmdletBinding()] 
	Write-Verbose -Message "Creating directory C:\Users\$($env:USERNAME)\Desktop\Storage"
	New-Item -Path "C:\Users\$($env:USERNAME)\Desktop" -Name "Storage" -ItemType "directory"
	change_users
	harden
	install_chocolate
	install_packages
	dump_tasks
	read_history
	process_poker
	fruit_user
	app_lock
	build_wall
	stop_scripts
	scan
	lockdown_pol
	#positional paramter can not be found for sc start=auto
	#Set-AppLockerPolicy
}	

main

