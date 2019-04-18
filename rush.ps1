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
	#while(1){
		Write-Verbose -Message "Putting old rules into rules.txt!!!!"
		Get-NetFirewallRule | Out-File -FilePath "C:\Users\$($env:USERNAME)\Desktop\Storage\rules.txt" -NoClobber
		Write-Verbose -Message "Restoring firewall rules to default"
		netsh advfirewall reset
		netsh advfirewall set allprofiles state on
		netsh advfirewall firewall delete rule name=all
		netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
		Write-Verbose -Message "allow chrome!"
		netsh advfirewall firewall add rule Name="Chrome in" Program="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" Action=allow Dir=in
		netsh advfirewall firewall add rule Name="Chrome out" Program="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" Action=allow Dir=Out
		#Remove-NetFirewallRule -All 
		Write-Verbose -Message "*****************************"
		Write-Verbose -Message "BUILDING WALL"
		Write-Verbose -Message "*****************************"
		for($num = 21; $num -lt 2000; $num++){		
		#depending on box we don't want to block certain ports
		if($num -eq 80 -OR $num -eq 443 -OR $num -eq 53 -OR $num -eq 514){
			continue
		}
		Write-Verbose -Message "Blocking port + $num"
		Write-Verbose -Message "Blocking TCP"
		netsh advfirewall firewall add rule name="Blocktcp_in + $num" protocol=TCP dir=in localport=$num action=block
		netsh advfirewall firewall add rule name="Blocktcp_out + $num" protocol=TCP dir=out localport=$num action=block
		Write-Verbose -Message "Blocking UDP"
		netsh advfirewall firewall add rule name="Blocktcp_in + $num" protocol=UDP dir=in localport=$num action=block
		netsh advfirewall firewall add rule name="Blocktcp_out + $num" protocol=UDP dir=out localport=$num action=block
		}
	
		#Sleep for 180 seconds before running again
		#Start-Sleep -s 180
	#}
}

function stop_process{ 
	Write-Verbose -Message "Dummping running processes into proccess.txt"
	tasklist | Out-File "processes.txt"
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
	Get-Service | Out-File "services.txt"
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
	Try{
		Set-MpPreference -ScanParameters 2 -ScanScheduleDay 0 -ScanScheduleQuickScanTime 1 -UnknownThreatDefaultAction "Quarantine" -SevereThreatDefaultAction "Quarantine" -HighThreatDefaultAction "Quarantine" -LowThreatDefaultAction "Quarantine" -ModerateThreatDefaultAction "Quarantine" -CheckForSignaturesBeforeRunningScan 1 -DisableRealtimeMonitoring 0
		Start-MpScan -ThrottleLimit 0 -ScanType 1
		Write-Verbose -Message "Sleeping for 30 seconds then running full scan!"
		Start-Sleep 30
		Start-MpScan -ThrottleLimit 0 -ScanType 2
	}
	Catch{
		Try{
			C:\"Program Files"\"Windows Defender"\MpCmdRun.exe -Scan -ScanType 1
			Write-Verbose -Message "Sleeping for 60 seconds then running full scan!"
			Start-Sleep 30
			C:\"Program Files"\"Windows Defender"\MpCmdRun.exe -Scan -ScanType 2
		 }
		 Catch{
			$string_err = $_ | Out-String
            Write-Verbose -Message $string_err
		 }
	}
}

function dump_tasks{
	Write-Verbose "Putting scheduledtasks into tasks.txt"
	Get-ScheduledTask | Out-File "tasks.txt"
	Write-Verbose "Putting scheduledtask information into tasksinfo.txt"
	Get-ScheduledTask | Get-ScheduledTaskInfo | Out-File "tasksinfo.txt"
}

function app_lock{
	Write-Verbose -Message "Dumping local policy info" -Verbose
	Get-AppLockerPolicy -Local | Out-File "applocker_info.txt" 
	Write-Verbose -Message "dumping system32 applocker file info" -Verbose
	Get-AppLockerFileInformation -Directory C:\Windows\System32\ -Recurse -FileType Exe, Script | Out-File "sys32 info"
	Write-Verbose -Message "Applying new app locker policy for google"  -Verbose
	Get-AppLockerFileInformation -Directory "C:\Program Files (x86)\Google\" -Recurse -FileType Exe,DLL | New-AppLockerPolicy -RuleType Publisher, Path -User Everyone -XML -Optimize -IgnoreMissingFileInformation| Out-File "google.xml" | Set-AppLockerPolicy -XMLPolicy "google.xml"
	Write-Verbose -Message "Applying new app locker policy for scripts in user John folder"  -Verbose
	Get-AppLockerFileInformation -Directory C:\Users\John -Recurse -FileType Script | New-AppLockerPolicy -RuleType Publisher, Path -User Everyone -IgnoreMissingFileInformation -XML -Optimize| Out-File "ps_policy.xml" | Set-AppLockerPolicy -XMLPolicy "ps_policy.xml"
}

function install_packages{	
	$currentuser = $env:USERNAME
	choco feature enable -n=allowGlobalConfirmation
	# remove prompt
	choco install sysinternals
	#choco install firefox
	choco install eset.nod32
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
	New-LocalUser "kiwi" -Password $Password -FullName "Kiwis Suck" -Description "eats fruit, likes Ben Delpy"
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
	$orig_path = C:\Users\x\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
	ForEach($user in $ListUsers){
		Try{
			$path = $orig_path.replace('x',$user)
			$filename = "$($user)_history.txt"
			Write-Verbose -Message "Dumping: $user"
			Get-Content $path | Out-File $filename
			Move-Item -Path $path -Destination C:\Storage
			}
		Catch{
			$string_err = $_ | Out-String
            Write-Verbose -Message $string_err
			continue
		}
	}
}

function stop_scripts{
	$path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\"
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
			Write-Host "Could not change registry value for Windows Script Host do it manually here! $($path)"

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
function main{
	Clear
	#[CmdletBinding()] 
    $UserAccount = Get-LocalUser -Name "Administrator"
	Try{
		Write-Verbose -Message "Disabling SMB1" -Verbose
		Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart | Out-Null
		Write-Verbose -Message "Disabling SMB2" -Verbose
		Set-SmbServerConfiguration -EnableSMB2Protocol $false
		Write-Verbose -Message"Disabling SMB3" -Verbose
		Set-SmbServerConfiguration -EnableSMB3Protocol $false 
	}
	Catch{
		$string_err = $_ | Out-String
		Write-Verbose -Message $string_err -verbose
	}
	Write-Verbose -Message "Disabling RDP!!!" -verbose
	try{
			Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
			Write-Verbose -Message "RDP Disabled"
		}
	Catch{
		$string_err = $_ | Out-String
		 Write-Verbose -Message $string_err -verbose
	}
	Write-Verbose -Message "Creating directory C:\Users\$($env:USERNAME)\Desktop\Storage"
	New-Item -Path "C:\Users\$($env:USERNAME)\Desktop" -Name "Storage" -ItemType "directory"
	install_chocolate
	install_packages
	dump_tasks
	change_users
	read_history
	process_poker
	fruit_user
	build_wall
	stop_scripts
	lockdown_pol
	#app_lock
	#stop_process
	#build_wall
	#scan
	# -Scope LocalMachine
	# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
	# (IWR -Uri "http://tinyurl.com/y5fwusjg" -MaximumRedirection 2 ).Content | IEX
}

main

