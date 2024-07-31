
function Show-Menu {
    Clear-Host
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "      Windows Audit Tool      " -ForegroundColor Cyan
    Write-Host "============================="
    Write-Host "1. Collect System Information"
    Write-Host "2. Check Windows Updates"
    Write-Host "3. Check Weak Passwords"
    Write-Host "4. List Running Services"
    Write-Host "5. Check Firewall"
    Write-Host "6. Check Critical Services"
    Write-Host "7. Check Open Ports"
    Write-Host "8. Check File and Folder Permissions"
    Write-Host "9. Audit User Accounts"
    Write-Host "10. Review Group Policy Settings"
    Write-Host "11. List Installed Software"
    Write-Host "12. Analyze Disk Usage"
    Write-Host "13. Review Event Logs"
    Write-Host "14. Check Network Configuration"
    Write-Host "15. Gather System Performance Metrics"
    Write-Host "16. Audit Scheduled Tasks"
    Write-Host "17. Generate Report"
    Write-Host "18. Help"
    Write-Host "0. Exit"
    Write-Host "============================="
}

function Show-Help {
    Clear-Host
    Write-Host "=============================" -ForegroundColor Cyan
    Write-Host "          Help              " -ForegroundColor Cyan
    Write-Host "============================="
    Write-Host  "This script performs a comprehensive security audit on a Windows 10 system."
    Write-Host 
                "Choose an option from the menu to perform specific checks."
    Write-Host 
                "Each option will provide detailed information about the system's security posture."
    Write-Host  "Press Enter to return to the main menu."
    Read-Host
}

function Get-SystemInfo {
    try {
        Write-Host "Collecting system information..." -ForegroundColor Yellow
        $systemInfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, WindowsBuildLabEx, OsArchitecture
        return $systemInfo
    } catch {
        Write-Host "Error collecting system information: $_" -ForegroundColor Red
    }
}

function Check-WindowsUpdates {
    try {
        Write-Host "Checking Windows updates..." -ForegroundColor Yellow
        Import-Module PSWindowsUpdate -ErrorAction Stop
        $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot
        if ($updates) {
            Write-Host "Available updates:" -ForegroundColor Yellow
            return $updates
        } else {
            Write-Host "The system is up-to-date." -ForegroundColor Green
            return $null
        }
    } catch {
        Write-Host "Error checking Windows updates: $_" -ForegroundColor Red
    }
}

function Check-WeakPasswords {
    try {
        Write-Host "Checking for weak passwords..." -ForegroundColor Yellow
        $weakPasswords = @()
        $users = Get-LocalUser
        foreach ($user in $users) {
            if ($user.PasswordNeverExpires -eq $false -and $user.Enabled -eq $true) {
                # Simulate a weak password check based on common criteria
                if ($user.PasswordRequired -eq $true) {
                    Write-Host "User: $($user.Name) - Password may be weak." -ForegroundColor Red
                    $weakPasswords += $user.Name
                }
            }
        }
        return $weakPasswords
    } catch {
        Write-Host "Error checking weak passwords: $_" -ForegroundColor Red
    }
}

function List-RunningServices {
    try {
        Write-Host "Listing running services..." -ForegroundColor Yellow
        $runningServices = Get-Service | Where-Object { $_.Status -eq 'Running' }
        return $runningServices
    } catch {
        Write-Host "Error listing running services: $_" -ForegroundColor Red
    }
}

function Check-Firewall {
    try {
        Write-Host "Checking the Windows Firewall..." -ForegroundColor Yellow
        $firewallProfile = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
        return $firewallProfile
    } catch {
        Write-Host "Error checking the firewall: $_" -ForegroundColor Red
    }
}

function Check-CriticalServices {
    try {
        Write-Host "Checking critical services..." -ForegroundColor Yellow
        $criticalServices = Get-Service | Where-Object { $_.Name -in ('spooler', 'bits', 'wuauserv') }
        return $criticalServices
    } catch {
        Write-Host "Error checking critical services: $_" -ForegroundColor Red
    }
}

function Check-OpenPorts {
    try {
        Write-Host "Checking open ports..." -ForegroundColor Yellow
        $portsToCheck = @(80, 443, 3306)
        $openPorts = @()
        foreach ($port in $portsToCheck) {
            $result = Test-NetConnection -Port $port -InformationLevel Quiet
            if ($result) {
                $openPorts += $port
            }
        }
        return $openPorts
    } catch {
        Write-Host "Error checking open ports: $_" -ForegroundColor Red
    }
}

function Check-FilePermissions {
    try {
        Write-Host "Checking file and folder permissions..." -ForegroundColor Yellow
        $filePermissions = Get-ChildItem -Path 'C:\Windows' -Force | 
            Select-Object Name, @{Name='Permissions';Expression={(Get-Acl $_.FullName).Access.IdentityReference}}
        return $filePermissions
    } catch {
        Write-Host "Error checking file permissions: $_" -ForegroundColor Red
    }
}

function Audit-UserAccounts {
    try {
        Write-Host "Auditing user accounts..." -ForegroundColor Yellow
        $userAccounts = Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires, LastLogon
        return $userAccounts
    } catch {
        Write-Host "Error auditing user accounts: $_" -ForegroundColor Red
    }
}

function Review-GroupPolicy {
    try {
        Write-Host "Reviewing group policy settings..." -ForegroundColor Yellow
        Import-Module GroupPolicy -ErrorAction Stop
        $gpoSettings = Get-GPResultantSetOfPolicy -Scope Computer -ReportType Html -Path "C:\temp\GPOReport.html"
        Write-Host "Group Policy report generated at C:\temp\GPOReport.html" -ForegroundColor Green
    } catch {
        Write-Host "Error reviewing group policy: $_" -ForegroundColor Red
    }
}

function List-InstalledSoftware {
    try {
        Write-Host "Listing installed software..." -ForegroundColor Yellow
        $installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
        return $installedSoftware
    } catch {
        Write-Host "Error listing installed software: $_" -ForegroundColor Red
    }
}

function Analyze-DiskUsage {
    try {
        Write-Host "Analyzing disk usage..." -ForegroundColor Yellow
        $diskUsage = Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name='Used(GB)';Expression={[math]::round($_.Used/1GB,2)}}, @{Name='Free(GB)';Expression={[math]::round($_.Free/1GB,2)}}
        return $diskUsage
    } catch {
        Write-Host "Error analyzing disk usage: $_" -ForegroundColor Red
    }
}

function Review-EventLogs {
    try {
        Write-Host "Reviewing event logs..." -ForegroundColor Yellow
        $eventLogs = Get-EventLog -LogName Security -Newest 10 | Select-Object TimeGenerated, EntryType, Message
        return $eventLogs
    } catch {
        Write-Host "Error reviewing event logs: $_" -ForegroundColor Red
    }
}

function Check-NetworkConfiguration {
    try {
        Write-Host "Checking network configuration..." -ForegroundColor Yellow
        $networkConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DefaultGateway
        return $networkConfig
    } catch {
        Write-Host "Error checking network configuration: $_" -ForegroundColor Red
    }
}

function Gather-PerformanceMetrics {
    try {
        Write-Host "Gathering system performance metrics..." -ForegroundColor Yellow
        $cpuUsage = Get-Counter -Counter '\Processor Information(_Total)\% Processor Time' -MaxSamples 1
        $memoryUsage = Get-Counter -Counter '\Memory\Available MBytes' -MaxSamples 1
        return @{
            CPUUsage = $cpuUsage.CounterSamples.CookedValue
            FreeMemory = $memoryUsage.CounterSamples.CookedValue
        }
    } catch {
        Write-Host "Error gathering performance metrics: $_" -ForegroundColor Red
    }
}

function Audit-ScheduledTasks {
    try {
        Write-Host "Auditing scheduled tasks..." -ForegroundColor Yellow
        $scheduledTasks = Get-ScheduledTask | Select-Object TaskName, State, LastRunTime
        return $scheduledTasks
    } catch {
        Write-Host "Error auditing scheduled tasks: $_" -ForegroundColor Red
    }
}

function Generate-Report {
    try {
        Write-Host "Generating report..." -ForegroundColor Yellow
        $report = @{
            SystemInfo = Get-SystemInfo
            WindowsUpdates = Check-WindowsUpdates
            WeakPasswords = Check-WeakPasswords
            RunningServices = List-RunningServices
            Firewall = Check-Firewall
            CriticalServices = Check-CriticalServices
            OpenPorts = Check-OpenPorts
            FilePermissions = Check-FilePermissions
            UserAccounts = Audit-UserAccounts
            GroupPolicy = Review-GroupPolicy
            InstalledSoftware = List-InstalledSoftware
            DiskUsage = Analyze-DiskUsage
            EventLogs = Review-EventLogs
            NetworkConfiguration = Check-NetworkConfiguration
            PerformanceMetrics = Gather-PerformanceMetrics
            ScheduledTasks = Audit-ScheduledTasks
        }
        $report | ConvertTo-Json | Out-File -FilePath 'C:\temp\pentest_report.json'
        Write-Host "Report generated at C:\temp\pentest_report.json" -ForegroundColor Green
    } catch {
        Write-Host "Error generating report: $_" -ForegroundColor Red
    }
}

do {
    Show-Menu
    $choice = Read-Host "Choose an option"

    if ($choice -match '^[0-9]+$' -and [int]$choice -ge 0 -and [int]$choice -le 18) {
        switch ($choice) {
            '1' { $result = Get-SystemInfo; $result | Format-List }
            '2' { $result = Check-WindowsUpdates; if ($result) { $result | Format-Table } }
            '3' { $result = Check-WeakPasswords; if ($result) { $result | Format-Table } }
            '4' { $result = List-RunningServices; $result | Format-Table }
            '5' { $result = Check-Firewall; $result | Format-Table }
            '6' { $result = Check-CriticalServices; $result | Format-Table }
            '7' { $result = Check-OpenPorts; $result | Format-Table }
            '8' { $result = Check-FilePermissions; $result | Format-Table }
            '9' { $result = Audit-UserAccounts; $result | Format-Table }
            '10' { Review-GroupPolicy }
            '11' { $result = List-InstalledSoftware; $result | Format-Table }
            '12' { $result = Analyze-DiskUsage; $result | Format-Table }
            '13' { $result = Review-EventLogs; $result | Format-Table }
            '14' { $result = Check-NetworkConfiguration; $result | Format-Table }
            '15' { $result = Gather-PerformanceMetrics; $result | Format-Table }
            '16' { $result = Audit-ScheduledTasks; $result | Format-Table }
            '17' { Generate-Report }
            '18' { Show-Help }
            '0' { Write-Host "Exiting..." -ForegroundColor Red; exit }
        }

        if ($result) {
            Write-Host "`nResult:" -ForegroundColor Green
            $result
        }
    } else {
        Write-Host "Invalid option, please try again." -ForegroundColor Red
    }

    Read-Host "Press Enter to continue..."
} while ($true)
