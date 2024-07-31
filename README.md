
# Requirements

- Windows 10.
- PowerShell (Running with Administrator Privileges).
- PowerShell 5.1 or later

# Features

The script offers the following functionalities:

- System Information Gathering: Collects basic details about the system, including computer name, Windows version, and OS architecture.
- Windows Update Check: Verifies if any pending Windows updates are available.
- Weak Password Detection: Identifies user accounts with potentially weak passwords (simulation based on common criteria).
- Running Services Listing: Displays a list of currently running services.
- Firewall Status Check: Retrieves information about the Windows Firewall status, including enabled state and default inbound/outbound actions.
- Critical Services Check: Verifies the status of critical services like spooler, BITS, and wuauserv.
- Open Port Check: Scans for specific ports (e.g., 80, 443, 3306) to identify open ports.
- File and Folder Permission Check: Analyzes permissions for files and folders within a specified path (e.g., C:\Windows).
- User Account Audit: Retrieves information about local user accounts, including username, enabled status, password expiration, and last logon time.
- Group Policy Review: Generates an HTML report summarizing the group policy settings applied to the system (requires GroupPolicy module).
- Installed Software Listing: Provides a list of installed software retrieved from the Win32_Product WMI class.
- Disk Usage Analysis: Calculates and displays used and free space (in GB) for each mounted disk drive.
- Event Log Review: Retrieves the most recent ten entries from the Security event log.
- Network Configuration Check: Displays details about network interfaces, including IP addresses and default gateway.
- System Performance Metrics: Gathers CPU usage and available memory statistics.
- Scheduled Task Audit: Lists scheduled tasks with their names, state, and last run time.
- Report Generation: Creates a JSON report containing the results of all audit checks, saved to C:\temp\pentest_report.json.

# Usage

- Save the script content as a .ps1 file 
- Right-click on the script file and select ***Run with PowerShell (Admin).***
- The script will display a menu with available options.
- Select the desired option by entering the corresponding ***number (1-18) and press Enter.***
- The script will execute the chosen check and display the results.
- To generate a report containing all audit results, select option 17. The report will be saved as ***a JSON file (C:\temp\pentest_report.json by default).***
- Option 18 provides additional help information about the script.
- Enter '0' and press Enter to exit the script.

# Example Output

Selecting option 1 (System Information) might produce output similar to:

          CsName                 : DESKTOP-AB12345
          WindowsVersion         : 10.0.19044.1701
          WindowsBuildLabEx      : 2009
          OsArchitecture         : x64

# Contributing

- We value contributions, feel free to fork the repository and contribute to the improvement of this Tool.
