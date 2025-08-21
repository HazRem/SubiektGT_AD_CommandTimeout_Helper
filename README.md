SubiektGT AD CommandTimeout Helper

    An interactive PowerShell utility for Active Directory administrators to quickly look up users, view the Command Timeout setting for InsERT Subiekt GT, and either navigate to or modify the value in the registry.

This tool is designed to solve a specific, recurring administrative task: checking and setting the Command Timeout registry value for users of Subiekt GT, directly referencing them via their Active Directory account.

✨ Features

    🔎 Interactive AD User Search: Instantly lists all Active Directory users and allows for real-time filtering by Name, SamAccountName, or SID.

    📈 Live Registry Data: For each user in the filtered list, it queries the local machine's registry to display the current Command Timeout value, showing a - if it's not set.

    🔧 Action Menu: After selecting a user by their index number, you can choose to:

        Open the Registry: Instantly opens regedit.exe directly to the user's specific Connection Properties key.

        Set the Value: Automatically creates or updates the Command Timeout DWORD value, setting it to 0. The script handles the creation of the required keys if they don't exist.

    🚀 Self-Elevating: The script automatically checks if it has administrator rights and will prompt for elevation if needed, ensuring it always has the permissions to perform registry operations.

🚀 Requirements

    Windows PowerShell 5.1 or PowerShell 7+

    Active Directory Module for Windows PowerShell (This is part of the Remote Server Administration Tools - RSAT).

    Administrator Privileges (the script will prompt for elevation automatically).

    Network access to an Active Directory Domain Controller.

🛠️ Usage

    Download the Get-SubiektCommandTimeout.ps1 script to your machine.

    Right-click the file and choose "Run with PowerShell".

    The script will request administrator privileges if it doesn't have them. Click "Yes" on the UAC prompt.

    The terminal will open and display a list of all users.

    Follow the on-screen prompts:

        Type a filter (e.g., a user's last name) and press Enter to narrow down the list.

        Type the index number of the user you want to manage and press Enter.

        Choose an action from the menu (open registry or set value) and press Enter.

PowerShell

# Example of running from an already-elevated PowerShell terminal
PS C:\Scripts> .\Get-SubiektCommandTimeout.ps1

⚙️ Configuration

The registry path and value name are hardcoded within the script for convenience. If you need to target a different setting or a different version of the software, you can easily modify the variables in the foreach loop section of the script.

Variables to change:

    $regQueryPath: The full path to the registry key.

    $valueName: The name of the registry value to read.

PowerShell

# Snippet from the script showing the configurable variables
$regQueryPath = "Registry::HKEY_USERS\$sid\Software\InsERT\InsERT GT\dbman\1.0\Connection Properties"
$valueName = "Command Timeout"

📄 License

This project is licensed under the MIT License. See the LICENSE file for details.
