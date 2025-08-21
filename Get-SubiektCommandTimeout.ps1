<#
.SYNOPSIS
  List all AD users with SID and allow repeated filtering, with indexes.
  Reads a specific registry value for each displayed user.
  After selecting a user, allows choosing between opening the registry or setting a DWORD value.
#>

# Automatyczne żądanie uprawnień administratora
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrator privileges to function correctly. Re-launching..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -File `"$PSCommandPath`""
    exit
}

Import-Module ActiveDirectory

# Pobierz wszystkich użytkowników z SID
$users = Get-ADUser -Filter * -Properties SID |
    Select-Object Name, SamAccountName, SID

Write-Host "Found $($users.Count) users in AD." -ForegroundColor Cyan
Write-Host "You can filter by Name, SamAccountName, or SID." -ForegroundColor Yellow
Write-Host "After filtering, type an index number to choose an action for that user." -ForegroundColor Yellow

# Zmienna do przechowywania ostatniego zestawu wyników
$lastResults = $null

# Pętla filtrowania
while ($true) {
    $input = Read-Host "`nEnter filter, index number, or 'exit'"

    if ($input -eq "exit") {
        Write-Host "Exiting..." -ForegroundColor Red
        break
    }

    # BLOK: Sprawdź, czy wprowadzono numer indeksu, aby wybrać akcję
    if ($input -match '^\d+$') {
        $index = [int]$input
        if ($null -eq $lastResults) {
            Write-Host "Please perform a search first before selecting an index." -ForegroundColor DarkYellow
            continue
        }

        if ($index -ge 1 -and $index -le $lastResults.Count) {
            $selectedUser = $lastResults[$index - 1]
            $sid = $selectedUser.SID.Value
            
            # Zdefiniuj ścieżki dla Edytora Rejestru i dostawcy PowerShell
            $regPathForRegedit = "HKEY_USERS\$sid\Software\InsERT\InsERT GT\dbman\1.0\Connection Properties"
            $regPathForPS = "Registry::HKEY_USERS\$sid\Software\InsERT\InsERT GT\dbman\1.0\Connection Properties"

            # >>> POCZĄTEK NOWEGO MENU WYBORU <<<
            Write-Host "`nAction for $($selectedUser.SamAccountName):" -ForegroundColor Yellow
            Write-Host "  [1] Open Registry Editor to this path"
            Write-Host "  [2] Set 'Command Timeout' to 0 (DWORD)"
            $action = Read-Host "Choose an option (or press Enter to cancel)"

            switch ($action) {
                '1' {
                    # Akcja: Otwórz Edytor Rejestru
                    Write-Host "Closing any existing Registry Editor windows..." -ForegroundColor Gray
                    Get-Process regedit -ErrorAction SilentlyContinue | Stop-Process -Force
                    Start-Sleep -Milliseconds 250 

                    Write-Host "Opening Registry Editor to 'Connection Properties'..." -ForegroundColor Cyan
                    Write-Host $regPathForRegedit -ForegroundColor White
                    
                    $regeditAppPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
                    if (-not (Test-Path $regeditAppPath)) {
                        New-Item -Path $regeditAppPath -Force | Out-Null
                    }
                    Set-ItemProperty -Path $regeditAppPath -Name "LastKey" -Value $regPathForRegedit -Force
                    Start-Process regedit.exe
                }
                '2' {
                    # Akcja: Ustaw wartość DWORD
                    try {
                        Write-Host "Setting 'Command Timeout' to 0..." -ForegroundColor Cyan
                        # Utwórz klucz, jeśli nie istnieje
                        if (-not (Test-Path $regPathForPS)) {
                            New-Item -Path $regPathForPS -Force | Out-Null
                            Write-Host "Created missing registry key path." -ForegroundColor Gray
                        }
                        # Ustaw wartość DWORD (tworzy ją lub nadpisuje)
                        Set-ItemProperty -Path $regPathForPS -Name "Command Timeout" -Value 0 -Type DWord -Force
                        Write-Host "Successfully set 'Command Timeout' DWORD value to 0 for $($selectedUser.SamAccountName)." -ForegroundColor Green
                    }
                    catch {
                        Write-Error "Failed to set registry value. Error: $($_.Exception.Message)"
                    }
                }
                default {
                    Write-Host "Operation cancelled." -ForegroundColor DarkYellow
                }
            }
            # >>> KONIEC NOWEGO MENU WYBORU <<<
            continue
        } else {
            Write-Host "Invalid index. Please enter a number between 1 and $($lastResults.Count)." -ForegroundColor Red
            continue
        }
    }

    # BLOK: Logika filtrowania
    $filter = $input 
    if ([string]::IsNullOrWhiteSpace($filter)) {
        $filtered = @($users)
    } else {
        $filtered = @($users | Where-Object {
            $_.Name -like "*$filter*" -or
            $_.SamAccountName -like "*$filter*" -or
            $_.SID.Value -like "*$filter*"
        })
    }

    $lastResults = $filtered

    if ($lastResults.Count -eq 0) {
        Write-Host "No results found for '$filter'." -ForegroundColor DarkYellow
    } else {
        Write-Host "`n--- Results for filter: '$filter' ---" -ForegroundColor Green
        
        $i = 0
        $finalResults = foreach ($user in $lastResults) {
            $i++ 
            $sid = $user.SID.Value
            $regQueryPath = "Registry::HKEY_USERS\$sid\Software\InsERT\InsERT GT\dbman\1.0\Connection Properties"
            $valueName = "Command Timeout"
            $regValue = "-" 
            try {
                $regValue = Get-ItemPropertyValue -Path $regQueryPath -Name $valueName -ErrorAction Stop
            }
            catch {}

            [PSCustomObject]@{
                Index             = $i
                Name              = $user.Name
                SamAccountName    = $user.SamAccountName
                'Command Timeout' = $regValue
                SID               = $user.SID
            }
        }

        $finalResults | Format-Table -AutoSize
        
        Write-Host "($($lastResults.Count) matches) - Enter an index to choose an action." -ForegroundColor Cyan
    }
}
