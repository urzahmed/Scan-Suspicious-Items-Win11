# Scan-Suspicious-Items-Win11
Script to find suspicious items in windows

✅ How to Run It
1. Open PowerShell as Administrator.
2. Copy Paste below script and then see the results
3. If you are not familar with given result please search about suspicious activity online
```
# Run this PowerShell script as Administrator

Write-Host "`n[!] Starting suspicious activity scan..." -ForegroundColor Cyan

# 1. Get suspicious running processes (e.g. unsigned, high CPU, scripts)
Write-Host "`n[*] Checking running processes..." -ForegroundColor Yellow
$processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 20

foreach ($proc in $processes) {
    try {
        $path = (Get-Process -Id $proc.Id -ErrorAction Stop).Path
        if ($path) {
            $signed = Get-AuthenticodeSignature $path
            if ($signed.Status -ne 'Valid') {
                Write-Host "⚠️ Unsigned or unknown process: $($proc.ProcessName) ($path)" -ForegroundColor Red
            }
        }
    } catch {
        # Some system processes do not expose a path or cause access errors
    }
}

# 2. Check for script-based processes
Write-Host "`n[*] Checking script-based processes..." -ForegroundColor Yellow
$scriptExtensions = "*.ps1", "*.vbs", "*.js"
foreach ($ext in $scriptExtensions) {
    $scriptProcs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$ext*" }
    foreach ($p in $scriptProcs) {
        Write-Host "⚠️ Script running: $($p.Name) - $($p.CommandLine)" -ForegroundColor Red
    }
}

# 3. List Startup items (Registry + Startup Folder)
Write-Host "`n[*] Checking Startup entries..." -ForegroundColor Yellow

# Registry Run keys
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $regPaths) {
    try {
        Get-ItemProperty -Path $path | ForEach-Object {
            $_.PSObject.Properties | ForEach-Object {
                Write-Host "➡️ Startup item: $($_.Name) = $($_.Value)" -ForegroundColor Magenta
            }
        }
    } catch {}
}

# Startup Folder
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($dir in $startupPaths) {
    if (Test-Path $dir) {
        Get-ChildItem $dir | ForEach-Object {
            Write-Host "➡️ Startup file: $($_.FullName)" -ForegroundColor Magenta
        }
    }
}

# 4. Check scheduled tasks
Write-Host "`n[*] Checking scheduled tasks..." -ForegroundColor Yellow
$schtasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }

foreach ($task in $schtasks) {
    try {
        $details = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
        Write-Host "📌 Task: $($task.TaskName), Last Run: $($details.LastRunTime)" -ForegroundColor Cyan
    } catch {
        Write-Host "⚠️ Could not retrieve info for task: $($task.TaskName)" -ForegroundColor DarkYellow
    }
}

# ✅ Completion message
Write-Host "`n✅ Scan complete. Review highlighted entries above." -ForegroundColor Green
