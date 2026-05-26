$connections = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue

if (-not $connections) {
    Write-Host "PORT 8000: No listener found"
    exit
}

foreach ($conn in $connections) {
    $targetPid = $conn.OwningProcess
    Write-Host "=== Port 8000 Listener ==="
    Write-Host "PID: $targetPid, State: $($conn.State)"

    $proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "Process Name: $($proc.ProcessName)"
        Write-Host "Process Path: $($proc.Path)"
        Write-Host "Start Time: $($proc.StartTime)"

        $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid" -ErrorAction SilentlyContinue
        if ($cim) {
            Write-Host "Parent PID: $($cim.ParentProcessId)"
            Write-Host "CommandLine: $($cim.CommandLine)"
            $parentProc = Get-Process -Id $cim.ParentProcessId -ErrorAction SilentlyContinue
            if ($parentProc) {
                Write-Host "Parent Name: $($parentProc.ProcessName)"
                Write-Host "Parent Path: $($parentProc.Path)"
            }
        }

        Write-Host ""
        Write-Host "=== Attempting to kill process tree ==="
        Stop-Process -Id $targetPid -Force -ErrorAction Stop
        Write-Host "Killed PID $targetPid"
    } else {
        Write-Host "Process not accessible - may need admin rights"
    }
}
