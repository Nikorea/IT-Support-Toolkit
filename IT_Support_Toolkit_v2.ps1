#requires -Version 5.1
<#
IT SUPPORT TOOLKIT v2.0
Windows 10 / 11 - PowerShell 5.1+
Run as Administrator.

Safety:
- Does not disable Defender, Firewall, Windows Update, or essential services.
- Destructive or disruptive actions require confirmation.
- Defender is used for malware scanning/remediation; detections and quarantine are reported.
- Network reset can interrupt VPN/remote sessions and may require a reboot.
#>

[CmdletBinding()]
param(
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$Root = Join-Path $env:ProgramData 'ITSupportToolkit'
$LogDir = Join-Path $Root 'Logs'
$ReportDir = Join-Path $Root 'Reports'
New-Item -ItemType Directory -Path $LogDir, $ReportDir -Force | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $LogDir "ITSupport_$Stamp.log"
$ReportFile = Join-Path $ReportDir "ITSupport_Report_$Stamp.html"

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    $color = switch ($Level) {
        'ERROR' { 'Red' }
        'WARN'  { 'Yellow' }
        'OK'    { 'Green' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Action {
    param([string]$Prompt)
    return ((Read-Host "$Prompt (S/N)") -match '^[sS]$')
}

function Pause-Menu {
    if (-not $NoPause) { Read-Host 'Presione Enter para continuar' | Out-Null }
}

function Invoke-Task {
    param([string]$Name, [scriptblock]$Script)
    Write-Log "Iniciando: $Name"
    try {
        & $Script
        Write-Log "Terminado: $Name" 'OK'
    } catch {
        Write-Log ("Fallo en {0}: {1}" -f $Name, $_.Exception.Message) 'ERROR'
    }
}

function Get-ComputerSnapshot {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Unidad = $_.DeviceID
            Volumen = $_.VolumeName
            TotalGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
            LibreGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 1) } else { 0 }
            LibrePct = if ($_.Size) { [math]::Round($_.FreeSpace / $_.Size * 100, 1) } else { 0 }
        }
    })
    [pscustomobject]@{
        Computer = $env:COMPUTERNAME
        User = "$env:USERDOMAIN\$env:USERNAME"
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        Serial = $bios.SerialNumber
        Windows = $os.Caption
        Version = $os.Version
        Build = $os.BuildNumber
        LastBoot = $os.LastBootUpTime
        CPU = $cpu.Name
        RAM_GB = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { $null }
        RAM_Free_GB = if ($os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { $null }
        Disks = $disks
    }
}

function Show-SystemInfo {
    Write-Host "`n=== DATOS DEL EQUIPO ===" -ForegroundColor Cyan
    $s = Get-ComputerSnapshot
    $s | Select-Object Computer, User, Manufacturer, Model, Serial, Windows, Version, Build, CPU, RAM_GB, RAM_Free_GB, LastBoot | Format-List
    $s.Disks | Format-Table -AutoSize
    Write-Log 'Inventario básico del equipo recopilado.' 'OK'
}

function Invoke-HealthCheck {
    Write-Host "`n=== DIAGNOSTICO GENERAL ===" -ForegroundColor Cyan

    Invoke-Task 'Estado de unidades físicas' {
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            Get-PhysicalDisk -ErrorAction SilentlyContinue |
                Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus,
                    @{N='SizeGB';E={[math]::Round($_.Size / 1GB, 1)}} |
                Format-Table -AutoSize
        } else {
            Write-Host 'Get-PhysicalDisk no está disponible en este equipo.'
        }
    }

    Invoke-Task 'Estado de espacio en discos' {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
            Select-Object DeviceID, VolumeName,
                @{N='TotalGB';E={[math]::Round($_.Size / 1GB, 1)}},
                @{N='LibreGB';E={[math]::Round($_.FreeSpace / 1GB, 1)}},
                @{N='LibrePct';E={if ($_.Size) {[math]::Round($_.FreeSpace / $_.Size * 100, 1)}}} |
            Format-Table -AutoSize
    }

    Invoke-Task 'Red, DNS y conectividad HTTPS' {
        Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
        Write-Host 'Resolución DNS:'
        Resolve-DnsName www.microsoft.com -ErrorAction SilentlyContinue |
            Select-Object -First 4 Name, Type, IPAddress | Format-Table -AutoSize
        Write-Host 'Conectividad TCP 443:'
        Test-NetConnection www.microsoft.com -Port 443 -InformationLevel Detailed |
            Select-Object ComputerName, RemoteAddress, TcpTestSucceeded | Format-List
    }

    Invoke-Task 'Errores críticos de Windows últimos 7 días' {
        $since = (Get-Date).AddDays(-7)
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 1,2
            StartTime = $since
        } -MaxEvents 35 -ErrorAction SilentlyContinue)
        if ($events.Count -eq 0) { Write-Host 'No se encontraron eventos críticos/error recientes en el registro System.' }
        else {
            $events | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
                @{N='Message';E={($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(240,($_.Message -replace '\s+',' ').Length))}} |
                Format-Table -Wrap -AutoSize
        }
    }

    Invoke-Task 'Servicios automáticos detenidos' {
        Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction SilentlyContinue |
            Select-Object -First 30 Name, DisplayName, State, StartMode | Format-Table -AutoSize
    }
    Write-Log 'Diagnóstico general terminado.' 'OK'
}

function Show-Performance {
    Write-Host "`n=== RENDIMIENTO ===" -ForegroundColor Cyan
    Invoke-Task 'Procesos con mayor consumo de CPU acumulado' {
        Get-Process -ErrorAction SilentlyContinue |
            Sort-Object CPU -Descending |
            Select-Object -First 15 ProcessName, Id,
                @{N='CPU_s';E={if ($_.CPU) {[math]::Round($_.CPU,1)} else {0}}},
                @{N='RAM_MB';E={[math]::Round($_.WorkingSet64 / 1MB,1)}} |
            Format-Table -AutoSize
    }
    Invoke-Task 'Procesos con mayor uso de memoria' {
        Get-Process -ErrorAction SilentlyContinue |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First 15 ProcessName, Id,
                @{N='RAM_MB';E={[math]::Round($_.WorkingSet64 / 1MB,1)}} |
            Format-Table -AutoSize
    }
    Invoke-Task 'Programas configurados para iniciar con Windows' {
        $startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
            Select-Object Name, Command, Location, User)
        $csv = Join-Path $ReportDir "Startup_$Stamp.csv"
        $startup | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
        $startup | Format-Table -Wrap -AutoSize
        Write-Host "Inventario CSV: $csv"
    }
    Write-Host 'Nota: los tiempos de CPU son acumulados desde que inició cada proceso, no una medición instantánea.'
}

function Invoke-Defender {
    Write-Host "`n=== MICROSOFT DEFENDER / ANTIMALWARE ===" -ForegroundColor Cyan
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Write-Log 'No se encontró la interfaz PowerShell de Defender. Puede haber otro antivirus o una política corporativa.' 'WARN'
        return
    }

    Invoke-Task 'Estado de Defender' {
        Get-MpComputerStatus |
            Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
                BehaviorMonitorEnabled, IoavProtectionEnabled, AntivirusSignatureLastUpdated,
                AntivirusSignatureVersion, QuickScanAge, FullScanAge |
            Format-List
    }

    Write-Host '[1] Actualizar firmas'
    Write-Host '[2] Actualizar firmas + análisis rápido'
    Write-Host '[3] Actualizar firmas + análisis completo (puede tardar horas)'
    Write-Host '[4] Análisis sin conexión de Microsoft Defender (puede reiniciar el equipo)'
    Write-Host '[0] Volver'
    $choice = Read-Host 'Seleccione'
    switch ($choice) {
        '1' {
            Invoke-Task 'Actualizar firmas' { Update-MpSignature }
        }
        '2' {
            Invoke-Task 'Actualizar firmas' { Update-MpSignature }
            Invoke-Task 'Análisis rápido' { Start-MpScan -ScanType QuickScan }
        }
        '3' {
            if (Confirm-Action '¿Confirmar análisis completo?') {
                Invoke-Task 'Actualizar firmas' { Update-MpSignature }
                Invoke-Task 'Análisis completo' { Start-MpScan -ScanType FullScan }
            }
        }
        '4' {
            Write-Log 'El análisis sin conexión puede reiniciar Windows. Guarde el trabajo y confirme que hay acceso físico o gestión fuera de banda.' 'WARN'
            if (Confirm-Action '¿Iniciar Microsoft Defender Offline?') {
                Invoke-Task 'Defender Offline' { Start-MpWDOScan }
            }
        }
        default { return }
    }

    Invoke-Task 'Detecciones recientes de Defender' {
        Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Select-Object InitialDetectionTime, ThreatID, ThreatStatusID, ActionSuccess, Resources |
            Format-List
    }
    Write-Host 'Defender aplica las acciones de cuarentena/remediación según su configuración y políticas.'
}

function Invoke-WindowsRepair {
    Write-Host "`n=== REPARACION DE WINDOWS ===" -ForegroundColor Cyan
    Write-Host 'Orden recomendado: DISM RestoreHealth, SFC y CHKDSK /scan.'
    if (-not (Confirm-Action '¿Ejecutar las comprobaciones y reparaciones?')) { return }

    Invoke-Task 'DISM RestoreHealth' { & dism.exe /Online /Cleanup-Image /RestoreHealth }
    Invoke-Task 'SFC Scannow' { & sfc.exe /scannow }
    Invoke-Task 'CHKDSK online scan C:' { & chkdsk.exe C: /scan }
    Write-Log 'Si DISM/SFC informan que no pudieron reparar archivos, revisar los logs antes de repetir o escalar.' 'WARN'
}

function Invoke-SafeCleanup {
    Write-Host "`n=== LIMPIEZA SEGURA ===" -ForegroundColor Cyan
    Write-Host 'Elimina temporales de usuario y Windows que no estén bloqueados.'
    Write-Host 'No toca Descargas, Escritorio, documentos, perfiles, cachés del navegador ni puntos de restauración.'
    if (-not (Confirm-Action '¿Continuar con la limpieza?')) { return }

    $targets = @($env:TEMP, (Join-Path $env:WINDIR 'Temp')) | Select-Object -Unique
    foreach ($target in $targets) {
        if (Test-Path -LiteralPath $target) {
            Invoke-Task "Limpiar $target" {
                Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Log 'Limpieza terminada. Algunos archivos en uso pueden permanecer.' 'OK'
}

function Invoke-VolumeOptimize {
    Write-Host "`n=== OPTIMIZACION DE UNIDADES ===" -ForegroundColor Cyan
    Write-Host 'Windows elige TRIM para SSD o desfragmentación para HDD según corresponda.'
    if (-not (Confirm-Action '¿Analizar volúmenes fijos?')) { return }

    Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter | ForEach-Object {
        $letter = $_.DriveLetter
        Invoke-Task "Analizar volumen $letter`:" {
            Optimize-Volume -DriveLetter $letter -Analyze -Verbose
        }
        if (Confirm-Action "¿Ejecutar optimización en $letter`: ahora?") {
            Invoke-Task "Optimizar volumen $letter`:" {
                Optimize-Volume -DriveLetter $letter -Verbose
            }
        }
    }
}

function Invoke-NetworkRepair {
    Write-Host "`n=== REPARACION DE RED ===" -ForegroundColor Cyan
    Write-Host 'Puede interrumpir VPN, escritorio remoto y conectividad. Winsock/TCP-IP puede requerir reinicio.'
    if (-not (Confirm-Action '¿Vaciar DNS y restablecer Winsock/TCP-IP?')) { return }

    Invoke-Task 'Vaciar caché DNS' { & ipconfig.exe /flushdns }
    Invoke-Task 'Restablecer Winsock' { & netsh.exe winsock reset }
    Invoke-Task 'Restablecer pila TCP/IP' { & netsh.exe int ip reset }
    Write-Log 'Reparación de red completada. Puede ser necesario reiniciar Windows y reconectar VPN.' 'WARN'
}

function Invoke-DiskAndMemoryChecks {
    Write-Host "`n=== HARDWARE: DISCO Y MEMORIA ===" -ForegroundColor Cyan
    Invoke-Task 'Estado reportado de discos físicos' {
        if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
            Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus,
                @{N='SizeGB';E={[math]::Round($_.Size / 1GB,1)}} | Format-Table -AutoSize
        }
        Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue |
            Select-Object InstanceName, PredictFailure, Reason | Format-Table -AutoSize
    }
    Write-Host 'La lectura SMART depende del controlador/firmware y no reemplaza el diagnóstico del fabricante.'
    Write-Host 'Para memoria RAM se puede programar Diagnóstico de memoria de Windows (requiere reinicio).'
    if (Confirm-Action '¿Abrir la herramienta de diagnóstico de memoria?') {
        Start-Process -FilePath 'mdsched.exe'
    }
}

function New-ClientReport {
    $snapshot = Get-ComputerSnapshot
    $diskRows = foreach ($d in $snapshot.Disks) {
        "<tr><td>$($d.Unidad)</td><td>$($d.Volumen)</td><td>$($d.TotalGB)</td><td>$($d.LibreGB)</td><td>$($d.LibrePct)%</td></tr>"
    }
    $defenderText = 'No disponible'
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $defenderText = "AntivirusEnabled=$($mp.AntivirusEnabled); RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled); Signatures=$($mp.AntivirusSignatureLastUpdated)"
    }
    $critical = @(Get-WinEvent -FilterHashtable @{
        LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-7)
    } -MaxEvents 25 -ErrorAction SilentlyContinue)
    $eventRows = foreach ($e in $critical) {
        $msg = [System.Net.WebUtility]::HtmlEncode((($e.Message -replace '\s+',' ').Substring(0,[Math]::Min(300,($e.Message -replace '\s+',' ').Length))))
        "<tr><td>$($e.TimeCreated)</td><td>$($e.Id)</td><td>$([System.Net.WebUtility]::HtmlEncode($e.ProviderName))</td><td>$msg</td></tr>"
    }
    $html = @"
<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Informe IT - $($snapshot.Computer)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#202938}h1,h2{color:#174a7e}
table{border-collapse:collapse;width:100%;margin:12px 0 24px}th,td{border:1px solid #ccd5df;padding:8px;text-align:left;font-size:13px}
th{background:#eaf1f8}.meta{background:#f4f7fa;padding:14px;border-radius:8px}
.small{color:#5b6572;font-size:12px}
</style></head><body>
<h1>Informe de soporte técnico</h1>
<div class="meta">
<b>Equipo:</b> $($snapshot.Computer)<br>
<b>Usuario:</b> $($snapshot.User)<br>
<b>Fabricante / modelo:</b> $($snapshot.Manufacturer) $($snapshot.Model)<br>
<b>Windows:</b> $($snapshot.Windows) - $($snapshot.Version) (Build $($snapshot.Build))<br>
<b>Procesador:</b> $($snapshot.CPU)<br>
<b>RAM:</b> $($snapshot.RAM_GB) GB (libre aproximada: $($snapshot.RAM_Free_GB) GB)<br>
<b>Fecha:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
</div>
<h2>Almacenamiento</h2>
<table><tr><th>Unidad</th><th>Volumen</th><th>Total GB</th><th>Libre GB</th><th>Libre %</th></tr>$($diskRows -join "`n")</table>
<h2>Microsoft Defender</h2><p>$([System.Net.WebUtility]::HtmlEncode($defenderText))</p>
<h2>Eventos críticos y errores (últimos 7 días)</h2>
<table><tr><th>Fecha</th><th>ID</th><th>Origen</th><th>Mensaje</th></tr>$($eventRows -join "`n")</table>
<p class="small">Log de ejecución: $([System.Net.WebUtility]::HtmlEncode($LogFile))</p>
<p class="small">Este informe es una instantánea de diagnóstico; no certifica ausencia total de malware o fallas de hardware.</p>
</body></html>
"@
    Set-Content -LiteralPath $ReportFile -Value $html -Encoding UTF8
    Write-Log "Informe HTML generado: $ReportFile" 'OK'
    Write-Host "Informe guardado: $ReportFile" -ForegroundColor Green
    if (Confirm-Action '¿Abrir el informe en el navegador?') {
        Start-Process $ReportFile
    }
}

function Invoke-GuidedRoutine {
    Write-Host "`nRutina guiada: diagnóstico -> Defender -> reparación -> limpieza -> optimización -> informe."
    Write-Host 'Puede tardar bastante. Defender y las reparaciones requieren decisiones explícitas.'
    if (-not (Confirm-Action '¿Iniciar rutina guiada?')) { return }
    Show-SystemInfo
    Invoke-HealthCheck
    Show-Performance
    Invoke-Defender
    Invoke-WindowsRepair
    Invoke-SafeCleanup
    Invoke-VolumeOptimize
    Invoke-DiskAndMemoryChecks
    New-ClientReport
}

function Show-Menu {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host '               IT SUPPORT TOOLKIT v2.0' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host " Equipo: $env:COMPUTERNAME | Usuario: $env:USERNAME"
    Write-Host " Log: $LogFile" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'DIAGNOSTICO'
    Write-Host ' [1] Información del equipo y almacenamiento'
    Write-Host ' [2] Diagnóstico general: discos, red, eventos y servicios'
    Write-Host ' [3] Rendimiento: procesos y programas de inicio'
    Write-Host ' [4] Hardware: estado de discos y diagnóstico de RAM'
    Write-Host ''
    Write-Host 'SEGURIDAD'
    Write-Host ' [5] Microsoft Defender: actualizar, análisis rápido/completo/offline'
    Write-Host ''
    Write-Host 'REPARACION Y MANTENIMIENTO'
    Write-Host ' [6] Reparar Windows: DISM + SFC + CHKDSK'
    Write-Host ' [7] Limpieza segura de temporales'
    Write-Host ' [8] Optimizar SSD/HDD con herramienta nativa de Windows'
    Write-Host ' [9] Reparación de red: DNS / Winsock / TCP-IP'
    Write-Host ''
    Write-Host 'REPORTES'
    Write-Host ' [10] Rutina completa guiada'
    Write-Host ' [11] Generar informe HTML para el cliente'
    Write-Host ' [0] Salir'
    Write-Host '============================================================' -ForegroundColor DarkCyan
}

if (-not (Test-Admin)) {
    Write-Host 'Ejecute PowerShell como Administrador y vuelva a iniciar el toolkit.' -ForegroundColor Yellow
    exit 1
}

Write-Log "Inicio IT Support Toolkit v2.0 | Windows PowerShell $($PSVersionTable.PSVersion) | $env:COMPUTERNAME"
do {
    Show-Menu
    $option = Read-Host 'Seleccione una opción'
    switch ($option) {
        '1'  { Show-SystemInfo; Pause-Menu }
        '2'  { Invoke-HealthCheck; Pause-Menu }
        '3'  { Show-Performance; Pause-Menu }
        '4'  { Invoke-DiskAndMemoryChecks; Pause-Menu }
        '5'  { Invoke-Defender; Pause-Menu }
        '6'  { Invoke-WindowsRepair; Pause-Menu }
        '7'  { Invoke-SafeCleanup; Pause-Menu }
        '8'  { Invoke-VolumeOptimize; Pause-Menu }
        '9'  { Invoke-NetworkRepair; Pause-Menu }
        '10' { Invoke-GuidedRoutine; Pause-Menu }
        '11' { New-ClientReport; Pause-Menu }
        '0'  { Write-Log 'Toolkit cerrado.'; break }
        default { Write-Host 'Opción no válida.' -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
    }
} while ($true)
