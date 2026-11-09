#requires -Version 5.1
<#
NIMA TOOLKIT v3.0
Windows 10 / 11 | Windows PowerShell 5.1+

Run from an elevated PowerShell session for full functionality.

Safety and operational notes:
- Read-only diagnostics are preferred.
- Low-risk maintenance can be run after confirmation.
- Potentially disruptive actions (network stack reset, offline Defender scan,
  printer spooler restart) always require explicit confirmation.
- Suspicious autoruns, services, tasks, and processes are reported, never
  automatically deleted or disabled.
- Remote support requires an approved RMM/remote-support product and explicit
  customer consent. This script does not create a hidden remote-control channel.
- Temperature sensors and SMART counters depend on OEM firmware/controller support.
#>

[CmdletBinding()]
param(
    [string]$CustomerId,
    [switch]$NoPause
)

$ErrorActionPreference = 'Continue'
$ToolkitVersion = '3.0'
$Root = Join-Path $env:ProgramData 'NimaToolkit'
$LogDir = Join-Path $Root 'Logs'
$ReportDir = Join-Path $Root 'Reports'
$HistoryRoot = Join-Path $Root 'Customers'
foreach ($folder in @($LogDir, $ReportDir, $HistoryRoot)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}
$RunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $LogDir "Nima_$RunId.log"
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Actions = [System.Collections.Generic.List[object]]::new()
$script:CustomerId = $CustomerId

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

function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet('Info','Low','Warning','Critical')][string]$Severity,
        [string]$Title,
        [string]$Details,
        [string]$Recommendation = ''
    )
    $item = [pscustomobject]@{
        Time = Get-Date
        Category = $Category
        Severity = $Severity
        Title = $Title
        Details = $Details
        Recommendation = $Recommendation
    }
    $script:Findings.Add($item) | Out-Null
    $level = if ($Severity -eq 'Critical') { 'ERROR' } elseif ($Severity -eq 'Warning') { 'WARN' } else { 'INFO' }
    Write-Log "$Category | $Severity | $Title | $Details" $level
}

function Add-Action {
    param([string]$Name, [string]$Result, [string]$Details = '')
    $script:Actions.Add([pscustomobject]@{
        Time = Get-Date
        Action = $Name
        Result = $Result
        Details = $Details
    }) | Out-Null
    Write-Log "$Name | $Result | $Details"
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-Action {
    param([string]$Prompt)
    return ((Read-Host "$Prompt (S/N)") -match '^[sS]$')
}

function Pause-Menu {
    if (-not $NoPause) { Read-Host 'Presione Enter para continuar' | Out-Null }
}

function Invoke-LoggedTask {
    param([string]$Name, [scriptblock]$Script)
    Write-Log "Iniciando: $Name"
    try {
        & $Script
        Add-Action -Name $Name -Result 'Completado'
    }
    catch {
        Add-Action -Name $Name -Result 'Error' -Details $_.Exception.Message
        Write-Log "$Name : $($_.Exception.Message)" 'ERROR'
    }
}

function Get-InstalledSoftware {
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = foreach ($path in $registryPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object @{N='Name';E={$_.DisplayName}},
                @{N='Version';E={$_.DisplayVersion}},
                @{N='Publisher';E={$_.Publisher}},
                @{N='InstallDate';E={$_.InstallDate}},
                @{N='UninstallString';E={$_.UninstallString}}
    }
    $items | Sort-Object Name, Version -Unique
}

function Get-SystemSnapshot {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            DriverVersion = $_.DriverVersion
            AdapterRAM_GB = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1GB, 2) } else { $null }
        }
    })
    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Drive = $_.DeviceID
            Label = $_.VolumeName
            TotalGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
            FreeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 1) } else { 0 }
            FreePercent = if ($_.Size) { [math]::Round($_.FreeSpace / $_.Size * 100, 1) } else { 0 }
        }
    })
    [pscustomobject]@{
        Computer = $env:COMPUTERNAME
        User = "$env:USERDOMAIN\$env:USERNAME"
        Manufacturer = $computer.Manufacturer
        Model = $computer.Model
        Serial = $bios.SerialNumber
        Windows = $os.Caption
        Version = $os.Version
        Build = $os.BuildNumber
        LastBoot = $os.LastBootUpTime
        CPU = $cpu.Name
        RAM_GB = if ($computer.TotalPhysicalMemory) { [math]::Round($computer.TotalPhysicalMemory / 1GB, 2) } else { $null }
        RAM_Free_GB = if ($os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { $null }
        GPUs = $gpus
        Volumes = $volumes
    }
}

function Show-Inventory {
    Write-Host "`n=== INVENTARIO DE HARDWARE Y SOFTWARE ===" -ForegroundColor Cyan
    $snapshot = Get-SystemSnapshot
    $snapshot | Select-Object Computer, User, Manufacturer, Model, Serial, Windows, Version, Build, CPU, RAM_GB, RAM_Free_GB, LastBoot | Format-List
    Write-Host 'GPU:'; $snapshot.GPUs | Format-Table -AutoSize
    Write-Host 'Volúmenes:'; $snapshot.Volumes | Format-Table -AutoSize

    $software = @(Get-InstalledSoftware)
    $software | Select-Object -First 60 Name, Version, Publisher, InstallDate | Format-Table -AutoSize
    $softwarePath = Join-Path $ReportDir "Software_$RunId.csv"
    $software | Export-Csv -LiteralPath $softwarePath -NoTypeInformation -Encoding UTF8

    $driversPath = Join-Path $ReportDir "Drivers_$RunId.csv"
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Select-Object DeviceName, Manufacturer, DriverVersion, DriverDate, InfName |
        Export-Csv -LiteralPath $driversPath -NoTypeInformation -Encoding UTF8
    Write-Host "Inventario de software: $softwarePath"
    Write-Host "Inventario de drivers: $driversPath"
    Add-Finding 'Inventario' 'Info' 'Inventario recopilado' "$($software.Count) aplicaciones registradas." 'Revisar exportaciones CSV.'
}

function Test-Temperatures {
    Write-Host "`n=== DIAGNOSTICO DE TEMPERATURAS CPU/GPU ===" -ForegroundColor Cyan
    $zones = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue)
    if ($zones.Count -gt 0) {
        foreach ($zone in $zones) {
            $celsius = [math]::Round(($zone.CurrentTemperature / 10) - 273.15, 1)
            Write-Host "Zona ACPI: $celsius °C (no necesariamente representa CPU o GPU)"
            if ($celsius -ge 85) {
                Add-Finding 'Temperatura' 'Warning' 'Zona ACPI elevada' "$celsius °C" 'Verificar refrigeración y sensores con herramienta del fabricante.'
            }
        }
    } else {
        Write-Host 'No se encontraron sensores ACPI accesibles.'
    }
    Add-Finding 'Temperatura' 'Info' 'Limitación de sensores' 'Windows no ofrece una lectura universal y fiable de temperatura CPU/GPU para todos los fabricantes.' 'Para lecturas exactas, usar utilidades OEM o un proveedor de sensores validado.'
}

function Test-StorageHealth {
    Write-Host "`n=== DIAGNOSTICO SMART SSD/HDD ===" -ForegroundColor Cyan
    $physical = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
    if ($physical.Count -gt 0) {
        $physical | Select-Object FriendlyName, SerialNumber, MediaType, HealthStatus, OperationalStatus,
            @{N='SizeGB';E={[math]::Round($_.Size / 1GB, 1)}} | Format-Table -AutoSize
        foreach ($disk in $physical) {
            if ($disk.HealthStatus -and $disk.HealthStatus -notin @('Healthy','Unknown')) {
                Add-Finding 'Almacenamiento' 'Warning' 'Estado de disco anómalo' "$($disk.FriendlyName): $($disk.HealthStatus)" 'Respaldar datos y ejecutar diagnóstico del fabricante.'
            }
        }
        try {
            $counters = @(Get-PhysicalDisk -ErrorAction Stop | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue)
            if ($counters.Count -gt 0) {
                $counters | Select-Object DeviceId, Temperature, Wear, ReadErrorsTotal, WriteErrorsTotal, PowerOnHours | Format-Table -AutoSize
                foreach ($counter in $counters) {
                    if (($null -ne $counter.Wear) -and ($counter.Wear -ge 90)) {
                        Add-Finding 'Almacenamiento' 'Warning' 'Desgaste informado elevado' "Wear: $($counter.Wear)" 'Validar porcentaje de vida útil con herramienta OEM.'
                    }
                    if (($null -ne $counter.Temperature) -and ($counter.Temperature -ge 70)) {
                        Add-Finding 'Almacenamiento' 'Warning' 'Temperatura de unidad elevada' "$($counter.Temperature) °C" 'Verificar ventilación y disipación del SSD.'
                    }
                }
            } else {
                Write-Host 'El controlador no expone contadores de confiabilidad.'
            }
        } catch {
            Write-Host 'Get-StorageReliabilityCounter no está disponible para este controlador.'
        }
    } else {
        Write-Host 'No se pudo consultar Get-PhysicalDisk.'
    }

    $predict = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue)
    if ($predict.Count -gt 0) {
        $predict | Select-Object InstanceName, PredictFailure, Reason | Format-Table -AutoSize
        foreach ($item in $predict) {
            if ($item.PredictFailure) {
                Add-Finding 'Almacenamiento' 'Critical' 'SMART predice posible fallo' $item.InstanceName 'Respaldar inmediatamente y planificar el reemplazo.'
            }
        }
    } else {
        Write-Host 'SMART clásico no disponible. NVMe/RAID/USB pueden requerir utilidades del fabricante.'
    }
}

function Test-MalwarePersistence {
    Write-Host "`n=== MALWARE Y PERSISTENCIA ===" -ForegroundColor Cyan
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $status = Get-MpComputerStatus
        $status | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
            AntivirusSignatureLastUpdated, AntivirusSignatureVersion | Format-List
        if (-not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled) {
            Add-Finding 'Seguridad' 'Warning' 'Defender no aparece completamente activo' 'Verificar si existe otro antivirus o una política corporativa.' 'Comprobar el producto de seguridad administrado.'
        }
        if (Confirm-Action '¿Actualizar firmas y ejecutar análisis rápido de Defender?') {
            Invoke-LoggedTask 'Actualizar firmas Defender' { Update-MpSignature }
            Invoke-LoggedTask 'Análisis rápido Defender' { Start-MpScan -ScanType QuickScan }
        }
        $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
        if ($threats.Count -gt 0) {
            $threats | Select-Object InitialDetectionTime, ThreatID, ThreatStatusID, ActionSuccess, Resources | Format-List
            Add-Finding 'Seguridad' 'Warning' 'Defender registra detecciones' "$($threats.Count) detección(es) registrada(s)." 'Revisar Historial de protección y estado de cuarentena.'
        }
    } else {
        Add-Finding 'Seguridad' 'Warning' 'Cmdlets de Defender no disponibles' 'Puede haber antivirus de terceros o administración centralizada.' 'Verificar el antivirus instalado.'
    }

    Write-Host "`nProgramas de inicio:"
    $startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User)
    $startup | Format-Table -Wrap -AutoSize

    Write-Host "`nTareas programadas no Microsoft (inventario):"
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Select-Object -First 100 TaskName, TaskPath, State)
    $tasks | Format-Table -AutoSize

    Write-Host "`nServicios automáticos detenidos:"
    Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction SilentlyContinue |
        Select-Object -First 40 Name, DisplayName, State, StartMode | Format-Table -AutoSize

    Write-Host "`nClaves Run/RunOnce:"
    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Write-Host "[$key]"
            Get-ItemProperty -Path $key | Format-List
        }
    }
    Write-Host 'Los elementos se inventarían para revisión: no se eliminan ni deshabilitan automáticamente.'
    Add-Finding 'Seguridad' 'Info' 'Inventario de persistencia completado' 'Se revisaron inicios, tareas y servicios.' 'Validar rutas, firmas digitales y reputación antes de tomar medidas.'
}

function Invoke-DefenderOffline {
    Write-Host 'El análisis sin conexión puede reiniciar el equipo y cerrar la sesión remota.'
    if (Confirm-Action '¿Iniciar Microsoft Defender Offline? Confirme que el cliente guardó su trabajo y hay acceso posterior al equipo.') {
        Invoke-LoggedTask 'Defender Offline' { Start-MpWDOScan }
    }
}

function Invoke-WindowsRepair {
    Write-Host "`n=== REPARACION DE WINDOWS ===" -ForegroundColor Cyan
    Write-Host 'DISM, SFC y CHKDSK /scan pueden tardar bastante.'
    if (-not (Confirm-Action '¿Ejecutar DISM RestoreHealth + SFC + CHKDSK /scan?')) { return }
    Invoke-LoggedTask 'DISM RestoreHealth' { & dism.exe /Online /Cleanup-Image /RestoreHealth }
    Invoke-LoggedTask 'SFC Scannow' { & sfc.exe /scannow }
    Invoke-LoggedTask 'CHKDSK C: /scan' { & chkdsk.exe C: /scan }
    Add-Finding 'Windows' 'Info' 'Reparación ejecutada' 'Se ejecutaron DISM, SFC y CHKDSK online.' 'Revisar resultados, reiniciar si se solicita y volver a diagnosticar.'
}

function Invoke-PerformanceOptimization {
    Write-Host "`n=== OPTIMIZACION DE RENDIMIENTO ===" -ForegroundColor Cyan
    Write-Host 'Procesos con mayor uso de memoria:'
    Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending |
        Select-Object -First 15 ProcessName, Id, @{N='RAM_MB';E={[math]::Round($_.WorkingSet64 / 1MB, 1)}} |
        Format-Table -AutoSize
    Write-Host 'Procesos con mayor CPU acumulada:'
    Get-Process -ErrorAction SilentlyContinue | Sort-Object CPU -Descending |
        Select-Object -First 15 ProcessName, Id, @{N='CPU_s';E={if ($_.CPU) {[math]::Round($_.CPU, 1)} else {0}}} |
        Format-Table -AutoSize
    Write-Host 'Aplicaciones de inicio:'
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User | Format-Table -Wrap -AutoSize

    if (Confirm-Action '¿Limpiar temporales de usuario y Windows (sin tocar Descargas/documentos)?') {
        foreach ($path in @($env:TEMP, (Join-Path $env:WINDIR 'Temp')) | Select-Object -Unique) {
            if (Test-Path $path) {
                Invoke-LoggedTask "Limpieza temporal $path" {
                    Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    if (Confirm-Action '¿Optimizar volúmenes con la operación que Windows elija para SSD/HDD?') {
        Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter | ForEach-Object {
            $letter = $_.DriveLetter
            Invoke-LoggedTask "Optimizar volumen $letter`:" {
                Optimize-Volume -DriveLetter $letter -Verbose
            }
        }
    }
    Write-Host 'No se cierran procesos ni se deshabilitan servicios de forma automática.'
}

function Test-Network {
    Write-Host "`n=== DIAGNOSTICO DE RED ===" -ForegroundColor Cyan
    Invoke-LoggedTask 'IPConfig completo' { ipconfig.exe /all }
    Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Format-List InterfaceAlias, NetProfile, IPv4Address, IPv4DefaultGateway, DNSServer

    foreach ($target in @('1.1.1.1','8.8.8.8')) {
        $pings = @(Test-Connection -ComputerName $target -Count 3 -ErrorAction SilentlyContinue)
        if ($pings.Count -gt 0) {
            $avg = [math]::Round(($pings | Measure-Object ResponseTime -Average).Average, 1)
            Write-Host "$target - promedio ICMP: $avg ms"
        } else {
            Add-Finding 'Red' 'Warning' "Sin respuesta ICMP $target" 'ICMP puede estar bloqueado; no confirma por sí solo una caída de Internet.' 'Probar gateway, DNS y TCP 443.'
        }
    }
    foreach ($domain in @('www.microsoft.com','github.com')) {
        try {
            Resolve-DnsName $domain -ErrorAction Stop |
                Select-Object -First 3 Name, Type, IPAddress | Format-Table -AutoSize
        } catch {
            Add-Finding 'Red' 'Warning' "Fallo DNS: $domain" $_.Exception.Message 'Verificar DNS configurado y conectividad.'
        }
    }
    Test-NetConnection www.microsoft.com -Port 443 -InformationLevel Detailed |
        Select-Object ComputerName, RemoteAddress, TcpTestSucceeded | Format-List
    Write-Host 'Conexiones TCP en escucha (muestra):'
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 40 LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize
}

function Invoke-NetworkRepair {
    Write-Host "`n=== REPARACION DE RED ===" -ForegroundColor Cyan
    Write-Host 'Puede interrumpir VPN, escritorio remoto y conectividad.'
    if (-not (Confirm-Action '¿Vaciar DNS y restablecer Winsock/TCP-IP?')) { return }
    Invoke-LoggedTask 'Vaciar DNS' { ipconfig.exe /flushdns }
    Invoke-LoggedTask 'Winsock reset' { netsh.exe winsock reset }
    Invoke-LoggedTask 'TCP/IP reset' { netsh.exe int ip reset }
    Add-Finding 'Red' 'Warning' 'Pila de red restablecida' 'Puede ser necesario reiniciar y reconectar VPN.' 'Asegurar acceso alternativo antes de reiniciar.'
}

function Test-Printers {
    Write-Host "`n=== DIAGNOSTICO Y REPARACION DE IMPRESORAS ===" -ForegroundColor Cyan
    Get-Printer -ErrorAction SilentlyContinue |
        Select-Object Name, DriverName, PortName, PrinterStatus, Shared |
        Format-Table -AutoSize
    Get-PrinterDriver -ErrorAction SilentlyContinue |
        Select-Object Name, Manufacturer, MajorVersion | Format-Table -AutoSize
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($spooler) { $spooler | Select-Object Name, Status, StartType | Format-List }
    if ($spooler -and $spooler.Status -ne 'Running') {
        Add-Finding 'Impresoras' 'Warning' 'Print Spooler detenido' 'El servicio de cola de impresión no está activo.' 'Iniciar el servicio si el cliente utiliza impresoras.'
    }
    if (Confirm-Action '¿Reiniciar Print Spooler? Los trabajos pendientes podrían verse afectados.') {
        Invoke-LoggedTask 'Reiniciar Print Spooler' { Restart-Service -Name Spooler -Force }
    }
    if (Confirm-Action '¿Abrir configuración de impresoras de Windows?') {
        Start-Process 'ms-settings:printers'
    }
}

function Test-BSOD {
    Write-Host "`n=== DIAGNOSTICO BSOD / PANTALLAZOS AZULES ===" -ForegroundColor Cyan
    $dumpFolders = @("$env:WINDIR\Minidump", "$env:WINDIR")
    foreach ($folder in $dumpFolders) {
        if (Test-Path $folder) {
            Get-ChildItem -LiteralPath $folder -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 20 FullName, Length, LastWriteTime | Format-Table -AutoSize
        }
    }
    $since = (Get-Date).AddDays(-30)
    $bugchecks = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; StartTime=$since} -ErrorAction SilentlyContinue)
    if ($bugchecks.Count -gt 0) {
        $bugchecks | Select-Object -First 30 TimeCreated, Id, Message | Format-List
        Add-Finding 'BSOD' 'Warning' 'Eventos de BugCheck encontrados' "$($bugchecks.Count) evento(s) en los últimos 30 días." 'Analizar minidumps con WinDbg y revisar drivers.'
    } else {
        Write-Host 'No se encontraron eventos WER-SystemErrorReporting en los últimos 30 días.'
    }
    $unexpected = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,6008; StartTime=$since} -ErrorAction SilentlyContinue)
    if ($unexpected.Count -gt 0) {
        $unexpected | Select-Object -First 30 TimeCreated, Id, ProviderName, Message | Format-List
        Add-Finding 'BSOD' 'Info' 'Reinicios o apagados inesperados' "$($unexpected.Count) evento(s) Kernel-Power 41 / EventLog 6008." 'Correlacionar con BugCheck, energía, temperatura y hardware; estos eventos no prueban por sí solos un BSOD.'
    }
    Write-Host 'Para analizar archivos .dmp en profundidad, usar WinDbg (Microsoft Store/Windows SDK).'
}

function Manage-StartupAndServices {
    Write-Host "`n=== GESTION DE INICIO Y SERVICIOS ===" -ForegroundColor Cyan
    Write-Host 'Programas de inicio:'
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User | Format-Table -Wrap -AutoSize
    Write-Host 'Servicios automáticos detenidos:'
    Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, State, StartMode | Format-Table -AutoSize
    Write-Host 'Servicios de terceros en ejecución (muestra):'
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch '\\Windows\\' } |
        Select-Object -First 40 Name, DisplayName, StartMode, PathName | Format-Table -Wrap -AutoSize
    Write-Host 'No se modifican servicios ni elementos de inicio automáticamente.'
    if (Confirm-Action '¿Abrir Administrador de tareas para gestionar aplicaciones de inicio?') {
        Start-Process 'taskmgr.exe'
    }
    if (Confirm-Action '¿Abrir consola de Servicios?') {
        Start-Process 'services.msc'
    }
}

function Request-RemoteConsent {
    Write-Host "`n=== SESION DE SOPORTE REMOTO AUTORIZADA ===" -ForegroundColor Cyan
    Write-Host 'Este módulo no abre una conexión remota ni oculta actividad.'
    Write-Host 'Debe existir una sesión mediante una herramienta RMM/remote support aprobada.'
    $client = Read-Host 'Identificador o nombre del cliente'
    $technician = Read-Host 'Nombre/ID del técnico'
    $consent = Read-Host '¿El cliente autorizó expresamente esta intervención? Escriba AUTORIZO para continuar'
    if ($consent -cne 'AUTORIZO') {
        Add-Action 'Sesión remota' 'No autorizada' "Cliente: $client; Técnico: $technician"
        Write-Log 'No se ejecutó ninguna acción remota: consentimiento no confirmado.' 'WARN'
        return
    }
    $entry = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Computer = $env:COMPUTERNAME
        Client = $client
        Technician = $technician
        Consent = 'AUTORIZO'
        Note = 'Consentimiento registrado localmente. Transporte remoto provisto por RMM externo.'
    }
    $consentPath = Join-Path $LogDir "RemoteConsent_$RunId.json"
    $entry | ConvertTo-Json | Set-Content -LiteralPath $consentPath -Encoding UTF8
    Add-Action 'Consentimiento de soporte remoto' 'Registrado' "Cliente: $client; Técnico: $technician; archivo: $consentPath"
    Write-Host "Consentimiento registrado: $consentPath" -ForegroundColor Green
    Write-Host 'Conecte y audite la sesión mediante su herramienta RMM. No comparta contraseñas ni tokens en este registro.'
}

function Save-CustomerHistory {
    $id = $script:CustomerId
    if ([string]::IsNullOrWhiteSpace($id)) { $id = Read-Host 'Identificador del cliente (ej. CLIENTE-001)' }
    $safeId = ($id -replace '[^a-zA-Z0-9._-]', '_')
    if ([string]::IsNullOrWhiteSpace($safeId)) { $safeId = 'SIN_ID' }
    $customerFolder = Join-Path $HistoryRoot $safeId
    New-Item -ItemType Directory -Path $customerFolder -Force | Out-Null
    $history = [pscustomobject]@{
        ToolkitVersion = $ToolkitVersion
        RunId = $RunId
        Timestamp = (Get-Date).ToString('o')
        CustomerId = $safeId
        Computer = $env:COMPUTERNAME
        User = "$env:USERDOMAIN\$env:USERNAME"
        Findings = @($script:Findings)
        Actions = @($script:Actions)
        LogFile = $LogFile
    }
    $historyPath = Join-Path $customerFolder "History_$RunId.json"
    $history | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $historyPath -Encoding UTF8
    Add-Action 'Historial de cliente' 'Guardado' $historyPath
    Write-Host "Historial: $historyPath" -ForegroundColor Green
}

function New-ClientReport {
    $snapshot = Get-SystemSnapshot
    $customer = if ($script:CustomerId) { $script:CustomerId } else { 'No especificado' }
    $software = @(Get-InstalledSoftware)
    $diskRows = foreach ($v in $snapshot.Volumes) {
        "<tr><td>$([System.Net.WebUtility]::HtmlEncode($v.Drive))</td><td>$([System.Net.WebUtility]::HtmlEncode($v.Label))</td><td>$($v.TotalGB)</td><td>$($v.FreeGB)</td><td>$($v.FreePercent)%</td></tr>"
    }
    $findingRows = foreach ($f in $script:Findings) {
        "<tr><td>$($f.Time)</td><td>$([System.Net.WebUtility]::HtmlEncode($f.Category))</td><td>$([System.Net.WebUtility]::HtmlEncode($f.Severity))</td><td>$([System.Net.WebUtility]::HtmlEncode($f.Title))</td><td>$([System.Net.WebUtility]::HtmlEncode($f.Details))</td><td>$([System.Net.WebUtility]::HtmlEncode($f.Recommendation))</td></tr>"
    }
    $actionRows = foreach ($a in $script:Actions) {
        "<tr><td>$($a.Time)</td><td>$([System.Net.WebUtility]::HtmlEncode($a.Action))</td><td>$([System.Net.WebUtility]::HtmlEncode($a.Result))</td><td>$([System.Net.WebUtility]::HtmlEncode($a.Details))</td></tr>"
    }
    $softwarePath = Join-Path $ReportDir "Software_$RunId.csv"
    $software | Export-Csv -LiteralPath $softwarePath -NoTypeInformation -Encoding UTF8
    $htmlPath = Join-Path $ReportDir "Nima_Report_$RunId.html"
    $html = @"
<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Nima Toolkit - Informe $($snapshot.Computer)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:30px;color:#202938}h1,h2{color:#164b7a}
.meta{background:#f2f5f8;padding:16px;border-radius:8px;line-height:1.7}
table{border-collapse:collapse;width:100%;margin:12px 0 26px}th,td{border:1px solid #ccd5df;padding:7px;text-align:left;font-size:12px;vertical-align:top}
th{background:#e8eff6}.note{font-size:11px;color:#5d6875}.pill{padding:3px 7px;border-radius:5px;background:#edf2f7}
@media print{body{margin:12mm}h2{page-break-after:avoid}tr{page-break-inside:avoid}}
</style></head><body>
<h1>Nima Toolkit v3.0 - Informe de soporte</h1>
<div class="meta">
<b>Cliente:</b> $([System.Net.WebUtility]::HtmlEncode($customer))<br>
<b>Equipo:</b> $([System.Net.WebUtility]::HtmlEncode($snapshot.Computer))<br>
<b>Usuario:</b> $([System.Net.WebUtility]::HtmlEncode($snapshot.User))<br>
<b>Fabricante / modelo:</b> $([System.Net.WebUtility]::HtmlEncode("$($snapshot.Manufacturer) $($snapshot.Model)"))<br>
<b>Número de serie BIOS:</b> $([System.Net.WebUtility]::HtmlEncode($snapshot.Serial))<br>
<b>Windows:</b> $([System.Net.WebUtility]::HtmlEncode("$($snapshot.Windows) $($snapshot.Version) (Build $($snapshot.Build))"))<br>
<b>CPU:</b> $([System.Net.WebUtility]::HtmlEncode($snapshot.CPU))<br>
<b>RAM:</b> $($snapshot.RAM_GB) GB (libre aprox. $($snapshot.RAM_Free_GB) GB)<br>
<b>Fecha:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
<b>Run ID:</b> $RunId
</div>
<h2>GPU</h2><p>$([System.Net.WebUtility]::HtmlEncode((($snapshot.GPUs | ForEach-Object {$_.Name}) -join '; ')))</p>
<h2>Almacenamiento</h2>
<table><tr><th>Unidad</th><th>Volumen</th><th>Total GB</th><th>Libre GB</th><th>Libre %</th></tr>$($diskRows -join "`n")</table>
<h2>Hallazgos</h2>
<table><tr><th>Fecha</th><th>Categoría</th><th>Severidad</th><th>Hallazgo</th><th>Detalle</th><th>Recomendación</th></tr>$($findingRows -join "`n")</table>
<h2>Acciones realizadas</h2>
<table><tr><th>Fecha</th><th>Acción</th><th>Resultado</th><th>Detalle</th></tr>$($actionRows -join "`n")</table>
<h2>Inventario de software</h2><p>$($software.Count) aplicaciones registradas. Exportación CSV: $([System.Net.WebUtility]::HtmlEncode($softwarePath))</p>
<p class="note">Este informe es una instantánea de diagnóstico. No certifica ausencia total de malware ni garantiza la salud física de componentes. Lecturas térmicas/SMART dependen del firmware y controlador.</p>
<p class="note">Log de ejecución: $([System.Net.WebUtility]::HtmlEncode($LogFile))</p>
</body></html>
"@
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
    Add-Action 'Informe HTML' 'Generado' $htmlPath
    Write-Host "Informe HTML: $htmlPath" -ForegroundColor Green

    if (Confirm-Action '¿Intentar generar también PDF usando Microsoft Edge instalado?') {
        $edgeCandidates = @(
            "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        )
        $edge = $edgeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($edge) {
            $pdfPath = Join-Path $ReportDir "Nima_Report_$RunId.pdf"
            try {
                Start-Process -FilePath $edge -ArgumentList @('--headless','--disable-gpu',"--print-to-pdf=$pdfPath",$htmlPath) -Wait
                if (Test-Path $pdfPath) {
                    Add-Action 'Informe PDF' 'Generado' $pdfPath
                    Write-Host "Informe PDF: $pdfPath" -ForegroundColor Green
                } else {
                    Add-Action 'Informe PDF' 'No generado' 'Edge no produjo el archivo; imprimir el HTML como PDF desde el navegador.'
                }
            } catch {
                Add-Action 'Informe PDF' 'Error' $_.Exception.Message
            }
        } else {
            Write-Host 'Microsoft Edge no encontrado. Abrí el HTML y usá Imprimir > Guardar como PDF.'
            Add-Action 'Informe PDF' 'Pendiente' 'Edge no encontrado.'
        }
    }
    if (Confirm-Action '¿Abrir el informe HTML?') { Start-Process $htmlPath }
}

function Invoke-FullRoutine {
    Write-Host "`nRutina completa: inventario, hardware, seguridad, rendimiento, red, BSOD y reporte."
    Write-Host 'Las reparaciones que puedan interrumpir servicios o conectividad requieren confirmación.'
    if (-not (Confirm-Action '¿Iniciar rutina completa?')) { return }
    Show-SystemInventory
    Test-Temperatures
    Test-StorageHealth
    Test-MalwarePersistence
    Invoke-PerformanceOptimization
    Test-Network
    Test-Printers
    Test-BSOD
    Manage-StartupAndServices
    if (Confirm-Action '¿Ejecutar ahora DISM + SFC + CHKDSK?') { Invoke-WindowsRepair }
    Save-CustomerHistory
    New-ClientReport
}

function Show-Menu {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host '                    NIMA TOOLKIT v3.0' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host " Equipo: $env:COMPUTERNAME | Usuario: $env:USERNAME"
    Write-Host " Cliente: $(if ($script:CustomerId) {$script:CustomerId} else {'No asignado'})"
    Write-Host " Log: $LogFile" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host 'DIAGNOSTICO'
    Write-Host ' [1] Inventario completo de hardware y software'
    Write-Host ' [2] Temperaturas CPU/GPU (si el hardware las expone)'
    Write-Host ' [3] SMART avanzado SSD/HDD'
    Write-Host ' [4] Malware y persistencia (Defender + auditoría)'
    Write-Host ' [5] Diagnóstico de rendimiento'
    Write-Host ' [6] Diagnóstico completo de red'
    Write-Host ' [7] Diagnóstico de impresoras'
    Write-Host ' [8] Diagnóstico BSOD / minidumps / eventos'
    Write-Host ' [9] Gestión de inicio y servicios (auditoría)'
    Write-Host ''
    Write-Host 'REPARACION'
    Write-Host ' [10] Reparación de Windows (DISM + SFC + CHKDSK)'
    Write-Host ' [11] Optimización y limpieza segura'
    Write-Host ' [12] Reparación de red (disruptiva)'
    Write-Host ' [13] Reiniciar Print Spooler / abrir impresoras'
    Write-Host ' [14] Análisis Defender Offline (puede reiniciar)'
    Write-Host ''
    Write-Host 'SOPORTE Y REPORTES'
    Write-Host ' [15] Registrar consentimiento para sesión remota autorizada'
    Write-Host ' [16] Guardar historial por cliente'
    Write-Host ' [17] Generar informe HTML / PDF'
    Write-Host ' [18] Rutina completa guiada'
    Write-Host ' [0] Salir'
    Write-Host '============================================================' -ForegroundColor DarkCyan
}

if (-not (Test-Admin)) {
    Write-Host 'Nima Toolkit necesita permisos de Administrador. Abra PowerShell como administrador.' -ForegroundColor Yellow
    exit 1
}

Write-Log "Inicio Nima Toolkit v$ToolkitVersion | PowerShell $($PSVersionTable.PSVersion) | $env:COMPUTERNAME"
if ([string]::IsNullOrWhiteSpace($script:CustomerId)) {
    $providedId = Read-Host 'ID del cliente (opcional; Enter para omitir)'
    if (-not [string]::IsNullOrWhiteSpace($providedId)) { $script:CustomerId = $providedId }
}

do {
    Show-Menu
    $selection = Read-Host 'Seleccione una opción'
    switch ($selection) {
        '1'  { Show-SystemInventory; Pause-Menu }
        '2'  { Test-Temperatures; Pause-Menu }
        '3'  { Test-StorageHealth; Pause-Menu }
        '4'  { Test-MalwarePersistence; Pause-Menu }
        '5'  { Invoke-PerformanceOptimization; Pause-Menu }
        '6'  { Test-Network; Pause-Menu }
        '7'  { Test-Printers; Pause-Menu }
        '8'  { Test-BSOD; Pause-Menu }
        '9'  { Manage-StartupAndServices; Pause-Menu }
        '10' { Invoke-WindowsRepair; Pause-Menu }
        '11' { Invoke-PerformanceOptimization; Pause-Menu }
        '12' { Invoke-NetworkRepair; Pause-Menu }
        '13' { Test-Printers; Pause-Menu }
        '14' { Invoke-DefenderOffline; Pause-Menu }
        '15' { Request-RemoteConsent; Pause-Menu }
        '16' { Save-CustomerHistory; Pause-Menu }
        '17' { New-ClientReport; Pause-Menu }
        '18' { Invoke-FullRoutine; Pause-Menu }
        '0'  { Write-Log 'Nima Toolkit cerrado.'; break }
        default { Write-Host 'Opción no válida.' -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
    }
} while ($true)
