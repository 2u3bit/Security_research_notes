<#
.SYNOPSIS
    Prepares a Windows 10/11 VM and installs FLARE-VM in one run.

.DESCRIPTION
    Follows the FLARE-VM pre-installation steps:
      1. Sanity checks (admin, Windows PowerShell 5.x, Windows 10+, real VM, disk, RAM, username)
      2. Waits for you to switch off Tamper Protection (cannot be done by script, by design)
      3. Disables Microsoft Defender via Group Policy registry keys
      4. Disables Windows Update via Group Policy + service
      5. Reboots if Defender is still active and resumes automatically after logon
      6. Pauses so you can take a VM snapshot
      7. Downloads and runs the official mandiant/flare-vm install.ps1

    ONLY RUN THIS INSIDE A DISPOSABLE ANALYSIS VM. It turns off AV and updates.

.PARAMETER NoGui
    Pass -noGui to the FLARE-VM installer (skip the package selection GUI).

.PARAMETER CustomConfig
    Path or URL to a ready-made FLARE-VM config.xml (passed as -customConfig).
    Overrides -PackageList.

.PARAMETER PackageList
    Text file with package ids to add (and "-id" lines to remove) on top of the
    official default config.xml. Defaults to flare-packages.txt next to this script.

.PARAMETER DefaultPackages
    Ignore the package list and install the plain FLARE-VM default set.

.PARAMETER Force
    Skip the "am I in a VM?" check. Use only if detection fails on your hypervisor.

.EXAMPLE
    # In an elevated Windows PowerShell (not pwsh 7) inside the VM:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\Install-FlareVM.ps1
#>
[CmdletBinding()]
param(
    [switch]$NoGui,
    [string]$CustomConfig,
    [string]$PackageList = (Join-Path $PSScriptRoot 'flare-packages.txt'),
    [switch]$DefaultPackages,
    [switch]$Force,
    [switch]$Resume   # internal: set when relaunched after reboot
)

$ErrorActionPreference = 'Stop'
$FlareInstallerUrl = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1'
$FlareConfigUrl    = 'https://raw.githubusercontent.com/mandiant/flare-vm/main/config.xml'
$WorkDir           = Join-Path $env:USERPROFILE 'Desktop\flare-vm-setup'
$RunOnceKey        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
$RunOnceName       = 'FlareVMSetupResume'

function Write-Step($msg) { Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Fail($msg)       { Write-Host "`n[x] $msg" -ForegroundColor Red; Read-Host 'Press Enter to exit'; exit 1 }

function Set-RegValue($Path, $Name, $Value, $Type = 'DWord') {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# ---------------------------------------------------------------- 1. checks
function Test-Prerequisites {
    Write-Step 'Checking prerequisites'

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'Run this script from an elevated (Run as administrator) PowerShell.'
    }
    Write-Ok 'Running as administrator'

    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -lt 5) {
        Fail 'Use Windows PowerShell 5.1 (powershell.exe), not PowerShell 7 (pwsh.exe).'
    }
    Write-Ok "Windows PowerShell $($PSVersionTable.PSVersion)"

    $os = Get-CimInstance Win32_OperatingSystem
    if ([int]$os.BuildNumber -lt 10240) { Fail "Windows 10 or newer required (found build $($os.BuildNumber))." }
    Write-Ok "$($os.Caption) build $($os.BuildNumber)"

    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $fingerprint = "$($cs.Manufacturer) $($cs.Model) $($bios.Manufacturer) $($bios.SerialNumber) $($bios.Version)"
    $isVm = $fingerprint -match 'VMware|VirtualBox|innotek|QEMU|KVM|Xen|Parallels|Bochs|Virtual Machine|Hyper-V|UTM'
    if (-not $isVm -and -not $Force) {
        Fail "This does not look like a VM ($($cs.Manufacturer) / $($cs.Model)). Refusing to disable Defender on a real machine. Use -Force only if you are sure."
    }
    Write-Ok "Virtual machine detected: $($cs.Manufacturer) $($cs.Model)"

    $freeGb = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
    if ($freeGb -lt 60) { Write-Warn2 "Only $freeGb GB free on C:. FLARE-VM wants at least 60 GB." } else { Write-Ok "$freeGb GB free on C:" }

    $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    if ($ramGb -lt 2) { Write-Warn2 "Only $ramGb GB RAM. FLARE-VM wants at least 2 GB (4+ recommended)." } else { Write-Ok "$ramGb GB RAM" }

    if ($env:USERNAME -match '\s') { Fail "Your username '$env:USERNAME' contains a space. FLARE-VM does not support that." }
    Write-Ok "Username '$env:USERNAME' OK"

    try {
        Invoke-WebRequest -Uri 'https://github.com' -UseBasicParsing -Method Head -TimeoutSec 15 | Out-Null
        Write-Ok 'Internet connectivity OK'
    } catch { Fail 'No internet access (github.com unreachable). FLARE-VM downloads everything online.' }
}

# ---------------------------------------------------------------- 2. tamper protection
function Wait-TamperProtectionOff {
    Write-Step 'Checking Tamper Protection'
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $status) { Write-Warn2 'Defender status unavailable (already removed?). Skipping.'; return }

    while ((Get-MpComputerStatus).IsTamperProtected) {
        Write-Warn2 'Tamper Protection is ON. Windows does not allow scripts to turn it off.'
        Write-Host  '        Opening Windows Security. Go to: Virus & threat protection > Manage settings'
        Write-Host  '        and switch OFF "Tamper Protection" (and "Real-time protection" while you are there).'
        Start-Process 'windowsdefender://threatsettings'
        Read-Host '        Press Enter once Tamper Protection is off'
    }
    Write-Ok 'Tamper Protection is off'
}

# ---------------------------------------------------------------- 3. defender
function Disable-Defender {
    Write-Step 'Disabling Microsoft Defender via Group Policy'
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'

    Set-RegValue $base 'DisableAntiSpyware'          1
    Set-RegValue $base 'DisableAntiVirus'            1
    Set-RegValue $base 'DisableRoutinelyTakingAction' 1
    Set-RegValue $base 'ServiceKeepAlive'            0

    $rtp = "$base\Real-Time Protection"
    Set-RegValue $rtp 'DisableRealtimeMonitoring'    1
    Set-RegValue $rtp 'DisableBehaviorMonitoring'    1
    Set-RegValue $rtp 'DisableOnAccessProtection'    1
    Set-RegValue $rtp 'DisableScanOnRealtimeEnable'  1
    Set-RegValue $rtp 'DisableIOAVProtection'        1

    $spy = "$base\Spynet"
    Set-RegValue $spy 'SpynetReporting'      0
    Set-RegValue $spy 'SubmitSamplesConsent' 2   # never send samples

    Set-RegValue "$base\MpEngine" 'MpEnablePus' 0
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 0

    # Immediate effect where allowed (no-op once policy has taken over)
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
            -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBlockAtFirstSeen $true `
            -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -PUAProtection Disabled -ErrorAction Stop
        Add-MpPreference -ExclusionPath 'C:\' -ErrorAction SilentlyContinue
    } catch { Write-Warn2 "Set-MpPreference: $($_.Exception.Message)" }

    gpupdate /force | Out-Null
    Write-Ok 'Defender policies applied'
}

# ---------------------------------------------------------------- 4. windows update
function Disable-WindowsUpdate {
    Write-Step 'Disabling Windows Update'
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegValue $au 'NoAutoUpdate' 1
    Set-RegValue $au 'AUOptions'    1
    Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DoNotConnectToWindowsUpdateInternetLocations' 1

    foreach ($svc in 'wuauserv', 'BITS', 'DoSvc') {
        try {
            Stop-Service $svc -Force -ErrorAction Stop
            Set-Service  $svc -StartupType Disabled -ErrorAction Stop
            Write-Ok "Service $svc stopped and disabled"
        } catch { Write-Warn2 "Could not disable ${svc}: $($_.Exception.Message)" }
    }
    Write-Ok 'Windows Update disabled (re-enable later via the AU policy key if you need patches)'
}

# ---------------------------------------------------------------- 5. reboot if needed
function Test-DefenderStillRunning {
    try { return [bool](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { return $false }
}

function Register-ResumeAndReboot {
    $relaunchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-Resume')
    if ($NoGui)        { $relaunchArgs += '-NoGui' }
    if ($CustomConfig) { $relaunchArgs += @('-CustomConfig', "`"$CustomConfig`"") }
    if ($Force)        { $relaunchArgs += '-Force' }
    if ($DefaultPackages) { $relaunchArgs += '-DefaultPackages' }
    if ($PSBoundParameters.ContainsKey('PackageList')) { $relaunchArgs += @('-PackageList', "`"$PackageList`"") }
    $cmd = "powershell.exe $($relaunchArgs -join ' ')"
    Set-RegValue $RunOnceKey $RunOnceName $cmd 'String'
    Write-Warn2 'Defender real-time protection is still active. A reboot is needed for the policy to take over.'
    Write-Host  '        The script resumes automatically after you log back in.'
    Read-Host   '        Press Enter to reboot now'
    Restart-Computer -Force
    exit 0
}

# ---------------------------------------------------------------- custom package config
function New-FlareConfig([string]$ListPath) {
    Write-Step "Building package config from $(Split-Path $ListPath -Leaf)"
    $add = @(); $remove = @()
    foreach ($line in Get-Content $ListPath) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        if ($l.StartsWith('-')) { $remove += $l.Substring(1).Trim() } else { $add += $l }
    }

    $defaultPath = Join-Path $WorkDir 'config.default.xml'
    Invoke-WebRequest -Uri $FlareConfigUrl -OutFile $defaultPath -UseBasicParsing
    [xml]$cfg = Get-Content $defaultPath -Raw
    $pkgRoot = $cfg.SelectSingleNode('//packages')
    if (-not $pkgRoot) {
        Write-Warn2 'Unexpected config.xml layout, falling back to the default package set.'
        return $null
    }

    $present = @{}
    foreach ($node in @($pkgRoot.SelectNodes('package'))) {
        $name = $node.GetAttribute('name')
        if ($remove | Where-Object { $name -like $_ }) {
            [void]$pkgRoot.RemoveChild($node)
            Write-Host "    - removed $name"
        } else { $present[$name] = $true }
    }
    $defaults = $present.Count

    foreach ($name in $add) {
        if ($present.ContainsKey($name)) { continue }
        if ($remove | Where-Object { $name -like $_ }) { continue }
        $el = $cfg.CreateElement('package')
        $el.SetAttribute('name', $name)
        [void]$pkgRoot.AppendChild($el)
        $present[$name] = $true
    }

    $out = Join-Path $WorkDir 'config.xml'
    $cfg.Save($out)
    Write-Ok "$defaults default + $($present.Count - $defaults) extra = $($present.Count) packages, saved to $out"
    return $out
}

# ---------------------------------------------------------------- 6+7. snapshot and install
function Install-Flare {
    Write-Step 'Snapshot time'
    Write-Host '    Take a VM snapshot NOW from your hypervisor (e.g. "pre-flare-clean").' -ForegroundColor Yellow
    Write-Host '    Defender and updates are off, nothing from FLARE-VM is installed yet.'
    if (Test-Path "$env:USERPROFILE\Desktop\ida*") { Write-Ok 'IDA Pro installer found on Desktop' }
    else { Write-Host '    IDA Pro via idapro.vm? Put the installer (and license) on the Desktop before continuing.' }
    Read-Host '    Press Enter when the snapshot is done'

    Write-Step 'Downloading FLARE-VM installer'
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
    $installer = Join-Path $WorkDir 'install.ps1'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $FlareInstallerUrl -OutFile $installer -UseBasicParsing
    Unblock-File $installer
    Write-Ok "Saved to $installer"

    Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    Set-ExecutionPolicy Unrestricted -Scope Process      -Force

    $configPath = $CustomConfig
    if (-not $configPath -and -not $DefaultPackages) {
        if (Test-Path $PackageList) { $configPath = New-FlareConfig $PackageList }
        else { Write-Warn2 "No package list at $PackageList, using the FLARE-VM defaults." }
    }

    $flareArgs = @{}
    if ($NoGui)      { $flareArgs['noGui'] = $true }
    if ($configPath) { $flareArgs['customConfig'] = $configPath }

    Write-Step 'Running FLARE-VM installer (you will be asked for your Windows password for auto-logon reboots)'
    Write-Host '    This takes a long time and reboots several times. Let it run.' -ForegroundColor Yellow
    Push-Location $WorkDir
    try { & $installer @flareArgs } finally { Pop-Location }
}

# ---------------------------------------------------------------- main
Write-Host '=== FLARE-VM one-shot setup ===' -ForegroundColor Magenta
Remove-ItemProperty -Path $RunOnceKey -Name $RunOnceName -ErrorAction SilentlyContinue

Test-Prerequisites

if (-not $Resume) {
    Wait-TamperProtectionOff
    Disable-Defender
    Disable-WindowsUpdate
    if (Test-DefenderStillRunning) { Register-ResumeAndReboot }
} else {
    Write-Step 'Resumed after reboot'
    if (Test-DefenderStillRunning) {
        Fail 'Defender real-time protection is still on after reboot. Check that Tamper Protection is off, then run the script again.'
    }
    Write-Ok 'Defender real-time protection is off'
}

Install-Flare
