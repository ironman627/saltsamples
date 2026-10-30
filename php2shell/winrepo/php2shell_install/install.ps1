# Dedicated x64 lab installations only. Never adopts existing PHP/Apache trees.
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Remove')][string]$Action = 'Install',
    [Parameter(Mandatory=$true)][ValidateSet('php', 'apache')][string]$Package,
    [string]$Version,
    [string]$Uri,
    [string]$Sha256
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$labRoot = 'C:\SaltLabs'
$phpRoot = Join-Path $labRoot 'PHP83'
$apacheRoot = Join-Path $labRoot 'Apache24'
$destination = if ($Package -eq 'php') { $phpRoot } else { $apacheRoot }
$marker = Join-Path $destination '.salt-php2shell-owned'
$serviceName = 'SaltPHP2ShellApache'
$httpd = Join-Path $apacheRoot 'bin\httpd.exe'
$support = 'C:\ProgramData\SaltPHP2Shell'
$registry = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SaltPHP2Shell-' + $Package
$displayName = if ($Package -eq 'php') { 'PHP 8.3 (Salt Lab x64 TS)' } else { 'Apache HTTP Server 2.4 (Salt Lab x64)' }

function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable exited with $LASTEXITCODE" }
}

function Save-HttpsDownload([uri]$DownloadUri, [string]$OutFile) {
    # Windows PowerShell 5.1 does not reliably follow HTTP 308 redirects.
    # Follow a bounded HTTPS chain, then stream the response to disk. Callers
    # still verify the archive hash or Microsoft Authenticode signature.
    for ($redirect = 0; $redirect -le 10; $redirect++) {
        if ($DownloadUri.Scheme -ne 'https') { throw 'Download redirect must use HTTPS.' }
        $request = [Net.HttpWebRequest]::Create($DownloadUri)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 60000
        $request.ReadWriteTimeout = 60000
        $response = $null
        try {
            $response = $request.GetResponse()
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                $location = $response.Headers['Location']
                if (-not $location) { throw 'Download redirect has no Location header.' }
                $DownloadUri = [uri]::new($DownloadUri, $location)
                continue
            }
            if ($status -ne 200) { throw "Download returned HTTP $status from $DownloadUri" }
            $inputStream = $response.GetResponseStream()
            try {
                $outputStream = [IO.File]::Create($OutFile)
                try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose() }
            } finally { $inputStream.Dispose() }
            return
        } finally {
            if ($response) { $response.Close() }
        }
    }
    throw 'Download exceeded 10 redirects.'
}

function Write-LabPhpHandler {
    if ((Test-Path -LiteralPath (Join-Path $apacheRoot '.salt-php2shell-owned')) -and
        (Test-Path -LiteralPath (Join-Path $phpRoot '.salt-php2shell-owned'))) {
        $handler = Join-Path $apacheRoot 'conf\extra\php2shell-lab.conf'
        @'
# Managed by the Salt PHP2Shell lab package wrapper.
LoadFile "C:/SaltLabs/PHP83/php8ts.dll"
LoadModule php_module "C:/SaltLabs/PHP83/php8apache2_4.dll"
PHPIniDir "C:/SaltLabs/PHP83"
<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>
'@ | Set-Content -LiteralPath $handler -Encoding ASCII
        $configuration = Join-Path $apacheRoot 'conf\httpd.conf'
        if ((Get-Content -LiteralPath $configuration -Raw) -notmatch '(?m)^Include conf/extra/php2shell-lab[.]conf\s*$') {
            Add-Content -LiteralPath $configuration -Value "`r`nInclude conf/extra/php2shell-lab.conf" -Encoding ASCII
        }
    }
}

$staging = $null
$restartApache = $false
try {
    if (-not [Environment]::Is64BitProcess) { throw 'Run with 64-bit PowerShell on x64 Windows.' }
    if (Test-Path -LiteralPath $destination) {
        if (-not (Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne $Package) {
            throw "Refusing to modify an unowned installation: $destination"
        }
    }
    $existingService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($existingService -and $existingService.PathName -notlike ('*' + $httpd + '*')) {
        throw 'The lab service name is already used by another installation.'
    }
    if ($existingService -and $existingService.State -eq 'Running') {
        Stop-Service -Name $serviceName
        (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
        $restartApache = $true
    }
    if ($Action -eq 'Remove') {
        if (-not (Test-Path -LiteralPath $marker)) { throw 'No owned lab installation to remove.' }
        if ($Package -eq 'apache' -and $existingService) {
            Invoke-Checked $httpd @('-k', 'uninstall', '-n', $serviceName)
            $restartApache = $false
        } elseif ($Package -eq 'php' -and (Test-Path -LiteralPath (Join-Path $apacheRoot '.salt-php2shell-owned'))) {
            $configuration = Join-Path $apacheRoot 'conf\httpd.conf'
            $text = Get-Content -LiteralPath $configuration -Raw
            [IO.File]::WriteAllText($configuration, ($text -replace '(?m)^Include conf/extra/php2shell-lab[.]conf\s*$', ''), [Text.Encoding]::ASCII)
        }
        # Exact fixed lab path, with ownership checked above; no user-computed target.
        if ($destination -notin @('C:\SaltLabs\PHP83', 'C:\SaltLabs\Apache24')) { throw 'Invalid removal path.' }
        Remove-Item -LiteralPath $destination -Recurse -Force
        if (Test-Path -LiteralPath $registry) { Remove-Item -LiteralPath $registry -Recurse -Force }
        Write-Output "Removed $displayName (including its lab configuration)."
    } else {
        if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$' -or $Sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'An exact version and SHA256 are required.' }
        $downloadUri = [uri]$Uri
        $allowedHost = if ($Package -eq 'php') { 'downloads.php.net' } else { 'www.apachelounge.com' }
        if ($downloadUri.Scheme -ne 'https' -or $downloadUri.Host -ne $allowedHost) { throw 'Unexpected software download host.' }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $staging = Join-Path ([IO.Path]::GetTempPath()) ('salt-php2shell-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $staging | Out-Null
        $archive = Join-Path $staging 'package.zip'
        Save-HttpsDownload -DownloadUri $downloadUri -OutFile $archive
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $Sha256) { throw 'Archive SHA256 mismatch.' }
        # Both builds require the Microsoft x64 VC runtime. Verify the publisher
        # before invoking its silent installer; accept only success/reboot-required.
        $vcRuntime = Join-Path $staging 'vc_redist.x64.exe'
        Save-HttpsDownload -DownloadUri 'https://aka.ms/vc14/vc_redist.x64.exe' -OutFile $vcRuntime
        $signature = Get-AuthenticodeSignature -LiteralPath $vcRuntime
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') { throw 'VC runtime signature validation failed.' }
        $vcProcess = Start-Process -FilePath $vcRuntime -ArgumentList '/install', '/quiet', '/norestart' -WindowStyle Hidden -PassThru -Wait
        if ($vcProcess.ExitCode -notin @(0, 1638, 3010)) { throw "VC runtime installer failed: $($vcProcess.ExitCode)" }
        $expanded = Join-Path $staging 'expanded'
        Expand-Archive -LiteralPath $archive -DestinationPath $expanded
        $source = if ($Package -eq 'apache') { Join-Path $expanded 'Apache24' } else { $expanded }
        if (-not (Test-Path -LiteralPath $source)) { throw 'Unexpected archive layout.' }
        $fresh = -not (Test-Path -LiteralPath $marker)
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        # Preserve the runtime configuration, application files and logs on upgrades.
        foreach ($item in Get-ChildItem -LiteralPath $source -Force) {
            if (-not $fresh -and $item.Name -in @('conf', 'logs', 'htdocs', 'php.ini')) { continue }
            Copy-Item -LiteralPath $item.FullName -Destination $destination -Recurse -Force
        }
        if ($Package -eq 'php') {
            Invoke-Checked (Join-Path $phpRoot 'php.exe') @('-n', '-v')
            $engineVersion = (& (Join-Path $phpRoot 'php.exe') -n -r 'echo PHP_VERSION;').Trim()
            if ($LASTEXITCODE -ne 0 -or $engineVersion -ne (($Version.Split('.')[0..2]) -join '.')) { throw 'PHP engine version does not match the package definition.' }
            if (-not (Test-Path -LiteralPath (Join-Path $phpRoot 'php.ini'))) {
                Copy-Item -LiteralPath (Join-Path $phpRoot 'php.ini-production') -Destination (Join-Path $phpRoot 'php.ini')
            }
        } else {
            $apacheVersion = (& $httpd -v) -join "`n"
            if ($LASTEXITCODE -ne 0 -or $apacheVersion -notmatch ('Apache/' + [regex]::Escape($Version) + '(?:\s|$)')) { throw 'Apache binary version does not match the package definition.' }
            if ($fresh) {
                $configuration = Join-Path $apacheRoot 'conf\httpd.conf'
                $text = Get-Content -LiteralPath $configuration -Raw
                $text = $text -replace '(?m)^Define SRVROOT .*$', 'Define SRVROOT "C:/SaltLabs/Apache24"'
                $text = $text -replace '(?m)^Listen .*$', 'Listen 127.0.0.1:8088'
                $text += "`r`nServerName localhost:8088`r`n"
                [IO.File]::WriteAllText($configuration, $text, [Text.Encoding]::ASCII)
            }
            Invoke-Checked $httpd @('-t')
            if (-not $existingService) { Invoke-Checked $httpd @('-k', 'install', '-n', $serviceName, '-f', (Join-Path $apacheRoot 'conf\httpd.conf')) }
        }
        Set-Content -LiteralPath $marker -Value $Package -Encoding ASCII
        Write-LabPhpHandler
        if (Test-Path -LiteralPath $httpd) { Invoke-Checked $httpd @('-t') }
        New-Item -ItemType Directory -Path $support -Force | Out-Null
        foreach ($file in @('install.cmd', 'install.ps1')) {
            $supportFile = Join-Path $support $file
            if ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot $file)) -ne $supportFile) {
                Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $supportFile -Force
            }
        }
        New-Item -Path $registry -Force | Out-Null
        foreach ($entry in @{
            DisplayName=$displayName; DisplayVersion=$Version; Publisher='Salt PHP2Shell Lab';
            InstallLocation=$destination;
            UninstallString=('"' + (Join-Path $support 'install.cmd') + '" -Action Remove -Package ' + $Package)
        }.GetEnumerator()) {
            New-ItemProperty -Path $registry -Name $entry.Key -Value $entry.Value -PropertyType String -Force | Out-Null
        }
        Write-Output "Installed $displayName $Version into $destination"
    }
} catch {
    Write-Output "Installation failed at: $($_.ScriptStackTrace)"
    Write-Error $_ -ErrorAction Continue
    exit 1
} finally {
    if ($restartApache) {
        try { Start-Service -Name $serviceName -ErrorAction Stop } catch { Write-Error $_ -ErrorAction Continue; exit 1 }
    }
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        $resolvedStaging = [IO.Path]::GetFullPath($staging)
        $expectedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if ($resolvedStaging.StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path $resolvedStaging -Leaf) -match '^salt-php2shell-[a-f0-9]{32}$') {
            Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
        }
    }
}
