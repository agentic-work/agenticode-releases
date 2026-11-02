#Requires -Version 5.1
<#
=============================================================================
 agenticode installer — Windows

     irm https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.ps1 | iex

 Pin a version:
     $env:AGENTICODE_VERSION='0.8.4'; irm https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.ps1 | iex

 Install the desktop app instead of the CLI:
     $env:AGENTICODE_FLAVOR='desktop'; irm https://raw.githubusercontent.com/agentic-work/agenticode-releases/main/install.ps1 | iex

 Environment (there are deliberately NO parameters — see note 1):
     AGENTICODE_INSTALL_BASE   endpoint root (default https://get.agenticwork.io)
     AGENTICODE_VERSION        pin a version, default: latest
     AGENTICODE_PREFIX         install directory for the CLI
     AGENTICODE_FLAVOR         'cli' (default) or 'desktop'
     AGENTICODE_PRINT_PLAN     print the resolved plan and exit, install nothing
     AGENTICODE_DESKTOP_INTERACTIVE  show the desktop installer UI (default: silent)

-----------------------------------------------------------------------------
 Notes for whoever edits this next

 1. This is piped into `iex`. A `param()` block cannot receive arguments that
    way — `irm ... | iex` has nowhere to put them — so every knob is an
    environment variable and there is exactly one way to configure this.

 2. The default flavour is the CLI, not the desktop app. Three reasons, in
    order of weight:
      * `irm | iex` is a terminal gesture and must be non-interactive. The
        desktop bundle is an NSIS wizard; running it without /S pops a GUI, so
        the previous default was interactive in the one context that cannot be.
      * The macOS/Linux one-liner installs a CLI. Two one-liners advertised as
        the same product must deliver the same product.
      * Integrity: the release manifest (checksums.txt) covers the CLI
        binaries. The desktop bundle is produced by a separate workflow and is
        absent from it, so it can only be verified via a per-asset sidecar.
        The default path should be the one under the primary manifest.
    Desktop is still one env var away, and stays silent-by-default so it is
    safe to pipe.

 3. SHA256 verification is MANDATORY, on both flavours, with no off switch.
    For an `irm | iex` install it is the one control that makes the whole
    thing defensible; an off switch is just the exploit's first step.

 4. No GitHub credential, ever — this script must never read a personal access
    token or touch the GitHub API. It fetches only from AGENTICODE_INSTALL_BASE.
    The release repo is private; mirroring release assets to that endpoint is
    the distribution pipeline's job.

 5. An endpoint that serves a single-page app for unknown paths answers 200
    with HTML. Every artefact fetched here is shape-checked before use, so a
    web page can never be treated as a version, a manifest or a binary.
=============================================================================
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# PowerShell 5.1 still defaults to TLS 1.0 on older boxes.
try {
  [Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$RELEASES_REPO = 'agentic-work/agenticode-releases'
$DEFAULT_BASE = "https://github.com/$RELEASES_REPO/releases/download"
$BIN_NAME     = 'agenticode'

function Get-EnvOr {
  param([string]$Name, [string]$Fallback = '')
  $v = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($v)) { return $Fallback }
  return $v.Trim()
}

function Write-Info { param([string]$m) Write-Host "==> $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "!   $m" -ForegroundColor Yellow }

function Stop-WithError {
  param([string]$Message, [string[]]$Hints = @())
  Write-Host "error: $Message" -ForegroundColor Red
  foreach ($h in $Hints) { Write-Host "       $h" }
  exit 1
}

function Test-OnWindows {
  # $IsWindows does not exist in Windows PowerShell 5.1.
  if (Test-Path Variable:\IsWindows) { return [bool](Get-Variable IsWindows -ValueOnly) }
  return $true
}

# --- endpoint sanity -------------------------------------------------------
# A one-liner that will pull an executable over plaintext HTTP from an
# arbitrary host is a downgrade attack waiting to happen. https anywhere;
# http only against loopback (local mirrors, CI, tests).
function Assert-BaseAllowed {
  param([string]$Base)
  if ($Base -match '^https://') { return }
  if ($Base -match '^http://(127\.0\.0\.1|localhost|\[::1\])(:|/|$)') { return }
  if ($Base -match '^http://') {
    Stop-WithError "refusing to install over plaintext http from '$Base'" `
      @('Use an https endpoint. http is only allowed against loopback.')
  }
  Stop-WithError "AGENTICODE_INSTALL_BASE must be a URL, got '$Base'"
}

function Get-TargetArch {
  $a = Get-EnvOr 'PROCESSOR_ARCHITEW6432'
  if (-not $a) { $a = Get-EnvOr 'PROCESSOR_ARCHITECTURE' }
  # Unset happens under non-Windows PowerShell (CI, tests); assume x64 there.
  if (-not $a) { return 'x64' }
  if ($a -in @('AMD64', 'x86_64', 'x64')) { return 'x64' }
  Stop-WithError "unsupported CPU architecture '$a' — agenticode publishes x64 for Windows only" `
    @('If you are on Windows on ARM, x64 emulation is not yet a supported target.')
}

# --- http ------------------------------------------------------------------
function Invoke-Download {
  param([string]$Url, [string]$OutFile)
  $prev = $ProgressPreference
  $ProgressPreference = 'SilentlyContinue'   # ~10x faster for large files on 5.1
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile
  } finally {
    $ProgressPreference = $prev
  }
}

function Try-Download {
  param([string]$Url, [string]$OutFile)
  try { Invoke-Download -Url $Url -OutFile $OutFile; return $true } catch { return $false }
}

function Test-LooksLikeHtml {
  param([string]$Path)
  try {
    $fs = [IO.File]::OpenRead($Path)
    try {
      $buf = New-Object byte[] 512
      $n = $fs.Read($buf, 0, 512)
    } finally { $fs.Dispose() }
    if ($n -le 0) { return $false }
    $head = [Text.Encoding]::ASCII.GetString($buf, 0, $n).ToLowerInvariant()
    return ($head -match '<!doctype html' -or $head -match '<html')
  } catch { return $false }
}

function Assert-NotHtml {
  param([string]$Path, [string]$What)
  if (Test-LooksLikeHtml -Path $Path) {
    Stop-WithError "$What returned an HTML page, not a file" `
      @('The install endpoint is falling through to a web app instead of',
        'serving the release artefacts. Nothing has been installed.')
  }
}

# --- version ---------------------------------------------------------------
$VERSION_RE = '^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'

function Resolve-Version {
  param([string]$Base, [string]$WorkDir)
  $url = "$Base/latest.txt"
  if (-not $env:AGENTICODE_INSTALL_BASE) { $url = "https://raw.githubusercontent.com/$RELEASES_REPO/main/latest.txt" }
  $file = Join-Path $WorkDir 'latest.txt'
  if (-not (Try-Download -Url $url -OutFile $file)) {
    Stop-WithError "could not fetch the version pointer: $url" `
      @('Check the endpoint is reachable, or pin a version:',
        "  `$env:AGENTICODE_VERSION='0.8.4'")
  }
  Assert-NotHtml -Path $file -What 'the version pointer'
  $raw = (Get-Content -Raw -Path $file).Trim()
  if ($raw -notmatch $VERSION_RE) {
    $short = $raw
    if ($short.Length -gt 60) { $short = $short.Substring(0, 60) }
    Stop-WithError "$url did not return a version number (got: '$short')" `
      @('That usually means the endpoint answered with an HTML page — a',
        'single-page-app catch-all rather than the real install channel.',
        "Pin explicitly to work around it: `$env:AGENTICODE_VERSION='0.8.4'")
  }
  return $raw.TrimStart('v')
}

# --- checksums -------------------------------------------------------------
# Manifest first, per-asset sidecar second. The desktop bundle is built by a
# separate workflow and is genuinely absent from the release checksums.txt,
# so the sidecar is a real path, not a fallback for laziness.
function Get-ExpectedHash {
  param([string]$Base, [string]$Tag, [string]$Asset, [string]$WorkDir)

  $sums = Join-Path $WorkDir 'checksums.txt'
  if (Try-Download -Url "$Base/$Tag/checksums.txt" -OutFile $sums) {
    Assert-NotHtml -Path $sums -What 'the checksum manifest'
    foreach ($line in Get-Content -Path $sums) {
      $parts = ($line.Trim() -split '\s+')
      if ($parts.Count -ge 2) {
        $name = $parts[1].TrimStart('*')
        if ($name -eq $Asset -and $parts[0] -match '^[0-9a-fA-F]{64}$') {
          return $parts[0].ToLowerInvariant()
        }
      }
    }
  }

  $side = Join-Path $WorkDir 'sidecar.sha256'
  if (Try-Download -Url "$Base/$Tag/$Asset.sha256" -OutFile $side) {
    Assert-NotHtml -Path $side -What 'the checksum sidecar'
    $first = ((Get-Content -Raw -Path $side).Trim() -split '\s+')[0]
    if ($first -match '^[0-9a-fA-F]{64}$') { return $first.ToLowerInvariant() }
  }

  Stop-WithError "no published checksum for $Asset at $Tag" `
    @("Looked in $Base/$Tag/checksums.txt",
      "and       $Base/$Tag/$Asset.sha256",
      'Verification is mandatory, so the install has been aborted.')
}

# --- PATH ------------------------------------------------------------------
function Add-ToUserPath {
  param([string]$Dir)
  if (-not (Test-OnWindows)) { return $false }
  try {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if (-not $key) { return $false }
    try {
      # Read UNEXPANDED. Reading the expanded value and writing it back turns
      # %USERPROFILE% into a literal path and silently breaks the user's PATH
      # on every future profile change — the classic installer own-goal.
      $raw = [string]$key.GetValue(
        'Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

      $already = $false
      foreach ($p in ($raw -split ';')) {
        if ($p.Trim().TrimEnd('\') -ieq $Dir.TrimEnd('\')) { $already = $true }
      }
      if ($already) { return $true }

      $new = if ([string]::IsNullOrWhiteSpace($raw)) { $Dir } else { "$($raw.TrimEnd(';'));$Dir" }
      $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
      try { $kind = $key.GetValueKind('Path') } catch { }
      $key.SetValue('Path', $new, $kind)
    } finally { $key.Dispose() }

    # Make it usable in THIS session too, without waiting for a new shell.
    [Environment]::SetEnvironmentVariable('Path', "$env:Path;$Dir", 'Process')
    return $true
  } catch {
    return $false
  }
}

# ===========================================================================
# main
# ===========================================================================
$BASE = (Get-EnvOr 'AGENTICODE_INSTALL_BASE' $DEFAULT_BASE).TrimEnd('/')
Assert-BaseAllowed -Base $BASE
# a custom base keeps the mirror layout; the default is GitHub Releases
if ($env:AGENTICODE_INSTALL_BASE) { $BASE = "$BASE/agenticode" }

$FLAVOR = (Get-EnvOr 'AGENTICODE_FLAVOR' 'cli').ToLowerInvariant()
if ($FLAVOR -notin @('cli', 'desktop')) {
  Stop-WithError "unknown flavor '$FLAVOR'" @("Supported values are 'cli' (default) and 'desktop'.")
}

$ARCH      = Get-TargetArch
$PRINT_PLAN = [bool](Get-EnvOr 'AGENTICODE_PRINT_PLAN')

$work = Join-Path ([IO.Path]::GetTempPath()) ("agenticode-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
  $requested = Get-EnvOr 'AGENTICODE_VERSION'
  if ($requested) {
    if ($requested -notmatch $VERSION_RE) {
      Stop-WithError "'$requested' is not a version number" @('Expected something like 0.8.4 or v0.8.4.')
    }
    $VERSION = $requested.TrimStart('v')
  } else {
    $VERSION = Resolve-Version -Base $BASE -WorkDir $work
  }
  $TAG = "v$VERSION"

  if ($FLAVOR -eq 'desktop') {
    $ASSET = "agenticode_${VERSION}_${ARCH}-setup.exe"
  } else {
    $ASSET = "$BIN_NAME-windows-$ARCH.exe"
  }
  $ASSET_URL = "$BASE/$TAG/$ASSET"

  # Silent by default: this is piped to iex and must never block on a wizard.
  $installerArgs = @('/S')
  if (Get-EnvOr 'AGENTICODE_DESKTOP_INTERACTIVE') { $installerArgs = @() }

  $PREFIX = Get-EnvOr 'AGENTICODE_PREFIX'
  if (-not $PREFIX) {
    $localAppData = Get-EnvOr 'LOCALAPPDATA'
    if (-not $localAppData) { $localAppData = Join-Path $HOME '.local' }
    $PREFIX = Join-Path $localAppData 'Programs\agenticode\bin'
  }
  $DEST = Join-Path $PREFIX "$BIN_NAME.exe"

  if ($PRINT_PLAN) {
    Write-Output "os=windows"
    Write-Output "arch=$ARCH"
    Write-Output "flavor=$FLAVOR"
    Write-Output "asset=$ASSET"
    Write-Output "version=$VERSION"
    Write-Output "tag=$TAG"
    Write-Output "base=$BASE"
    Write-Output "asset_url=$ASSET_URL"
    Write-Output "checksums_url=$BASE/$TAG/checksums.txt"
    Write-Output "prefix=$PREFIX"
    Write-Output "dest=$DEST"
    Write-Output "verify=required"
    Write-Output ("installer_args=" + ($installerArgs -join ' '))
    exit 0
  }

  Write-Info "agenticode $VERSION (windows-$ARCH, $FLAVOR)"

  $expected = Get-ExpectedHash -Base $BASE -Tag $TAG -Asset $ASSET -WorkDir $work

  $downloaded = Join-Path $work $ASSET
  Write-Info "Downloading $ASSET"
  if (-not (Try-Download -Url $ASSET_URL -OutFile $downloaded)) {
    Stop-WithError "could not download $ASSET_URL" `
      @('Check the endpoint is reachable and that this version was published.')
  }
  Assert-NotHtml -Path $downloaded -What 'the binary URL'

  $actual = (Get-FileHash -Path $downloaded -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    Stop-WithError 'SHA256 checksum mismatch — refusing to install' `
      @("expected $expected",
        "actual   $actual",
        'The download does not match the published manifest. Nothing has',
        'been changed on disk. Re-run; if it persists, do not install.')
  }
  Write-Info "Checksum OK ($actual)"

  if ($FLAVOR -eq 'desktop') {
    Write-Info 'Running the desktop installer'
    $p = Start-Process -FilePath $downloaded -ArgumentList $installerArgs -PassThru -Wait
    if ($p.ExitCode -ne 0) {
      Stop-WithError "the desktop installer exited with code $($p.ExitCode)" `
        @('Re-run with $env:AGENTICODE_DESKTOP_INTERACTIVE=1 to see its UI.')
    }
    Write-Host ''
    Write-Host "Installed agenticode $VERSION (desktop) — look for it on the Start menu."
    exit 0
  }

  # --- CLI install --------------------------------------------------------
  if (-not (Test-Path -LiteralPath $PREFIX)) {
    try { New-Item -ItemType Directory -Path $PREFIX -Force | Out-Null }
    catch {
      Stop-WithError "cannot create $PREFIX — no write permission" `
        @('Choose somewhere you own: $env:AGENTICODE_PREFIX=''C:\Users\you\bin''')
    }
  }

  # Stage inside the destination directory so the final move is a rename on
  # the same volume — an interrupted install can never leave a half-written
  # agenticode.exe at $DEST.
  $stage = Join-Path $PREFIX (".$BIN_NAME.install." + $PID + '.tmp')
  try {
    Copy-Item -LiteralPath $downloaded -Destination $stage -Force
    if (Test-Path -LiteralPath $DEST) { Remove-Item -LiteralPath $DEST -Force }
    Move-Item -LiteralPath $stage -Destination $DEST -Force
  } catch {
    Stop-WithError "could not write $DEST — $($_.Exception.Message)" `
      @('If agenticode is currently running, close it and re-run.')
  } finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue }
  }

  Write-Host ''
  Write-Host "Installed agenticode $VERSION — $DEST"

  if (Add-ToUserPath -Dir $PREFIX) {
    Write-Host "Added $PREFIX to your user PATH (open a new terminal to pick it up)."
  } else {
    Write-Warn "Could not update your PATH automatically. Add this directory yourself:"
    Write-Host "    $PREFIX"
  }

  Write-Host ''
  Write-Host 'Next:'
  Write-Host '  agenticode --version'
  Write-Host '  agenticode login'
  Write-Host '  agenticode doctor'
}
finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
