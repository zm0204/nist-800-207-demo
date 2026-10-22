param([switch]$Verify, [switch]$NoBrowser)
$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
$launcherPath = Join-Path $repoRoot 'scripts\start_identity.py'
$launchArguments = @()
if ($Verify) { $launchArguments += '--verify' }
if ($NoBrowser) { $launchArguments += '--no-browser' }
& $pythonPath $launcherPath @launchArguments
exit $LASTEXITCODE
