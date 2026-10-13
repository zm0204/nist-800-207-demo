param([string]$Docker)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path $PSScriptRoot -Parent
$taskFile=Join-Path $taskRoot 'artifacts/remote/active.json'
if(!(Test-Path -LiteralPath $taskFile)){Write-Output 'No recorded remote run.';exit}
$taskRecord=Get-Content -LiteralPath $taskFile -Raw | ConvertFrom-Json
if($taskRecord.project -notmatch '^zta-remote-[a-f0-9]{8}$'){throw 'Invalid recorded project.'}
$taskProcess=Get-Process -Id $taskRecord.pid -ErrorAction SilentlyContinue
if($taskProcess){
    if($taskProcess.Path -ne $taskRecord.executable){throw 'Process ID was reused; refusing to stop an unrelated process.'}
    Stop-Process -Id $taskProcess.Id
}
if(!$Docker){$Docker=(Get-Command docker -ErrorAction SilentlyContinue).Source}
if(!$Docker){$Docker=Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin/docker.exe'}
& $Docker compose --project-directory $taskRoot --env-file $taskRecord.envFile -p $taskRecord.project -f (Join-Path $taskRoot 'compose.yaml') -f (Join-Path $taskRoot 'compose.remote.yaml') stop
if($LASTEXITCODE -ne 0){throw 'Container stop failed; retained active record for retry.'}
Move-Item -LiteralPath $taskFile -Destination ($taskFile+'.stopped-'+[DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
Write-Output 'Remote tunnel and containers stopped. Databases and local demo preserved.'
