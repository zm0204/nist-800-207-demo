param(
    [Parameter(Mandatory=$true)][string]$AllowedEmail,
    [string]$Cloudflared,
    [string]$Docker
)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path $PSScriptRoot -Parent
$taskWork=Join-Path $taskRoot 'artifacts/remote'
if($AllowedEmail -notmatch '^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'){throw 'Use one exact allowed email address; wildcards are not permitted.'}
if(!$Cloudflared){$Cloudflared=Join-Path $taskRoot 'artifacts/tools/cloudflared.exe'}
if(!$Docker){$Docker=(Get-Command docker -ErrorAction SilentlyContinue).Source}
if(!$Docker){$Docker=Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin/docker.exe'}
if(!(Test-Path -LiteralPath $Cloudflared)){throw 'Download official cloudflared into artifacts/tools/cloudflared.exe first. See docs/remote.md.'}
if(!(Test-Path -LiteralPath $Docker)){throw 'Docker executable not found.'}
$taskHelp=& $Cloudflared tunnel --help 2>&1
if(($taskHelp -join "`n") -notmatch '\-\-allowed-mail'){throw 'This cloudflared does not support protected Quick Tunnels. Refusing to publish.'}
Write-Warning 'Experimental: protected Quick Tunnel sessions may expire seconds after email login (cloudflare/cloudflared#1752). Do not use for a presentation until browser verification passes. See docs/remote.md.'
& $Docker info --format '{{.ServerVersion}}' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Start Docker Desktop first.'}
if(Test-Path (Join-Path $taskWork 'active.json')){throw 'A remote run is recorded. Stop it with remote-stop.ps1 first.'}
if(Get-NetTCPConnection -LocalPort 8081 -State Listen -ErrorAction SilentlyContinue){throw 'Port 8081 is already in use. Refusing to tunnel an unknown service.'}
New-Item -ItemType Directory -Force $taskWork | Out-Null
$taskOut=Join-Path $taskWork 'cloudflared.out.log';$taskErr=Join-Path $taskWork 'cloudflared.err.log'
$taskProcess=Start-Process -FilePath $Cloudflared -ArgumentList @('tunnel','--url','http://localhost:8081','--allowed-mail',$AllowedEmail,'--no-autoupdate') -WindowStyle Hidden -RedirectStandardOutput $taskOut -RedirectStandardError $taskErr -PassThru
$taskDeadline=(Get-Date).AddSeconds(90);$taskOrigin=$null
try {
    while((Get-Date) -lt $taskDeadline){
        if($taskProcess.HasExited){throw 'cloudflared stopped before establishing a protected tunnel. Inspect artifacts/remote logs.'}
        $taskLog=(Get-Content $taskErr -Raw -ErrorAction SilentlyContinue)+(Get-Content $taskOut -Raw -ErrorAction SilentlyContinue)
        if($taskLog -match 'https://[a-z0-9-]+\.trycloudflare\.com'){$taskOrigin=$Matches[0];break}
        Start-Sleep -Seconds 1
    }
    if(!$taskOrigin){throw 'Timed out waiting for Cloudflare URL.'}
    $taskHost=([Uri]$taskOrigin).Host
    $taskHash=[System.Security.Cryptography.SHA256]::Create()
    $taskSuffix=([BitConverter]::ToString($taskHash.ComputeHash([Text.Encoding]::UTF8.GetBytes($taskHost)))).Replace('-','').Substring(0,8).ToLower()
    $taskProject='zta-remote-'+$taskSuffix
    $taskEnv=Join-Path $taskWork 'remote.env'
    $taskKey=New-Object byte[] 32
    $taskRng=[System.Security.Cryptography.RandomNumberGenerator]::Create(); $taskRng.GetBytes($taskKey); $taskRng.Dispose()
    $taskSecret=[BitConverter]::ToString($taskKey).Replace('-','').ToLower()
    @("REMOTE_RP_ID=$taskHost","REMOTE_ORIGIN=$taskOrigin","SERVICE_KEY=$taskSecret","ENVOY_UID=101") | Set-Content -LiteralPath $taskEnv -Encoding utf8
    $taskRecord=@{pid=$taskProcess.Id;executable=(Resolve-Path $Cloudflared).Path;project=$taskProject;url=$taskOrigin;envFile=$taskEnv;createdUtc=[DateTime]::UtcNow.ToString('o')}
    $taskRecord | ConvertTo-Json | Set-Content (Join-Path $taskWork 'active.json') -Encoding utf8
    & $Docker compose --project-directory $taskRoot --env-file $taskEnv -p $taskProject -f (Join-Path $taskRoot 'compose.yaml') -f (Join-Path $taskRoot 'compose.remote.yaml') up --build -d --wait --wait-timeout 180
    if($LASTEXITCODE -ne 0){throw 'Remote containers failed to become healthy.'}
    Write-Output "Protected demo URL: $taskOrigin"
    Write-Output 'First complete Cloudflare email verification, then register a new Passkey for this hostname.'
    Write-Output 'Local demo remains unchanged. Keep this computer online. Stop with scripts/remote-stop.ps1.'
} catch {
    if(!$taskProcess.HasExited){Stop-Process -Id $taskProcess.Id -ErrorAction SilentlyContinue}
    throw
}

