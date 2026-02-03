# Deploy: GitHub repo + push. Uses GH_TOKEN if set (create at https://github.com/settings/tokens, scope: repo).
# Then open Streamlit + Google so you can paste secrets and create OAuth client.

param([string]$Token = $env:GH_TOKEN)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
Set-Location $projectRoot
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

$repoName = "incident-management"

# --- Step 1: Create GitHub repo and push ---
if ($Token) {
    Write-Host "`n=== Creating GitHub repo with token ===" -ForegroundColor Cyan
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Accept" = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }
    $body = @{ name = $repoName; description = "Incident Management with OAuth"; private = $false } | ConvertTo-Json
    try {
        $repo = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Method Post -Headers $headers -Body $body -ContentType "application/json"
        $login = $repo.owner.login
        Write-Host "Repo created: $($repo.html_url)" -ForegroundColor Green
        git remote remove origin 2>$null
        git remote add origin "https://${Token}@github.com/${login}/${repoName}.git"
        git push -u origin main 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host "Pushed to main." -ForegroundColor Green }
    } catch { Write-Host "Create/push failed: $_" -ForegroundColor Red }
} else {
    Write-Host "`n=== GitHub: use token or interactive login ===" -ForegroundColor Cyan
    Write-Host "Option A: Set GH_TOKEN (recommended). Create a token at https://github.com/settings/tokens (scope: repo)."
    Write-Host "         Then run: `$env:GH_TOKEN='your_token'; .\do_all_deploy_steps.ps1"
    Write-Host "Option B: Run: gh auth login (complete in browser), then: .\step2_create_repo_and_push.ps1`n"
    try {
        $null = [System.Console]::KeyAvailable
        $useGh = Read-Host "Run 'gh auth login' now? (opens browser) [y/N]"
        if ($useGh -eq 'y' -or $useGh -eq 'Y') {
            gh auth login --web --hostname github.com --git-protocol https
            & "$projectRoot\step2_create_repo_and_push.ps1"
        }
    } catch { }
}

# --- Step 2: Open Streamlit Cloud and Google Console ---
Write-Host "`n=== Opening Streamlit Cloud and Google Console ===" -ForegroundColor Cyan
Start-Process "https://share.streamlit.io"
Start-Sleep -Seconds 1
Start-Process "https://console.cloud.google.com/apis/credentials"
Start-Process "https://github.com/settings/tokens/new?description=Streamlit+Deploy&scopes=repo"

Write-Host "`n=== Next (in browser) ===" -ForegroundColor Green
Write-Host "1. Streamlit Cloud: New app -> repo incident-management, main file app.py. Paste secrets from: secrets_to_paste_in_streamlit.toml"
Write-Host "2. Google Console: Create OAuth 2.0 Client ID (Web). Redirect URI = your Streamlit app URL."
Write-Host "3. After deploy, set OAUTH_REDIRECT_URI in Streamlit secrets to your app URL. Add Google Client ID/Secret. Reboot app."
Write-Host "`nSecrets file: $projectRoot\secrets_to_paste_in_streamlit.toml`n"
